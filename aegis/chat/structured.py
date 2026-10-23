"""Structured answer path (RAG10) — counts, lists and look-ups straight from the store, no model.

A parsed :class:`FindingFilter` becomes a scan-scoped query over the findings, and the answer is a
fixed template built from real fields. No generation, so nothing can be hallucinated: the citations
are the matched finding ids (plus their evidence ids for a listing/look-up). An empty result is the
same ``"no finding matches"`` the explain path uses, with empty citations.
"""

from __future__ import annotations

from aegis.chat.schemas import Answer, FindingFilter
from aegis.evidence.links import visible_findings
from aegis.evidence.models import Finding
from aegis.graph.route_normalize import normalize_path
from aegis.observability import get_logger

__all__ = ["answer_structured", "matching_findings", "NO_MATCH"]

log = get_logger("chat.structured")

NO_MATCH = "No finding matches."
_MAX_LISTED = 20
_MAX_EVIDENCE = 20


def _state(f: Finding) -> str:
    return getattr(f.state, "value", f.state) or "candidate"


def _file_matches(finding_file: str | None, wanted: str) -> bool:
    if not finding_file:
        return False
    a, b = finding_file.replace("\\", "/"), wanted.replace("\\", "/")
    return a == b or a.endswith("/" + b) or a.endswith(b) or b in a


def matching_findings(store, filt: FindingFilter) -> list[Finding]:
    """The scan's visible findings that satisfy every set field of *filt* (deterministic order)."""
    out = []
    for f in visible_findings(store, filt.scan_id):
        if filt.owasp and (f.owasp or "").upper() != filt.owasp.upper():
            continue
        if filt.type and f.type != filt.type:
            continue
        if filt.state and _state(f) != filt.state:
            continue
        if filt.severity_min is not None and (f.severity or 0.0) < filt.severity_min:
            continue
        if filt.file and not _file_matches(f.file, filt.file):
            continue
        if filt.function and (f.function or "") != filt.function and filt.function not in (f.function or ""):
            continue
        if filt.route and not (f.route and normalize_path(filt.route) in normalize_path(f.route)):
            continue
        out.append(f)
    out.sort(key=lambda f: (-f.risk, -f.severity, f.id))
    return out


def _describe(filt: FindingFilter) -> str:
    """A short phrase naming the active filters, for the answer sentence."""
    parts = []
    if filt.severity_min is not None:
        parts.append(f"severity ≥ {filt.severity_min:g}")
    if filt.owasp:
        parts.append(filt.owasp)
    if filt.type:
        parts.append(filt.type.replace("_", " "))
    if filt.state:
        parts.append(filt.state)
    if filt.file:
        parts.append(f"in {filt.file}")
    if filt.function:
        parts.append(f"in {filt.function}()")
    if filt.route:
        parts.append(f"on {filt.route}")
    return " ".join(parts)


def _one(f: Finding) -> str:
    bits = [f.owasp, _state(f), f"risk {f.risk:.2f}"]
    return f"{f.id} ({', '.join(b for b in bits if b)})"


def answer_structured(store, filt: FindingFilter) -> Answer:
    """Answer a counting / listing / look-up question from the store (no model)."""
    findings = matching_findings(store, filt)
    desc = _describe(filt)
    scope = f" matching {desc}" if desc else ""

    if not findings:
        log.info("structured.no_match", scan_id=filt.scan_id, filter=desc or "(none)")
        return Answer(text=NO_MATCH if not desc else f"No finding matches{scope}.")

    ids = [f.id for f in findings]
    if filt.count:
        n = len(findings)
        text = f"{n} finding{'s' if n != 1 else ''}{scope}."
        return Answer(text=text, finding_ids=ids, evidence_ids=[])

    listed = ", ".join(_one(f) for f in findings[:_MAX_LISTED])
    more = "" if len(findings) <= _MAX_LISTED else f" (+{len(findings) - _MAX_LISTED} more)"
    text = f"{len(findings)} finding{'s' if len(findings) != 1 else ''}{scope}: {listed}{more}."

    evidence_ids: list[str] = []
    for f in findings:
        for e in store.evidence_for(f.id):
            if e.id not in evidence_ids:
                evidence_ids.append(e.id)
            if len(evidence_ids) >= _MAX_EVIDENCE:
                break
    log.info("structured.answer", scan_id=filt.scan_id, matched=len(findings), count=filt.count)
    return Answer(text=text, finding_ids=ids, evidence_ids=evidence_ids)
