"""Semgrep adapter (PHASES P5.4).

Maps Semgrep JSON results to findings with ``code_location`` and (when a
dataflow trace is present) ``dataflow_path`` evidence. Rule id → finding type.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["SemgrepAdapter", "rule_id"]

# check_id → (finding type, owasp, severity weight)
_RULE_MAP: dict[str, tuple[str, str, float]] = {
    "fastapi-sqli": ("sqli", "A03", 0.9),
    "fastapi-missing-owner-check": ("broken_access_control", "A01", 0.9),
    "weak-hash": ("weak_crypto", "A02", 0.6),
    "python-command-injection": ("command_injection", "A03", 0.9),
    "python-code-injection": ("code_injection", "A03", 0.9),
    "python-unsafe-deserialization": ("insecure_deserialization", "A08", 0.8),
    "python-ssrf": ("ssrf", "A10", 0.8),
    "python-path-traversal": ("path_traversal", "A01", 0.8),
    "python-tls-verify-disabled": ("insecure_tls", "A02", 0.6),
    # TNW-5: framework-independent Python SQL, Express (JavaScript + TypeScript) and Spring (Java)
    "python-sqli": ("sqli", "A03", 0.9),
    "js-sqli": ("sqli", "A03", 0.9),
    "js-command-injection": ("command_injection", "A03", 0.9),
    "js-code-injection": ("code_injection", "A03", 0.9),
    "js-ssrf": ("ssrf", "A10", 0.8),
    "js-path-traversal": ("path_traversal", "A01", 0.8),
    "java-sqli": ("sqli", "A03", 0.9),
    "java-command-injection": ("command_injection", "A03", 0.9),
    "java-ssrf": ("ssrf", "A10", 0.8),
    "java-path-traversal": ("path_traversal", "A01", 0.8),
}


def rule_id(check_id: str) -> str:
    """Our rule id for a semgrep ``check_id``.

    Semgrep prefixes a local rule's id with the dotted path of its rules folder
    (``rules.semgrep.fastapi-sqli``); our own rules are matched back to their bare id.
    Other ids are kept whole so unmapped rules stay distinct.
    """
    for known in _RULE_MAP:
        if check_id == known or check_id.endswith("." + known):
            return known
    return check_id


def _posix(path):
    """Semgrep reports paths as the OS writes them (``app\\routes\\users.py`` on Windows)."""
    if not path:
        return path
    rel = str(path).replace("\\", "/")
    return rel[2:] if rel.startswith("./") else rel


class SemgrepAdapter(Adapter):
    tool = "semgrep"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        results = (raw or {}).get("results", []) if isinstance(raw, dict) else []
        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for r in results:
            check_id = rule_id(r.get("check_id", ""))
            # unmapped rules share one bounded type; the rule id keeps findings distinct
            ftype, owasp, sev = _RULE_MAP.get(check_id, ("code_issue", None, 0.5))
            path = _posix(r.get("path"))
            line = (r.get("start") or {}).get("line")
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            owasp = meta.get("owasp", owasp)

            draft = FindingDraft(
                type=ftype,
                owasp=owasp,
                title=extra.get("message", check_id),
                file=path,
                line=line,
                severity=sev,
                source="worker2.semgrep",
                mode=self._mode,
                variant="" if check_id in _RULE_MAP else check_id,
            )
            evidence = [
                EvidenceDraft(
                    kind="code_location",
                    tool="semgrep",
                    payload={"file": path, "line": line, "rule": check_id, "note": extra.get("message")},
                )
            ]
            trace = extra.get("dataflow_trace")
            if trace:
                evidence.append(
                    EvidenceDraft(
                        kind="dataflow_path",
                        tool="semgrep",
                        payload={
                            "file": path,
                            "line": line,
                            "rule": check_id,
                            "source": trace.get("taint_source"),
                            "steps": trace.get("steps", []),
                            "sink": trace.get("taint_sink"),
                            "traced_by": trace.get("traced_by", "semgrep"),
                            # the handler the flow starts in (the correlator's "function"); a flow
                            # traced through a helper call starts outside the finding's own function
                            **({"function": trace["handler"]} if trace.get("handler") else {}),
                            "note": "source reaches sink",
                        },
                    )
                )
            out.append((draft, evidence))
        return out
