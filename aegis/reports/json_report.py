"""JSON report (AG12.1, PHASES P13.6).

One document per scan, built only from the evidence store and the security graph — the
same facts the API serves — so the HTML report and any other output are renderings of it:

* ``findings`` — every visible finding (merged duplicates folded into their primary) as the
  API's frozen ``FindingDetail``, ranked: open findings by risk, then resolved ones. Each adds
  its ``risk_breakdown`` (formula, factor values, the arithmetic) and what was merged into it.
* ``evidence`` — every evidence record of the scan (claims cite them by ID), payloads with
  credentials redacted.
* ``risk`` — the formula, so any score can be recomputed by hand.
* ``db_snapshot_dates`` — the offline vulnerability-database dates the results depend on.
* ``attack_paths`` — endpoint → function → sink → finding chains from the security graph.

Nothing here comes from the LLM except the explanation text that already passed validation.
A leaked secret is never reproduced: the ``where`` snippet masks the flagged line's literals,
and stored fix diffs for secrets are already masked.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.agent.explanation import five_parts
from aegis.api.schemas import EvidenceOut, FindingDetail, Scores
from aegis.evidence.links import linked_to, visible_findings
from aegis.evidence.models import Evidence, Finding, FindingState
from aegis.evidence.store import EvidenceStore
from aegis.fix.draft import mask_literals, secret_literals
from aegis.graph.correlator import build_graph, load_handlers
from aegis.graph.security_graph import SecurityGraph, graph_path
from aegis.llm.status import scan_llm_summary
from aegis.observability import get_logger
from aegis.risk import factors
from aegis.risk.engine import KMAX, RISK_FORMULA, risk_breakdown
from aegis.workers.runtime import coverage as runtime_coverage

__all__ = ["REPORT_VERSION", "build_json_report", "evidence_out", "finding_detail", "load_graph", "redact"]

log = get_logger("reports.json")

REPORT_VERSION = "1.0"
_SENSITIVE_KEYS = ("authorization", "cookie", "password", "passwd", "token", "secret", "api_key", "apikey", "session")
REDACTED = "***REDACTED***"


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _enum(value: Any) -> Any:
    return getattr(value, "value", value)


def redact(value: Any) -> Any:
    """Replace credential-like fields anywhere in a payload (a report is meant to be shared)."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            lowered = str(key).lower()
            sensitive = any(s in lowered for s in _SENSITIVE_KEYS) and not lowered.endswith(("_fingerprint", "_id", "_ids"))
            if sensitive and isinstance(item, (str, int, float)) and item not in ("", REDACTED):
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _payload(ev: Evidence) -> Any:
    try:
        return json.loads(ev.payload_json or "{}")
    except ValueError:
        return {"unparseable": True}


def evidence_out(ev: Evidence, *, redacted: bool) -> EvidenceOut:
    """An evidence record as the API shape; ``redacted`` for anything meant to be shared."""
    payload = _payload(ev)
    return EvidenceOut(
        id=ev.id,
        finding_id=ev.finding_id,
        scan_id=ev.scan_id,
        kind=ev.kind,
        tool=ev.tool,
        tool_version=ev.tool_version,
        db_date=ev.db_date,
        payload=redact(payload) if redacted else payload,
        created_at=_iso(ev.created_at),
    )


def _where(finding: Finding, source_path: str | None) -> str | None:
    where = five_parts(finding, source_path)["where"]
    if where and finding.type == "secret" and source_path and finding.file and finding.line:
        try:
            text = (Path(source_path) / finding.file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return where
        where = mask_literals(where, secret_literals(text, [finding.line]))
    return where


def _fix(store: EvidenceStore, finding: Finding) -> dict | None:
    attempt = store.latest_fix_attempt(finding.id)
    fix = five_parts(finding, None, attempt)["fix"]
    if fix is None or attempt is None:
        return fix
    stored = json.loads(attempt.verify_report_json or "{}")
    verify = stored.get("verify") or {}
    if verify:
        fix["verification"] = {
            "passed": verify.get("passed"),
            "reason": verify.get("reason"),
            **{name: (verify.get(name) or {}).get("status") for name in ("static", "tests", "runtime")},
            "retest_evidence_ids": verify.get("retest_evidence_ids", []),
        }
        commit = verify.get("commit") or {}
        fix["commit_mode"] = attempt.commit_mode
        fix["warnings"] = commit.get("warnings", [])
    if stored.get("resolution"):
        fix["resolution"] = stored["resolution"]
    return fix


def finding_detail(store: EvidenceStore, finding: Finding, source_path: str | None) -> dict:
    evidence_ids = [e.id for e in store.evidence_for(finding.id)]
    claims = [
        {"field": c.field, "text": c.text, "evidence_ids": json.loads(c.evidence_ids_json or "[]")}
        for c in store.list_claims(finding.id, kept=True)
    ]
    detail = FindingDetail(
        id=finding.id,
        type=finding.type,
        owasp=finding.owasp,
        title=finding.title,
        severity=finding.severity,
        state=_enum(finding.state),
        mode=_enum(finding.mode),
        route=finding.route,
        function=finding.function,
        file=finding.file,
        line=finding.line,
        risk=finding.risk,
        correlation_score=finding.correlation_score,
        what=finding.what,
        where=_where(finding, source_path),
        impact=finding.impact,
        exploit=finding.exploit,
        fix=_fix(store, finding),
        scores=Scores(
            confidence=factors.confidence(finding.state),
            exploitability=finding.exploitability,
            exposure=finding.exposure,
            criticality=finding.criticality,
            path_factor=finding.path_factor,
            risk=finding.risk,
            correlation=finding.correlation_score,
        ),
        claims=claims,
        evidence_ids=evidence_ids,
        sources=json.loads(finding.sources or "[]"),
    ).model_dump()
    detail["risk_breakdown"] = risk_breakdown(finding)
    detail["merged"] = linked_to(store, finding.id)
    detail["history"] = [
        {"from": t.from_state, "to": t.to_state, "actor": t.actor, "reason": t.reason, "evidence_ids": json.loads(t.evidence_ids or "[]"), "at": _iso(t.at)}
        for t in store.list_transitions([finding.id])
    ]
    return detail


def load_graph(store: EvidenceStore, scan_id: str, data_dir: str | Path | None) -> SecurityGraph:
    if data_dir is not None:
        saved = graph_path(data_dir, scan_id)
        if saved.is_file():
            return SecurityGraph.load(saved)
    return build_graph(store, scan_id, load_handlers(store, scan_id))


def _db_dates(scan, evidence: list[Evidence]) -> dict[str, str]:
    dates = json.loads(scan.db_snapshot_dates or "{}")
    for ev in evidence:  # a tool that recorded its own database date counts too
        if ev.db_date and ev.tool not in dates:
            dates[ev.tool] = ev.db_date
    return dict(sorted(dates.items()))


def _repo_commit(scan) -> str | None:
    """The commit a repo scan cloned (recorded by ``prepare``), so the report says what was scanned."""
    try:
        clone = json.loads(scan.config_json or "{}").get("repo_clone") or {}
    except (json.JSONDecodeError, AttributeError):
        return None
    return clone.get("commit") if isinstance(clone, dict) else None


def build_json_report(store: EvidenceStore, scan_id: str, *, data_dir: str | Path | None = None) -> dict:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise KeyError(f"unknown scan {scan_id}")
    findings = visible_findings(store, scan_id)
    open_ = sorted((f for f in findings if f.state != FindingState.resolved), key=lambda f: (-f.risk, -f.severity, f.id))
    resolved = sorted((f for f in findings if f.state == FindingState.resolved), key=lambda f: f.id)
    details = [finding_detail(store, f, scan.source_path) for f in [*open_, *resolved]]
    for rank, detail in enumerate(details, 1):
        detail["rank"] = rank

    evidence = store.list_evidence(scan_id)
    by_state: dict[str, int] = {}
    for f in findings:
        by_state[_enum(f.state)] = by_state.get(_enum(f.state), 0) + 1
    tool_calls = store.list_tool_calls(scan_id)
    graph = load_graph(store, scan_id, data_dir)

    # runtime coverage: a scan that finds nothing is not a clean bill of health if a check was
    # blocked (login / API description refused) or never attempted (TNW)
    _coverage = runtime_coverage.summarize(store, scan_id)
    _coverage_note = None
    if _coverage and runtime_coverage.is_limited(_coverage):
        _coverage_note = (
            "No findings were established for some runtime checks, but runtime coverage was "
            "limited — see runtime_coverage. A clean result here does not mean the target is secure."
        )

    report = {
        "aegis_report": REPORT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "id": scan.id,
            "mode": _enum(scan.mode),
            "status": _enum(scan.status),
            "target_url": scan.target_url,
            "source": Path(scan.source_path).name if scan.source_path else None,
            "repo_url": scan.repo_url,
            "repo_commit": _repo_commit(scan),
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
        },
        "summary": {
            "findings": len(findings),
            "open": len(open_),
            "resolved": len(resolved),
            "by_state": dict(sorted(by_state.items())),
            "top_risk": details[0]["id"] if open_ else None,
            "evidence": len(evidence),
        },
        "risk": {"formula": RISK_FORMULA, "kmax": KMAX, "confidence_by_state": {s.value: factors.confidence(s) for s in FindingState}},
        "runtime_coverage": _coverage,
        "runtime_coverage_note": _coverage_note,
        "db_snapshot_dates": _db_dates(scan, evidence),
        "findings": details,
        "attack_paths": graph.attack_paths(),
        "evidence": [evidence_out(ev, redacted=True).model_dump() for ev in sorted(evidence, key=lambda e: e.id)],
        "audit": {
            "tool_calls": len(tool_calls),
            "blocked": sum(1 for c in tool_calls if c.blocked_reason),
            "by_tool": dict(sorted({c.tool: sum(1 for d in tool_calls if d.tool == c.tool) for c in tool_calls}.items())),
            # which model wrote the explanations and drafts, and whether it could answer
            "ai": scan_llm_summary(scan, store.list_decisions(scan_id)),
        },
    }
    log.info("report.json_built", scan_id=scan_id, findings=len(details), evidence=len(evidence))
    return report
