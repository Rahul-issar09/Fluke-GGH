"""explain node (PHASES P12.1 / AG10.1) — the model *proposes* an explanation; it writes nothing.

For each finding the model gets the guarded payload (normalized fields and evidence
**digests** — never raw evidence, code or comments) and answers with
``Explanation{finding_id, claims[{field, text, evidence_ids}]}``.

This node does not touch a finding. It records what the model said — and anything it
said that was refused — in the audit log (``AgentDecision``, node ``explain``). The
``validate`` node reads that record, drops every claim that is not backed by real
evidence, and is the only place that writes explanation fields. If the model is
unreachable or never gives a usable answer, an empty proposal is recorded
(source ``fallback``) and ``validate`` fills the parts from fixed templates.
"""

from __future__ import annotations

import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import AgentDeps, get_deps
from aegis.agent.llm import llm_unavailable, structured_call
from aegis.agent.prompt_guard import build_payload
from aegis.agent.schemas import Explanation
from aegis.agent.validator import correlated_evidence_ids, exploit_established, validate_claims
from aegis.evidence.digest import digest
from aegis.evidence.links import visible_findings
from aegis.evidence.models import Finding
from aegis.graph.correlator import build_graph, load_handlers
from aegis.graph.security_graph import SecurityGraph
from aegis.observability import get_logger

log = get_logger("agent.node.explain")

_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "explain.txt"
_MAX_DIGESTS = 10


@lru_cache(maxsize=1)
def _system_prompt() -> str:
    return _PROMPT.read_text(encoding="utf-8")


def _payload(deps: AgentDeps, finding: Finding, allowed: set[str], scan_mode: str) -> dict[str, Any]:
    """Only normalized fields and digests, through the prompt guard."""
    evidence = {e.id: e for e in deps.store.list_evidence(finding.scan_id) if e.id in allowed}
    digests = [digest(evidence[i]) for i in sorted(evidence)][:_MAX_DIGESTS]
    return build_payload(
        {
            "finding_id": finding.id,
            "type": finding.type,
            "owasp": finding.owasp,
            "title": finding.title,
            "state": finding.state.value,
            "mode": scan_mode,
            "route": finding.route,
            "function": finding.function,
            "file": finding.file,
            "line": finding.line,
            "where": f"{finding.file}:{finding.line}" if finding.file and finding.line else finding.file,
            "scores": {
                "risk": finding.risk,
                "severity": finding.severity,
                "exploitability": finding.exploitability,
                "exposure": finding.exposure,
                "criticality": finding.criticality,
                "path_factor": finding.path_factor,
                "correlation": finding.correlation_score,
            },
            "evidence_ids": sorted(allowed),
            "evidence_digests": digests,
        }
    )


def _dump(explanation: Explanation) -> list[dict[str, Any]]:
    return [c.model_dump() for c in explanation.claims]


async def explain(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="explain", scan_id=scan_id)
    started = time.monotonic()
    deps = get_deps(config)
    store = deps.store

    scan = store.get_scan(scan_id)
    scan_mode = scan.mode.value if scan is not None and hasattr(scan.mode, "value") else str(state.get("mode"))
    graph: SecurityGraph = build_graph(store, scan_id, load_handlers(store, scan_id))
    route = deps.llm_route(scan_id)  # the model this scan started with

    proposed = 0
    for finding in sorted(visible_findings(store, scan_id), key=lambda f: (-f.risk, f.id)):
        allowed = correlated_evidence_ids(store, graph, finding.id)
        if not allowed:
            log.warning("explain.no_evidence_to_cite", finding_id=finding.id)
            continue

        def validate(explanation: Explanation, _finding=finding, _allowed=allowed) -> list[str]:
            """A retry is worth it only if nothing usable came back; individual bad claims are just dropped."""
            if explanation.finding_id != _finding.id:
                return [f"finding_id must be '{_finding.id}', not '{explanation.finding_id}'"]
            verdicts = validate_claims(
                explanation.claims, finding_id=_finding.id, allowed_evidence_ids=_allowed, store=store,
                exploit_established=exploit_established(_finding),
            )
            if any(v.kept for v in verdicts):
                return []
            return [r for v in verdicts for r in v.reasons][:5] or ["write at least one claim"]

        trace: list[dict[str, Any]] = []
        error: str | None = None
        try:
            explanation, source = await structured_call(
                Explanation,
                _system_prompt(),
                _payload(deps, finding, allowed, scan_mode),
                validate,
                trace=trace,
                **route,
            )
        except Exception as exc:  # noqa: BLE001 - the model being down must never fail the scan
            log.warning("explain.llm_unavailable", finding_id=finding.id, error=type(exc).__name__)
            explanation, source, error = None, "fallback", llm_unavailable(exc)

        for attempt in trace:  # what the model produced that was refused
            store.add_decision(
                scan_id, "explain", "llm" if attempt["attempt"] == "llm" else "llm_retry",
                finding_id=finding.id, input_summary={"finding_id": finding.id, "evidence_ids": sorted(allowed)},
                output={"rejected": attempt["kind"]}, valid=False, error=attempt["error"],
            )
        if explanation is None:
            error = error or "; ".join(a["error"] for a in trace)[:300] or "no usable explanation"
        store.add_decision(
            scan_id, "explain", source, finding_id=finding.id,
            input_summary={"finding_id": finding.id, "evidence_ids": sorted(allowed)},
            output={"claims": _dump(explanation) if explanation else []}, valid=True, error=error,
        )
        proposed += 1
        log.info(
            "explain.proposed", scan_id=scan_id, finding_id=finding.id, source=source,
            claims=len(explanation.claims) if explanation else 0,
        )

    log.info(
        "node.exit", node="explain", scan_id=scan_id, findings=proposed,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {"completed_stages": ["explain"]}
