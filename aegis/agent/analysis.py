"""Shared analysis helpers for the investigation loop (AG09).

* :func:`worklist` — the findings still being investigated, derived from the
  store (ranked, de-duplicated, unresolved, no terminal decision yet) so it is
  correct after a restart and never depends on what a previous iteration kept in
  memory.
* :func:`refresh_analysis` — after a tool action produced new evidence, re-link
  runtime findings to their handlers, re-score everything, and persist the graph,
  so the next iteration decides on current facts.

Deterministic; no LLM.
"""

from __future__ import annotations

import json

from aegis.agent.deps import AgentDeps
from aegis.evidence.models import Finding
from aegis.evidence.store import EvidenceStore
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers
from aegis.graph.security_graph import SecurityGraph, graph_path
from aegis.observability import get_logger
from aegis.risk.engine import rank_findings, score_scan

__all__ = ["TERMINAL_STEPS", "terminal_findings", "worklist", "refresh_analysis"]

log = get_logger("agent.analysis")

# Steps that close the investigation of a finding (no tool runs).
TERMINAL_STEPS = frozenset({"mark_sufficient", "escalate_to_human"})


def terminal_findings(store: EvidenceStore, scan_id: str) -> dict[str, str]:
    """``{finding_id: step}`` for findings that already got a valid terminal decision."""
    done: dict[str, str] = {}
    for decision in store.list_decisions(scan_id):
        if decision.node != "investigate" or not decision.valid or not decision.finding_id:
            continue
        try:
            step = json.loads(decision.output_json or "{}").get("next_step")
        except (json.JSONDecodeError, ValueError, AttributeError):
            continue
        if step in TERMINAL_STEPS:
            done[decision.finding_id] = step
    return done


def worklist(store: EvidenceStore, scan_id: str) -> list[Finding]:
    """Open findings by risk, minus those the loop has already closed."""
    closed = terminal_findings(store, scan_id)
    return [f for f in rank_findings(store, scan_id) if f.id not in closed]


def refresh_analysis(deps: AgentDeps, scan_id: str, scan_mode: str) -> SecurityGraph:
    """Re-correlate (correlated mode), re-score, and persist the graph. Returns the new graph."""
    store = deps.store
    handlers = load_handlers(store, scan_id)
    if scan_mode == "correlated":
        report = correlate_scan(store, scan_id, handlers, threshold=deps.correlation_threshold)
        log.info("analysis.correlated", scan_id=scan_id, linked=len(report.correlated))
    new_graph = build_graph(store, scan_id, handlers)
    scores = score_scan(store, scan_id, new_graph, sensitive_routes=deps.sensitive_routes)
    for finding_id, s in scores.items():
        new_graph.backend.add_node(finding_id, "finding", risk=s.risk)
    new_graph.save(graph_path(deps.data_dir, scan_id))
    log.info("analysis.refreshed", scan_id=scan_id, scored=len(scores))
    return new_graph
