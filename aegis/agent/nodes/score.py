"""score node (AG08) — deterministic risk for every finding, then the ranked worklist.

Builds the scan's security graph (the path factor needs it, and runtime-only /
code-only scans skip ``correlate``), scores every visible finding, writes the
risk onto the graph and persists it, and hands the ranked open findings to the
investigation loop as ``open_findings``. No LLM.
"""

from __future__ import annotations

import time

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.graph.correlator import build_graph, load_handlers
from aegis.graph.security_graph import graph_path
from aegis.observability import get_logger
from aegis.risk.engine import rank_findings, score_scan

log = get_logger("agent.node.score")


def score(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="score", scan_id=scan_id)
    started = time.monotonic()
    deps = get_deps(config)

    graph = build_graph(deps.store, scan_id, load_handlers(deps.store, scan_id))
    scores = score_scan(deps.store, scan_id, graph, sensitive_routes=deps.sensitive_routes)

    for finding_id, s in scores.items():  # make the graph carry the final risk
        graph.backend.add_node(finding_id, "finding", risk=s.risk)
    graph.save(graph_path(deps.data_dir, scan_id))

    ranked = rank_findings(deps.store, scan_id)
    log.info(
        "node.exit",
        node="score",
        scan_id=scan_id,
        scored=len(scores),
        open=len(ranked),
        top=[(f.id, f.risk) for f in ranked[:3]],
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {"open_findings": [f.id for f in ranked], "completed_stages": ["score"]}
