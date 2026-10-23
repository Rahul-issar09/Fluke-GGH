"""correlate node (AG07) — runs in correlated mode only.

Deterministic: links each runtime finding to its handler, merges the matching
static finding, then builds and persists the scan's security graph. No LLM.

The route → handler map is the Worker 2 evidence described in
``graph.correlator``; until that worker exists the map is empty and nothing is
correlated (the graph is still built from whatever the scan produced).
"""

from __future__ import annotations

import time

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers
from aegis.graph.security_graph import graph_path
from aegis.observability import get_logger

log = get_logger("agent.node.correlate")


def correlate(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="correlate", scan_id=scan_id)
    started = time.monotonic()
    deps = get_deps(config)

    handlers = load_handlers(deps.store, scan_id)
    if not handlers:
        log.info("correlate.no_handler_map", scan_id=scan_id)
    report = correlate_scan(deps.store, scan_id, handlers, threshold=deps.correlation_threshold)

    graph = build_graph(deps.store, scan_id, handlers)
    saved = graph.save(graph_path(deps.data_dir, scan_id))

    log.info(
        "node.exit",
        node="correlate",
        scan_id=scan_id,
        handlers=len(handlers),
        correlated=len(report.correlated),
        dropped=len(report.dropped),
        graph=str(saved),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {"completed_stages": ["correlate"]}
