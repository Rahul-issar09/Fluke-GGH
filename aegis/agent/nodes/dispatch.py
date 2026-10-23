"""dispatch node (PHASES P11.3 / AG09.2) — turns a decision into a fixed, safe action.

The mapping from a ``NextStep`` to what runs is fixed in code (below). The model's
decision only selects *which* mapped action; every target (route, file, function)
is **re-derived from the store here** and the decision's own ``target`` is ignored,
so a model can never steer a tool at a URL, host, file or payload of its choosing.
Tools run through the worker stages' registered steps (so SafetyController, the
allowlist and the audit still apply).

====================== ===============================================================
request_source_evidence  ``code``: extract_routes, then semgrep **on the matched handler's file**
request_runtime_retest   ``runtime``: validate/discover/authenticate/model, then the replay
                         check **on that one route**
request_crypto_scan      ``crypto``: discover → rules → CBOM, scoped to the finding's file
link_and_score           correlator + risk (the refresh below) — no tool
mark_sufficient /        recorded only — no tool
escalate_to_human
====================== ===============================================================

After any action the analysis is refreshed (re-correlate, re-score, persist graph), so a
retest that proves a static finding merges it into the new runtime finding and the next
iteration decides on current facts. Every action is recorded as an ``AgentDecision`` with
``node="dispatch"`` for the audit trail.
"""

from __future__ import annotations

import time
from typing import Any

from langchain_core.runnables import RunnableConfig

from aegis.agent.analysis import refresh_analysis, worklist
from aegis.agent.deps import AgentDeps, get_deps
from aegis.agent.nodes.worker_stage import run_steps
from aegis.agent.schemas import NextStep, NextStepDecision
from aegis.evidence.models import Finding
from aegis.graph.correlator import Handler, RuntimeTarget, build_graph, link_score, load_handlers
from aegis.graph.route_normalize import split_route
from aegis.observability import get_logger

log = get_logger("agent.node.dispatch")

_RUNTIME_PREP = ["validate_target", "discover_routes", "authenticate", "build_request_model"]
_RUNTIME_CHECK = {"broken_access_control": "check_bola", "ssrf": "check_ssrf"}
_CRYPTO_STEPS = ["discover", "classical_rules", "quantum_rules", "build_cbom"]
_NO_TOOL = (NextStep.mark_sufficient, NextStep.escalate_to_human, NextStep.link_and_score)


def matched_handler(handlers: list[Handler], finding: Finding) -> Handler | None:
    """The handler declaring the finding's route (same normalized path; method preferred)."""
    parsed = split_route(finding.route or "")
    if parsed is None:
        return None
    target = RuntimeTarget(*parsed)
    scored = []
    for handler in handlers:
        score, signals = link_score(target, handler, [])
        if signals.get("route"):
            scored.append((-score, handler.qualname, handler))
    return min(scored, key=lambda t: (t[0], t[1]))[2] if scored else None


def _outcome(step: NextStep, **extra: Any) -> dict[str, Any]:
    return {"action": step.value, **extra}


def _summarize_run(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "steps_run": list(result.get("steps_run", [])),
        "steps_skipped": list(result.get("steps_skipped", [])),
        "errors": list(result.get("errors", [])),
    }


async def _source_evidence(finding: Finding, state: dict, config: RunnableConfig, deps: AgentDeps) -> dict[str, Any]:
    extract = await run_steps("code", ["extract_routes"], state, config)
    handler = matched_handler(load_handlers(deps.store, finding.scan_id), finding)
    if handler is None:
        log.info("dispatch.no_handler_located", finding_id=finding.id)
        return _outcome(NextStep.request_source_evidence, handler=None, note="no handler located", **_summarize_run(extract))
    semgrep = await run_steps(
        "code", ["semgrep"], state, config,
        target={"file": handler.file, "function": handler.function, "route": finding.route},
    )
    merged = _summarize_run(extract)
    scan = _summarize_run(semgrep)
    return _outcome(
        NextStep.request_source_evidence,
        handler=handler.qualname,
        target={"file": handler.file},
        steps_run=merged["steps_run"] + scan["steps_run"],
        steps_skipped=merged["steps_skipped"] + scan["steps_skipped"],
        errors=merged["errors"] + scan["errors"],
    )


async def _runtime_retest(finding: Finding, state: dict, config: RunnableConfig, deps: AgentDeps) -> dict[str, Any]:
    check = _RUNTIME_CHECK.get(finding.type)
    graph = build_graph(deps.store, finding.scan_id, load_handlers(deps.store, finding.scan_id))
    route = finding.route
    if route is None:  # a static finding: the endpoint that reaches its function, from the graph
        for target in graph.backend.successors(finding.id, "ON"):
            routes = graph.backend.predecessors(target, "HANDLED_BY")
            if routes:
                route = sorted(routes)[0]
                break
    if check is None or route is None:
        return _outcome(NextStep.request_runtime_retest, note="no runtime check or endpoint for this finding")
    result = await run_steps("runtime", [*_RUNTIME_PREP, check], state, config, target={"route": route})
    return _outcome(NextStep.request_runtime_retest, target={"route": route}, check=check, **_summarize_run(result))


async def _crypto_scan(finding: Finding, state: dict, config: RunnableConfig, deps: AgentDeps) -> dict[str, Any]:
    result = await run_steps("crypto", _CRYPTO_STEPS, state, config, target={"file": finding.file})
    return _outcome(NextStep.request_crypto_scan, target={"file": finding.file}, **_summarize_run(result))


async def _execute(
    decision: NextStepDecision, state: dict, config: RunnableConfig, deps: AgentDeps
) -> dict[str, Any]:
    step = decision.next_step
    if step in _NO_TOOL:
        return _outcome(step, tool=False)
    finding = deps.store.get_finding(decision.finding_id)
    if finding is None:
        return _outcome(step, note="finding no longer exists")
    if step == NextStep.request_source_evidence:
        return await _source_evidence(finding, state, config, deps)
    if step == NextStep.request_runtime_retest:
        return await _runtime_retest(finding, state, config, deps)
    return await _crypto_scan(finding, state, config, deps)


async def dispatch(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    iteration = state.get("iterations", 0)
    log.info("node.enter", node="dispatch", scan_id=scan_id, iteration=iteration)
    started = time.monotonic()
    deps = get_deps(config)
    scan = deps.store.get_scan(scan_id)
    scan_mode = scan.mode.value if scan is not None and hasattr(scan.mode, "value") else str(state.get("mode"))

    errors: list[str] = []
    for decision in state.get("pending_actions") or []:
        try:
            outcome = await _execute(decision, state, config, deps)
        except Exception as exc:  # noqa: BLE001 - one failed action must not end the investigation
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
            outcome = _outcome(decision.next_step, errors=[reason])
            log.error("dispatch.action_failed", finding_id=decision.finding_id, step=decision.next_step.value, reason=reason)
        errors += [f"dispatch.{decision.next_step.value}: {e}" for e in outcome.get("errors", [])]
        deps.store.add_decision(
            scan_id, "dispatch", "rule", finding_id=decision.finding_id,
            input_summary={"next_step": decision.next_step.value, "iteration": iteration},
            output=outcome, valid=True, error=None,
        )
        log.info("dispatch.action", scan_id=scan_id, finding_id=decision.finding_id, **{k: v for k, v in outcome.items() if k != "errors"})

    refresh_analysis(deps, scan_id, scan_mode)  # re-correlate + re-score on whatever the tools produced

    open_ids = [f.id for f in worklist(deps.store, scan_id)]
    log.info(
        "node.exit", node="dispatch", scan_id=scan_id, actions=len(state.get("pending_actions") or []),
        open=len(open_ids), duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {
        "pending_actions": [],
        "iterations": iteration + 1,
        "open_findings": open_ids,
        "errors": errors,
        "completed_stages": ["dispatch"],
    }
