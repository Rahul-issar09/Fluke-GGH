"""investigate node (PHASES P11.2 / AG09.2) — rules first, the LLM second.

For every open finding (the worklist is derived from the store each pass):

1. build a normalized :class:`FindingSummary` (IDs and fields, never raw evidence);
2. ``rules.decide`` — if exactly one step is valid, that is the decision (source ``rule``);
3. otherwise ask the LLM to pick **among the steps the rules declared valid**. The
   payload goes through the prompt guard and carries only normalized fields plus
   evidence *digests*; the answer is validated (``validate_decision``); one corrective
   retry; then ``rules.default`` (source ``fallback``). If the model is unreachable the
   result is the same fallback — an LLM outage never fails a scan;
4. persist every decision, including rejected LLM attempts (``valid=False`` + the reason);
5. terminal decisions (``mark_sufficient`` / ``escalate_to_human``) close the finding; tool
   actions are queued in ``pending_actions`` for ``dispatch``.

The model never creates, edits or deletes a finding and never supplies a target: the
decision's target is replaced by the one resolved from the store.
"""

from __future__ import annotations

import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from aegis.agent import rules
from aegis.agent.analysis import TERMINAL_STEPS, worklist
from aegis.agent.deps import AgentDeps, get_deps
from aegis.agent.llm import llm_unavailable, structured_call
from aegis.agent.prompt_guard import build_payload
from aegis.agent.rules import FindingSummary
from aegis.agent.schemas import NextStep, NextStepDecision, Target
from aegis.agent.validator import validate_decision
from aegis.evidence.digest import digest
from aegis.graph.correlator import build_graph, load_handlers
from aegis.graph.security_graph import SecurityGraph
from aegis.observability import get_logger

log = get_logger("agent.node.investigate")

_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "investigate.txt"
_MAX_DIGESTS = 6


@lru_cache(maxsize=1)
def _system_prompt() -> str:
    return _PROMPT.read_text(encoding="utf-8")


def _input_summary(s: FindingSummary, valid: list[NextStep]) -> dict[str, Any]:
    return {
        "finding_id": s.finding_id,
        "type": s.type,
        "state": s.state,
        "mode": s.mode,
        "route": s.route,
        "function": s.function,
        "correlation": s.correlation,
        "evidence_ids": s.evidence_ids,
        "attempted": list(s.attempted),
        "valid_next_steps": [v.value for v in valid],
    }


def _output(d: NextStepDecision) -> dict[str, Any]:
    return {
        "next_step": d.next_step.value,
        "target": d.target.model_dump(),
        "reason_evidence_ids": list(d.reason_evidence_ids),
    }


def _prompt_payload(deps: AgentDeps, s: FindingSummary, valid: list[NextStep]) -> dict[str, Any]:
    """The only thing the model sees: normalized fields + evidence digests, via the prompt guard."""
    digests = [digest(e) for e in deps.store.evidence_for(s.finding_id)][:_MAX_DIGESTS]
    return build_payload(
        {
            "finding_id": s.finding_id,
            "type": s.type,
            "state": s.state,
            "mode": s.mode,
            "route": s.route,
            "function": s.function,
            "file": s.file,
            "line": s.line,
            "scores": {"risk": s.risk, "correlation": s.correlation},
            "evidence_ids": s.evidence_ids,
            "evidence_digests": digests,
            "valid_next_steps": [v.value for v in valid],
        }
    )


async def _consult_llm(
    deps: AgentDeps,
    s: FindingSummary,
    valid: list[NextStep],
    graph: SecurityGraph,
    audit: list[dict[str, Any]],
    route: dict[str, Any],
) -> tuple[NextStepDecision | None, str, str | None]:
    """Ask the model; returns ``(decision | None, source, error)``. Rejected attempts go to *audit*."""
    rejected: list[tuple[NextStepDecision, list[str]]] = []

    def validate(decision: NextStepDecision) -> list[str]:
        errors = validate_decision(decision, summary=s, valid=valid, store=deps.store, graph=graph)
        if errors:
            rejected.append((decision, errors))
        return errors

    trace: list[dict[str, Any]] = []
    try:
        decision, source = await structured_call(
            NextStepDecision,
            _system_prompt(),
            _prompt_payload(deps, s, valid),
            validate,
            trace=trace,
            **route,
        )
    except Exception as exc:  # noqa: BLE001 - the model being down must never fail the scan
        log.warning("investigate.llm_unavailable", finding_id=s.finding_id, error=type(exc).__name__)
        return None, "fallback", llm_unavailable(exc)

    rejected_iter = iter(rejected)
    for entry in trace:
        source_label = "llm" if entry["attempt"] == "llm" else "llm_retry"
        output: dict[str, Any] = {"rejected": entry["kind"]}
        if entry["kind"] == "invalid":
            bad, _ = next(rejected_iter, (None, None))
            if bad is not None:
                output = {**_output(bad), "rejected": "invalid"}
        audit.append({"source": source_label, "output": output, "error": entry["error"]})

    if decision is None:
        return None, "fallback", "; ".join(e["error"] for e in trace)[:300] or "no valid llm answer"
    return decision, source, None


async def investigate(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="investigate", scan_id=scan_id, iteration=state.get("iterations", 0))
    started = time.monotonic()
    deps = get_deps(config)
    store = deps.store

    scan = store.get_scan(scan_id)
    scan_mode = scan.mode.value if scan is not None and hasattr(scan.mode, "value") else str(state.get("mode"))
    graph = build_graph(store, scan_id, load_handlers(store, scan_id))
    threshold = deps.correlation_threshold

    pending: list[NextStepDecision] = []
    closed = 0
    route: dict[str, Any] | None = None  # how to reach the model; resolved on the first judgment call
    for finding in worklist(store, scan_id):
        summary = rules.summarize_finding(store, finding, scan_mode=scan_mode, graph=graph)
        valid = rules.valid_steps(summary, threshold)
        if not summary.evidence:
            log.warning("investigate.no_evidence_to_cite", finding_id=finding.id)
            continue

        source, error = "rule", None
        decision = rules.decide(summary, threshold)
        audit: list[dict[str, Any]] = []
        if decision is None:  # several steps are valid: a judgment call for the model
            route = route or deps.llm_route(scan_id)  # the model this scan started with (read once)
            decision, source, error = await _consult_llm(deps, summary, valid, graph, audit, route)
            if decision is None:
                decision = rules.default(summary, threshold)
                source = "fallback"
            else:  # keep what the model suggested, but the target comes from the store
                decision = decision.model_copy(
                    update={"target": Target(route=summary.route or summary.handler_route, function=summary.function)}
                )

        for rejected in audit:  # what the model said and why it was refused
            store.add_decision(
                scan_id, "investigate", rejected["source"], finding_id=finding.id,
                input_summary=_input_summary(summary, valid), output=rejected["output"],
                valid=False, error=rejected["error"],
            )
        if decision is None:
            continue
        store.add_decision(
            scan_id, "investigate", source, finding_id=finding.id,
            input_summary=_input_summary(summary, valid), output=_output(decision),
            valid=True, error=error,
        )
        log.info(
            "investigate.decision",
            scan_id=scan_id,
            finding_id=finding.id,
            next_step=decision.next_step.value,
            source=source,
            valid_steps=[v.value for v in valid],
        )

        if decision.next_step.value in TERMINAL_STEPS:
            closed += 1
        else:
            pending.append(decision)

    log.info(
        "node.exit",
        node="investigate",
        scan_id=scan_id,
        pending=[(d.finding_id, d.next_step.value) for d in pending],
        closed=closed,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {
        "pending_actions": pending,
        "open_findings": [d.finding_id for d in pending],
        "completed_stages": ["investigate"],
    }
