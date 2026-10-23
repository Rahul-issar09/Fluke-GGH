"""Worker stage subgraphs (PHASES P3.4 / AG05.3).

Each worker stage (runtime / code / crypto) is a LangGraph subgraph: a linear
chain of *steps* (SYSTEM_DESIGN §5.3). The step implementations are workers
built in AG06/AG14/AG15; they register themselves here::

    @register_step("runtime", "check_bola")
    async def check_bola(state, config): ...

so the graph can already run with whatever exists:

* a step that is not registered is **skipped with a WARNING** (never a crash),
* a step that raises is recorded as ``Evidence(kind="tool_error")`` and the
  chain continues (P4.2 — "a failing tool produces tool_error evidence and the
  next node still runs"),
* a step may raise :class:`StageAbort` to stop the remaining steps of its stage
  (e.g. the target is unreachable / off-allowlist); the abort is recorded and
  the stage still completes so the scan can report it.

The subgraph uses a private state schema (not the frozen ``AegisState``) so the
step bookkeeping never leaks into, or duplicates, parent-state reducers. The
parent only receives ``completed_stages`` and ``errors``.

No LLM is used inside workers.
"""

from __future__ import annotations

import inspect
import operator
import time
from collections.abc import Callable
from typing import Annotated, Any, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph

from aegis.agent.deps import MissingDeps, get_deps
from aegis.agent.state import ScanInputs
from aegis.evidence.models import Mode
from aegis.observability import get_logger

__all__ = [
    "STAGE_STEPS",
    "STEP_REGISTRY",
    "StageAbort",
    "StageState",
    "register_step",
    "build_stage_graph",
    "make_stage_node",
    "run_steps",
]

log = get_logger("agent.stage")

# Step order per stage. runtime/code follow SD §5.3. crypto follows PHASES P3.4
# (discover → classical → quantum → cbom → tls): the CBOM carries the
# classical/quantum flags, so it must be built after the rules run (the SD §5.3
# listing puts build_cbom first — see conflict C40).
STAGE_STEPS: dict[str, list[str]] = {
    "runtime": [
        # first, so a target whose certificate is not trusted still gets its TLS findings
        # (validate_target then stops the stage); runtime-only scans only (TNW-2)
        "tls_scan",
        "validate_target",
        "discover_routes",
        "authenticate",
        # routes from a crawl when the target publishes no OpenAPI document (TNW-4); after the
        # login, so pages behind it are found too
        "crawl",
        "build_request_model",
        "check_bola",
        "check_ssrf",
        "check_misconfig",
        "check_api",
    ],
    "code": ["inventory", "extract_routes", "semgrep", "gitleaks", "trufflehog", "osv", "trivy"],
    "crypto": ["discover", "classical_rules", "quantum_rules", "tls_scan", "build_cbom"],
}

# step(state, config) -> None | {"errors": [str]}   (sync or async)
StepFn = Callable[[dict, RunnableConfig], Any]
STEP_REGISTRY: dict[str, StepFn] = {}


class StageAbort(Exception):
    """Raised by a step to stop the remaining steps of its stage."""


def register_step(stage: str, step: str) -> Callable[[StepFn], StepFn]:
    if stage not in STAGE_STEPS or step not in STAGE_STEPS[stage]:
        raise ValueError(f"unknown worker step '{stage}.{step}'")

    def decorator(fn: StepFn) -> StepFn:
        STEP_REGISTRY[f"{stage}.{step}"] = fn
        return fn

    return decorator


class StageState(TypedDict, total=False):
    scan_id: str
    mode: Mode
    inputs: ScanInputs
    errors: Annotated[list[str], operator.add]
    aborted: bool
    steps_run: Annotated[list[str], operator.add]
    steps_skipped: Annotated[list[str], operator.add]
    # Set only when the investigation loop narrows a run to one route / file / function
    # (resolved from the store, never supplied by the model). Steps may honor it.
    target: dict[str, Any]


def _record_failure(config: RunnableConfig, scan_id: str, key: str, reason: str) -> None:
    """Persist a failed step as tool_error evidence (best effort)."""
    try:
        deps = get_deps(config)
    except MissingDeps:
        return
    try:
        deps.store.add_tool_error(scan_id, tool=key, reason=reason)
    except Exception as exc:  # noqa: BLE001 - never let bookkeeping break the scan
        log.error("stage.tool_error_not_recorded", scan_id=scan_id, step=key, error=str(exc)[:200])


def _make_step_node(stage: str, step: str, registry: dict[str, StepFn] | None):
    key = f"{stage}.{step}"

    async def run_step(state: StageState, config: RunnableConfig) -> dict:
        scan_id = state.get("scan_id", "")
        if state.get("aborted"):
            log.info("step.skipped_stage_aborted", stage=stage, step=step, scan_id=scan_id)
            return {"steps_skipped": [step]}

        fn = (registry if registry is not None else STEP_REGISTRY).get(key)
        if fn is None:
            log.warning("step.not_implemented", stage=stage, step=step, scan_id=scan_id)
            return {"steps_skipped": [step]}

        log.info("step.enter", stage=stage, step=step, scan_id=scan_id)
        started = time.monotonic()
        try:
            result = fn(state, config)
            if inspect.isawaitable(result):
                result = await result
        except StageAbort as exc:
            reason = str(exc)[:200]
            _record_failure(config, scan_id, key, reason)
            log.error("step.abort", stage=stage, step=step, scan_id=scan_id, reason=reason)
            return {"aborted": True, "errors": [f"{key}: {reason}"], "steps_run": [step]}
        except Exception as exc:  # noqa: BLE001 - a failing tool must not crash the scan (P4.2)
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
            _record_failure(config, scan_id, key, reason)
            log.error("step.failed", stage=stage, step=step, scan_id=scan_id, reason=reason)
            return {"errors": [f"{key}: {reason}"], "steps_run": [step]}

        update: dict[str, Any] = {"steps_run": [step]}
        if isinstance(result, dict):
            extra = set(result) - {"errors"}
            if extra:
                log.warning("step.ignored_keys", stage=stage, step=step, keys=sorted(extra))
            if result.get("errors"):
                update["errors"] = list(result["errors"])
        log.info(
            "step.exit",
            stage=stage,
            step=step,
            scan_id=scan_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return update

    run_step.__name__ = f"{stage}_{step}"
    return run_step


def build_stage_graph(
    stage: str, registry: dict[str, StepFn] | None = None, steps: list[str] | None = None
):
    """Compile the linear step chain for *stage* (all steps, or the given subset in stage order)."""
    chosen = STAGE_STEPS[stage] if steps is None else [s for s in STAGE_STEPS[stage] if s in steps]
    g = StateGraph(StageState)
    previous = START
    for step in chosen:
        g.add_node(step, _make_step_node(stage, step, registry))
        g.add_edge(previous, step)
        previous = step
    g.add_edge(previous, END)
    return g.compile()


def make_stage_node(stage: str, registry: dict[str, StepFn] | None = None):
    """Build the parent-graph node for *stage* (runs its subgraph)."""
    subgraph = build_stage_graph(stage, registry)

    async def stage_node(state: dict, config: RunnableConfig) -> dict:
        scan_id = state["scan_id"]
        log.info("node.enter", node=stage, scan_id=scan_id)
        started = time.monotonic()
        try:
            sub = await subgraph.ainvoke(
                {
                    "scan_id": scan_id,
                    "mode": state.get("mode"),
                    "inputs": state.get("inputs"),
                    "errors": [],
                    "aborted": False,
                    "steps_run": [],
                    "steps_skipped": [],
                },
                config,
            )
        finally:
            # in-memory sessions/clients live only for the duration of the stage
            try:
                await get_deps(config).close_scratch(scan_id, stage)
            except MissingDeps:
                pass
        log.info(
            "node.exit",
            node=stage,
            scan_id=scan_id,
            steps_run=sub.get("steps_run", []),
            steps_skipped=sub.get("steps_skipped", []),
            aborted=bool(sub.get("aborted")),
            errors=len(sub.get("errors", [])),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"completed_stages": [stage], "errors": list(sub.get("errors", []))}

    stage_node.__name__ = f"{stage}_subgraph"
    return stage_node


async def run_steps(
    stage: str,
    steps: list[str],
    state: dict,
    config: RunnableConfig,
    *,
    target: dict[str, Any] | None = None,
    registry: dict[str, StepFn] | None = None,
) -> dict[str, Any]:
    """Run a subset of *stage*'s steps, optionally narrowed to one target.

    Used by the investigation loop (``dispatch``) for focused evidence requests:
    e.g. only ``semgrep`` on one file, or the replay check on one route. Same
    semantics as a full stage — missing steps are skipped, failures become
    ``tool_error`` evidence — and the stage's in-memory scratch (HTTP client,
    sessions) is closed afterwards. Returns the stage result
    (``steps_run`` / ``steps_skipped`` / ``errors`` / ``aborted``).
    """
    scan_id = state["scan_id"]
    subgraph = build_stage_graph(stage, registry, steps)
    log.info("subset.enter", stage=stage, steps=steps, scan_id=scan_id, target=target or {})
    try:
        result = await subgraph.ainvoke(
            {
                "scan_id": scan_id,
                "mode": state.get("mode"),
                "inputs": state.get("inputs"),
                "errors": [],
                "aborted": False,
                "steps_run": [],
                "steps_skipped": [],
                "target": dict(target or {}),
            },
            config,
        )
    finally:
        try:
            await get_deps(config).close_scratch(scan_id, stage)
        except MissingDeps:
            pass
    log.info(
        "subset.exit",
        stage=stage,
        scan_id=scan_id,
        steps_run=result.get("steps_run", []),
        steps_skipped=result.get("steps_skipped", []),
        errors=len(result.get("errors", [])),
    )
    return result
