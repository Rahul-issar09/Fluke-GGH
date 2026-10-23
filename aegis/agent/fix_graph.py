"""The fix subgraph — human in the loop (AG11.2, PHASES P12.7–P12.8, SYSTEM_DESIGN §5.7).

::

    START → make_copy → apply_diff → verify_static → verify_tests → verify_runtime → record
                │            │             │              │               │           │
                └────────────┴─────────────┴──── fail ────┴───────────────┘           │ verified
                                     ▼                                                 ▼
                               mark_failed → END                   await_approval ⇄ commit → END

* Each step is one node over ``FixState`` (thread ``fix_id``, checkpointed), so a pause or a
  crash resumes where it stopped. ``verify_runtime`` marks itself ``skipped`` outside Mode 3.
* ``await_approval`` calls ``interrupt({fix_id, verify_report, …})``: the graph waits for a
  human. It resumes with ``Command(resume={"mode": "patch" | "apply"})``; any other answer is
  refused and the graph pauses again — nothing is committed without an explicit approval.
* ``commit`` writes the fix (``fix.committer``). If that is refused (e.g. a read-only source for
  ``apply``) the graph goes back to waiting, so a different mode can be chosen. Once committed,
  the finding is resolved through the state machine with the verification's ``retest``
  evidence — the only way a fix changes a finding's state.

No LLM is involved in this graph.
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import var_child_runnable_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from aegis.agent.deps import AgentDeps, get_deps
from aegis.agent.state import FixState
from aegis.evidence.state_machine import IllegalTransition, transition
from aegis.fix.committer import commit_fix, unavailable_reason
from aegis.fix.verifier import (
    PatchedTarget,
    VerifyContext,
    apply_to_copy,
    begin,
    check_failed,
    conclude,
    load_subject,
    make_copy,
    run_check,
)
from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.executor import execute_tool

__all__ = ["APPROVAL_MODES", "build_fix_graph", "verify_context"]

log = get_logger("agent.fix_graph")

APPROVAL_MODES = ("patch", "apply")


def verify_context(deps: AgentDeps, fix_id: str) -> VerifyContext:
    """The verifier's collaborators for *fix_id*'s scan: its own allowlist, tools, transport."""
    store = deps.store
    attempt = store.get_fix_attempt(fix_id)
    finding = store.get_finding(attempt.finding_id) if attempt else None
    scan = store.get_scan(finding.scan_id) if finding else None
    scan_cfg = json.loads(scan.config_json or "{}") if scan else {}
    allowlist = Allowlist(scan_cfg.get("allowlist") or deps.default_allowlist)

    patched = deps.patched_target
    if patched is None and deps.patched_target_url:
        url = deps.patched_target_url

        async def prestaged(_workspace: Path) -> PatchedTarget:
            return PatchedTarget(base_url=url, built_from_workspace=False)

        patched = prestaged

    return VerifyContext(
        store=store,
        controller=SafetyController(
            allowlist,
            TestInputLibrary.load(),
            RateLimiter(deps.rate_limit_rps, deps.rate_limit_burst),
            executor=deps.tool_executor or execute_tool,
            audit_sink=store.add_tool_call_log,
        ),
        workspaces_root=Path(deps.data_dir) / "workspaces",
        allowlist=allowlist,
        http_transport=deps.http_transport,
        rate_limit_rps=deps.rate_limit_rps,
        rate_limit_burst=deps.rate_limit_burst,
        patched_target=patched,
    )


def _ctx(state: FixState, config: RunnableConfig) -> VerifyContext:
    return verify_context(get_deps(config), state["fix_id"])


def _workspace(state: FixState) -> Path:
    return Path(state["workspace_path"])


# --- verification ------------------------------------------------------------------------------ #
async def make_copy_node(state: FixState, config: RunnableConfig) -> dict:
    ctx = _ctx(state, config)
    log.info("node.enter", node="make_copy", fix_id=state["fix_id"])
    report = begin(ctx, state["fix_id"])
    attempt = ctx.store.get_fix_attempt(state["fix_id"])
    if report.get("passed") is False:
        return {"verify_report": report, "diff": attempt.diff}
    workspace, report = await make_copy(ctx, state["fix_id"], report)
    return {"workspace_path": str(workspace) if workspace else None, "verify_report": report, "diff": attempt.diff}


async def apply_diff_node(state: FixState, config: RunnableConfig) -> dict:
    report = await apply_to_copy(_ctx(state, config), state["fix_id"], _workspace(state), state["verify_report"])
    return {"verify_report": report}


def _check_node(name: str):
    async def node(state: FixState, config: RunnableConfig) -> dict:
        report = await run_check(_ctx(state, config), name, state["fix_id"], _workspace(state), state["verify_report"])
        return {"verify_report": report}

    node.__name__ = f"verify_{name}"
    return node


def _record(passed_expected: bool):
    async def node(state: FixState, config: RunnableConfig) -> dict:
        workspace = Path(state["workspace_path"]) if state.get("workspace_path") else None
        report = conclude(_ctx(state, config), state["fix_id"], state["verify_report"], workspace)
        errors = [] if report["passed"] else [f"{state['fix_id']}: not verified — {report['reason']}"]
        return {"verify_report": report, "errors": errors}

    node.__name__ = "record" if passed_expected else "mark_failed"
    return node


def _go_on_unless_failed(check: str | None, next_node: str):
    def route(state: FixState) -> str:
        report = state.get("verify_report") or {}
        if report.get("passed") is False or (check and check_failed(report, check)):
            return "mark_failed"
        return next_node

    return route


def _after_record(state: FixState) -> str:
    return "await_approval" if (state.get("verify_report") or {}).get("passed") else END


# --- approval and commit ---------------------------------------------------------------------- #
def _summary(state: FixState) -> dict:
    report = state.get("verify_report") or {}
    return {
        "passed": report.get("passed"),
        **{name: {"status": (report.get(name) or {}).get("status"), "reason": (report.get(name) or {}).get("reason")} for name in ("static", "tests", "runtime")},
        "retest_evidence_ids": report.get("retest_evidence_ids", []),
        "files": report.get("files", []),
    }


def _interrupt(value: dict, config: RunnableConfig):
    """``interrupt()`` finds its run through a context variable that Python 3.10 cannot carry into
    async tasks (LangGraph needs 3.11 for that); give it the node's own run config explicitly."""
    token = var_child_runnable_config.set(config)
    try:
        return interrupt(value)
    finally:
        var_child_runnable_config.reset(token)


def await_approval_node(state: FixState, config: RunnableConfig) -> dict:
    """Pause until a human approves a commit mode. Anything else pauses again."""
    request = {
        "fix_id": state["fix_id"],
        "finding_id": state["finding_id"],
        "verify_report": _summary(state),
        "modes": list(APPROVAL_MODES),
        "diff": state.get("diff"),
        "refused": None,
    }
    last_commit = (state.get("verify_report") or {}).get("commit")
    if last_commit and not last_commit.get("ok"):
        request["refused"] = last_commit.get("reason")
    while True:
        answer = _interrupt(request, config)
        mode = answer.get("mode") if isinstance(answer, dict) else None
        reason = unavailable_reason(mode) if isinstance(mode, str) else "no commit mode was given"
        if reason is None and mode in APPROVAL_MODES:
            break
        log.info("fix.approval_refused", fix_id=state["fix_id"], answer=str(answer)[:80], reason=reason)
        request = {**request, "refused": reason or f"{mode} cannot be approved"}
    log.info("fix.approved", fix_id=state["fix_id"], finding_id=state["finding_id"], mode=mode)
    return {"approved": True, "commit_mode": mode}


async def commit_node(state: FixState, config: RunnableConfig) -> dict:
    deps = get_deps(config)
    store = deps.store
    fix_id, mode = state["fix_id"], state["commit_mode"]
    subject = load_subject(store, fix_id)
    attempt = store.get_fix_attempt(fix_id)
    report = dict(state.get("verify_report") or {})

    if attempt.status != "verified":  # a commit only ever follows a passed verification
        reason = f"{fix_id} is {attempt.status}, not verified"
        log.warning("fix.commit_refused", fix_id=fix_id, mode=mode, reason=reason)
        return {"approved": False, "errors": [reason]}

    finding = store.get_finding(attempt.finding_id)
    result = commit_fix(
        mode,
        fix_id=fix_id,
        finding_id=finding.id,
        finding_type=finding.type,
        diff=attempt.diff,
        files=report.get("files", []),
        source_files=report.get("source_files", {}),
        workspace=Path(attempt.workspace_path) if attempt.workspace_path else None,
        source=subject.source if subject else None,
        from_clone=bool(subject and subject.scan.repo_url),
        patches_dir=Path(deps.data_dir) / "patches",
    )
    report["commit"] = result.as_dict()
    stored = json.loads(attempt.verify_report_json or "{}")
    stored["verify"] = {**stored.get("verify", {}), "commit": result.as_dict()}

    if not result.ok:  # back to the human, who can choose another mode
        store.update_fix_attempt(fix_id, verify_report=stored)
        return {"verify_report": report, "approved": False, "commit_mode": None, "errors": [f"{fix_id}: {mode} refused — {result.reason}"]}

    errors: list[str] = []
    evidence = report.get("retest_evidence_ids", [])
    try:
        transition(store, finding.id, "resolved", evidence_ids=evidence, actor="verifier", reason=f"fix {fix_id} verified and committed ({mode}) after approval")
        stored["resolution"] = {"resolved": True, "evidence_ids": evidence}
        log.info("fix.resolved", fix_id=fix_id, finding_id=finding.id, evidence=evidence)
    except IllegalTransition as exc:  # e.g. a finding that was never confirmed cannot be "resolved"
        stored["resolution"] = {"resolved": False, "reason": str(exc)}
        errors.append(f"{finding.id} committed but not resolved: {exc}")
        log.warning("fix.resolution_refused", fix_id=fix_id, finding_id=finding.id, reason=str(exc))
    store.update_fix_attempt(fix_id, status="committed", commit_mode=mode, verify_report=stored)
    return {"verify_report": report, "errors": errors}


def _after_commit(state: FixState) -> str:
    commit = (state.get("verify_report") or {}).get("commit") or {}
    return END if commit.get("ok") else "await_approval"


# --- graph ---------------------------------------------------------------------------------------- #
def build_fix_graph(checkpointer=None):
    g = StateGraph(FixState)
    g.add_node("make_copy", make_copy_node)
    g.add_node("apply_diff", apply_diff_node)
    for name in ("static", "tests", "runtime"):
        g.add_node(f"verify_{name}", _check_node(name))
    g.add_node("record", _record(True))
    g.add_node("mark_failed", _record(False))
    g.add_node("await_approval", await_approval_node)
    g.add_node("commit", commit_node)

    g.add_edge(START, "make_copy")
    g.add_conditional_edges("make_copy", _go_on_unless_failed(None, "apply_diff"), ["apply_diff", "mark_failed"])
    g.add_conditional_edges("apply_diff", _go_on_unless_failed(None, "verify_static"), ["verify_static", "mark_failed"])
    g.add_conditional_edges("verify_static", _go_on_unless_failed("static", "verify_tests"), ["verify_tests", "mark_failed"])
    g.add_conditional_edges("verify_tests", _go_on_unless_failed("tests", "verify_runtime"), ["verify_runtime", "mark_failed"])
    g.add_conditional_edges("verify_runtime", _go_on_unless_failed("runtime", "record"), ["record", "mark_failed"])
    g.add_conditional_edges("record", _after_record, ["await_approval", END])
    g.add_edge("mark_failed", END)
    g.add_edge("await_approval", "commit")
    g.add_conditional_edges("commit", _after_commit, ["await_approval", END])
    return g.compile(checkpointer=checkpointer)
