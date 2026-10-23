"""AG09.2 — the investigate ⇄ dispatch loop inside the real graph, and its audit trail."""

from __future__ import annotations

import json

import pytest

from _corr_helpers import seed_handlers, seed_static
from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.worker_stage import STEP_REGISTRY
from aegis.agent.prompt_guard import ALLOWED_KEYS
from aegis.evidence.links import merged_ids
from aegis.evidence.models import Mode
from aegis.risk.engine import rank_findings
from aegis.services.job_runner import open_checkpointer
from aegis.services.scan_service import get_audit

pytestmark = pytest.mark.phase("AG09")


def fake_code_worker(monkeypatch, store, scan_id):
    """Stand-ins for Worker 2's steps, behaving as the real ones will.

    The extractor misses on its first (full-stage) run — say the handler lives in a module the
    first pass could not parse — and finds the handlers when the loop asks again. Semgrep acts only
    when the loop narrows it to a file, and (like the real one, through SafetyController) leaves an
    audited tool call behind.
    """
    runs = {"extract": 0}

    async def extract_routes(state, config):
        runs["extract"] += 1
        if runs["extract"] > 1:
            seed_handlers(store, scan_id)

    async def semgrep(state, config):
        if not state.get("target"):
            return
        seed_static(store, scan_id)
        store.add_tool_call_log({"scan_id": scan_id, "tool": "semgrep", "target_host": None,
                                 "args_hash": "0123456789abcdef", "duration_ms": 12, "exit_code": 0,
                                 "blocked_reason": None})

    monkeypatch.setitem(STEP_REGISTRY, "code.extract_routes", extract_routes)
    monkeypatch.setitem(STEP_REGISTRY, "code.semgrep", semgrep)


def chain(audit: dict, finding_id: str) -> list[tuple]:
    """(node, source, step-or-action) for one finding's *investigation*, in order."""
    out = []
    for d in audit["decisions"]:
        if d["finding_id"] != finding_id or not d["valid"] or d["node"] not in ("investigate", "dispatch"):
            continue
        step = d["output"].get("next_step") or d["output"].get("action")
        out.append((d["node"], d["source"], step))
    return out


def bac(store, scan_id):
    return next(f for f in store.list_findings(scan_id) if f.type == "broken_access_control" and f.route)


# --- the AG09 acceptance flow ------------------------------------------------------------------------------ #
async def test_mode3_audit_shows_source_evidence_then_semgrep_then_correlation_then_sufficient(store, tmp_path, monkeypatch):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    fake_code_worker(monkeypatch, store, scan_id)
    deps = config["configurable"]["deps"]

    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == []
    order = final["completed_stages"]
    assert order[order.index("score"):order.index("explain")] == ["score", "investigate", "dispatch", "investigate"]
    assert final["iterations"] == 1 and final["open_findings"] == [] and final["pending_actions"] == []

    # the runtime finding is now tied to its root cause in code
    f = bac(store, scan_id)
    assert (f.function, f.line, f.correlation_score, f.risk) == ("get_account", 27, 1.0, 0.792)
    assert len(merged_ids(store, scan_id)) == 1  # the Semgrep twin was absorbed

    audit = get_audit(store, scan_id)
    assert chain(audit, f.id) == [
        ("investigate", "rule", "request_source_evidence"),
        ("dispatch", "rule", "request_source_evidence"),
        ("investigate", "rule", "mark_sufficient"),
    ]
    assert any(c["tool"] == "semgrep" for c in audit["tool_calls"])             # the Semgrep call is in the trail
    assert ("candidate", "confirmed") in {(t["from"], t["to"]) for t in audit["transitions"] if t["finding_id"] == f.id}
    dispatch_row = next(d for d in audit["decisions"] if d["node"] == "dispatch" and d["finding_id"] == f.id)
    assert dispatch_row["output"]["handler"] == "app/routes/accounts.py::get_account"
    assert dispatch_row["output"]["steps_run"] == ["extract_routes", "semgrep"]
    assert all(d["valid"] for d in audit["decisions"])

    # every investigation step was an obvious case, so the model was never asked to decide one
    # (it is still asked to write the explanations afterwards)
    assert deps.llm.investigation_payloads() == []
    assert len(deps.llm.explanation_payloads()) == len(store.list_findings(scan_id)) - 1  # the merged twin has none


async def test_the_same_flow_survives_a_checkpointer(store, tmp_path, monkeypatch):
    """Pending actions are pydantic objects in graph state; they must serialize cleanly."""
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    fake_code_worker(monkeypatch, store, scan_id)
    config["configurable"]["thread_id"] = scan_id

    async with open_checkpointer(tmp_path / "cp" / "checkpoints.db") as saver:
        final = await build_aegis_graph(saver).ainvoke(state, config)
        snapshot = await build_aegis_graph(saver).aget_state(config)

    assert final["errors"] == [] and bac(store, scan_id).correlation_score == 1.0
    assert snapshot.next == ()  # ran to the end


# --- termination ----------------------------------------------------------------------------------------------- #
async def test_the_loop_terminates_when_actions_cannot_make_progress(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)  # no code worker: source evidence can never help
    state["max_iterations"] = 10  # a generous cap must not mean 10 rounds
    deps = config["configurable"]["deps"]

    final = await build_aegis_graph().ainvoke(state, config)

    order = final["completed_stages"]
    assert order.count("dispatch") == 1 and order.count("investigate") == 2
    assert final["iterations"] == 1 and final["errors"] == []
    # round 2 found both runtime findings exhausted -> the model chose among [mark_sufficient, escalate_to_human]
    consulted = [d for d in get_audit(store, scan_id)["decisions"] if d["node"] == "investigate" and d["source"] == "llm"]
    assert len(consulted) == 2 and {d["output"]["next_step"] for d in consulted} == {"mark_sufficient"}
    assert len(deps.llm.investigation_payloads()) == 2


async def test_the_iteration_cap_is_enforced(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    state["max_iterations"] = 1

    final = await build_aegis_graph().ainvoke(state, config)

    order = final["completed_stages"]
    assert order[order.index("investigate"):order.index("explain")] == ["investigate", "dispatch"]  # no second pass
    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    closed = [d for d in get_audit(store, scan_id)["decisions"] if d["node"] == "investigate" and d["output"].get("next_step") == "mark_sufficient"]
    assert closed == []  # capped before anything was closed: the investigation simply ran out of rounds


# --- a static finding that needs proof --------------------------------------------------------------------------- #
async def test_a_static_finding_is_retested_and_stays_unproven_against_a_fixed_app(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, demo="patched")
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)

    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == []
    static = next(f for f in store.list_findings(scan_id) if f.type == "broken_access_control")
    assert [f for f in store.list_findings(scan_id) if f.route] == []        # the fixed app proved nothing
    audit = get_audit(store, scan_id)
    assert chain(audit, static.id) == [
        ("investigate", "rule", "request_runtime_retest"),
        ("dispatch", "rule", "request_runtime_retest"),
        ("investigate", "llm", "mark_sufficient"),                            # exhausted -> the model's call
    ]
    retest = next(d for d in audit["decisions"] if d["node"] == "dispatch")
    assert retest["output"]["check"] == "check_bola" and retest["output"]["target"] == {"route": "GET /api/accounts/{param}"}


# --- what the model is allowed to see across the whole loop ----------------------------------------------------------- #
async def test_the_model_never_sees_raw_evidence_anywhere_in_the_loop(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    final = await build_aegis_graph().ainvoke(state, config)
    llm = config["configurable"]["deps"].llm
    assert llm.payloads, "the scenario should have consulted the model"

    for payload in llm.payloads:
        assert set(payload) <= ALLOWED_KEYS
        assert payload["finding_id"].startswith("F-") and payload["evidence_ids"]  # only IDs it may cite
    seen = json.dumps([[m.content for m in call] for call in llm.calls])
    for raw in ("alice", "account_number", "session=", "Cookie", "response_excerpt", "payload_json"):
        assert raw not in seen
    assert final["errors"] == []
