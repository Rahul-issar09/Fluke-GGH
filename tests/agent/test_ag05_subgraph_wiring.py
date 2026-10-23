"""AG05.3 — worker stage subgraphs: registry wiring, graceful skip, failure
handling."""

from __future__ import annotations

import pytest
from sqlmodel import select

from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.worker_stage import (
    STAGE_STEPS,
    STEP_REGISTRY,
    StageAbort,
    build_stage_graph,
    make_stage_node,
    register_step,
)
from aegis.evidence.models import Evidence, Mode

pytestmark = pytest.mark.phase("AG05")


def _stage_input(scan_id: str = "S-0001") -> dict:
    return {
        "scan_id": scan_id,
        "errors": [],
        "aborted": False,
        "steps_run": [],
        "steps_skipped": [],
    }


def _tool_errors(store, scan_id: str) -> list[Evidence]:
    with store.session() as s:
        return list(
            s.exec(select(Evidence).where(Evidence.scan_id == scan_id, Evidence.kind == "tool_error"))
        )


# --- design ---------------------------------------------------------------- #
def test_stage_step_lists():
    assert STAGE_STEPS["runtime"][:7] == [
        "tls_scan",
        "validate_target", "discover_routes", "authenticate", "crawl", "build_request_model", "check_bola",
    ]
    assert STAGE_STEPS["code"] == ["inventory", "extract_routes", "semgrep", "gitleaks", "trufflehog", "osv", "trivy"]
    # CBOM is built after the classical/quantum rules (PHASES P3.4, conflict C40)
    assert STAGE_STEPS["crypto"] == ["discover", "classical_rules", "quantum_rules", "tls_scan", "build_cbom"]


def test_register_step_rejects_unknown_step():
    with pytest.raises(ValueError):
        register_step("runtime", "not_a_step")
    with pytest.raises(ValueError):
        register_step("nope", "check_bola")


# --- graceful skip --------------------------------------------------------- #
@pytest.mark.parametrize("stage", ["runtime", "code", "crypto"])
async def test_unregistered_steps_are_skipped_cleanly(stage):
    sub = await build_stage_graph(stage, registry={}).ainvoke(_stage_input())
    assert sub["steps_run"] == []
    assert sub["steps_skipped"] == STAGE_STEPS[stage]
    assert sub["errors"] == []
    assert sub["aborted"] is False


async def test_registered_steps_run_in_stage_order_others_skipped():
    seen: list[str] = []

    def sync_step(state, config):
        seen.append("validate_target")

    async def async_step(state, config):
        seen.append("check_bola")

    registry = {"runtime.check_bola": async_step, "runtime.validate_target": sync_step}
    sub = await build_stage_graph("runtime", registry).ainvoke(_stage_input())
    assert seen == ["validate_target", "check_bola"]  # stage order, not registry order
    assert sub["steps_run"] == ["validate_target", "check_bola"]
    assert "authenticate" in sub["steps_skipped"]


# --- failures -------------------------------------------------------------- #
async def test_failing_step_records_tool_error_and_chain_continues(store, tmp_path):
    scan_id, _, config = make_run(store, tmp_path, Mode.code)
    ran: list[str] = []

    def boom(state, config):
        raise ValueError("semgrep exploded")

    def after(state, config):
        ran.append("gitleaks")

    registry = {"code.semgrep": boom, "code.gitleaks": after}
    sub = await build_stage_graph("code", registry).ainvoke(_stage_input(scan_id), config)

    assert ran == ["gitleaks"]  # next step still ran
    assert sub["steps_run"] == ["semgrep", "gitleaks"]
    assert any("code.semgrep" in e and "semgrep exploded" in e for e in sub["errors"])
    errors = _tool_errors(store, scan_id)
    assert len(errors) == 1 and errors[0].tool == "code.semgrep"


async def test_stage_abort_skips_remaining_steps(store, tmp_path):
    scan_id, _, config = make_run(store, tmp_path, Mode.runtime)
    called: list[str] = []

    def validate(state, config):
        raise StageAbort("target not reachable")

    def bola(state, config):  # pragma: no cover - must not run
        called.append("check_bola")

    registry = {"runtime.validate_target": validate, "runtime.check_bola": bola}
    sub = await build_stage_graph("runtime", registry).ainvoke(_stage_input(scan_id), config)

    assert called == []
    assert sub["aborted"] is True
    assert sub["steps_run"] == ["validate_target"]
    assert "check_bola" in sub["steps_skipped"]
    assert any("target not reachable" in e for e in sub["errors"])
    assert len(_tool_errors(store, scan_id)) == 1


async def test_failure_without_deps_still_does_not_crash():
    def boom(state, config):
        raise RuntimeError("x")

    sub = await build_stage_graph("code", {"code.semgrep": boom}).ainvoke(_stage_input())
    assert any("code.semgrep" in e for e in sub["errors"])


async def test_step_returned_errors_are_collected_and_unknown_keys_ignored():
    def step(state, config):
        return {"errors": ["soft problem"], "completed_stages": ["hacked"], "plan": ["x"]}

    sub = await build_stage_graph("code", {"code.inventory": step}).ainvoke(_stage_input())
    assert sub["errors"] == ["soft problem"]
    assert "completed_stages" not in sub  # worker steps cannot touch parent state


# --- parent node ----------------------------------------------------------- #
async def test_stage_node_marks_stage_completed_and_returns_errors(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)

    def boom(state, config):
        raise RuntimeError("fail")

    node = make_stage_node("code", {"code.gitleaks": boom})
    out = await node({**state, "mode": Mode.code}, config)
    assert out["completed_stages"] == ["code"]
    assert len(out["errors"]) == 1


# --- registry through the real graph --------------------------------------- #
async def test_registered_global_step_runs_inside_full_graph(store, tmp_path, monkeypatch):
    seen: list[str] = []

    async def check_bola(state, config):
        seen.append(state["scan_id"])

    monkeypatch.setitem(STEP_REGISTRY, "runtime.check_bola", check_bola)

    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    final = await build_aegis_graph().ainvoke(state, config)

    assert seen == [scan_id]
    assert final["completed_stages"][-1] == "finalize"
    assert final["errors"] == []


async def test_failing_worker_does_not_stop_the_scan(store, tmp_path, monkeypatch):
    def boom(state, config):
        raise RuntimeError("tool died")

    monkeypatch.setitem(STEP_REGISTRY, "code.semgrep", boom)
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    final = await build_aegis_graph().ainvoke(state, config)

    assert final["completed_stages"][-1] == "finalize"
    assert any("code.semgrep" in e for e in final["errors"])
    assert len(_tool_errors(store, scan_id)) == 1
