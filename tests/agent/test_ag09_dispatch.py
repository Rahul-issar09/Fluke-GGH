"""AG09.2 — dispatch: each enum triggers exactly its mapped action, with targets from the store."""

from __future__ import annotations

import json

import pytest

from _corr_helpers import seed_handlers, seed_runtime_bac, seed_static
from _graph_helpers import make_run
from aegis.agent.nodes import runtime_subgraph
from aegis.agent.nodes import dispatch as dispatch_module
from aegis.agent.nodes.dispatch import dispatch, matched_handler
from aegis.agent.nodes.worker_stage import STEP_REGISTRY
from aegis.agent.schemas import NextStep as N
from aegis.agent.schemas import NextStepDecision, Target
from aegis.evidence.links import merged_ids
from aegis.evidence.models import Mode
from aegis.graph.correlator import load_handlers

pytestmark = pytest.mark.phase("AG09")

ALL_CODE = ["inventory", "extract_routes", "semgrep", "gitleaks", "osv", "trivy"]
ALL_CRYPTO = ["discover", "classical_rules", "quantum_rules", "build_cbom", "tls_scan"]


def pending(finding_id: str, step: N, evidence_id: str, **target) -> NextStepDecision:
    return NextStepDecision(finding_id=finding_id, next_step=step, target=Target(**target), reason_evidence_ids=[evidence_id])


@pytest.fixture
def world(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    state["mode"] = Mode.correlated
    return dict(store=store, scan=scan_id, state=state, config=config, deps=config["configurable"]["deps"])


@pytest.fixture
def spies(monkeypatch):
    """Record every code/crypto step that runs (and the narrowed target it was given)."""
    calls: list[tuple[str, dict]] = []

    def install(stage: str, names: list[str]):
        for name in names:
            async def step(state, config, _key=f"{stage}.{name}"):
                calls.append((_key, dict(state.get("target") or {})))
            monkeypatch.setitem(STEP_REGISTRY, f"{stage}.{name}", step)

    install("code", ALL_CODE)
    install("crypto", ALL_CRYPTO)
    return calls


def run(world, *decisions):
    world["state"]["pending_actions"] = list(decisions)
    return dispatch(world["state"], world["config"])


def dispatch_rows(world):
    return [d for d in world["store"].list_decisions(world["scan"]) if d.node == "dispatch"]


# --- request_source_evidence ------------------------------------------------------------------------------ #
async def test_source_evidence_extracts_routes_then_scans_the_matched_handlers_file(world, spies):
    seed_handlers(world["store"], world["scan"])
    runtime = seed_runtime_bac(world["store"], world["scan"])
    own = world["store"].evidence_for(runtime)[0].id

    await run(world, pending(runtime, N.request_source_evidence, own))

    assert spies == [
        ("code.extract_routes", {}),
        ("code.semgrep", {"file": "app/routes/accounts.py", "function": "get_account", "route": "GET /api/accounts/{id}"}),
    ]
    (row,) = dispatch_rows(world)
    out = json.loads(row.output_json)
    assert out["action"] == "request_source_evidence" and out["handler"] == "app/routes/accounts.py::get_account"
    assert out["steps_run"] == ["extract_routes", "semgrep"]


async def test_a_target_chosen_by_the_model_is_ignored(world, spies):
    seed_handlers(world["store"], world["scan"])
    runtime = seed_runtime_bac(world["store"], world["scan"])
    own = world["store"].evidence_for(runtime)[0].id
    evil = pending(runtime, N.request_source_evidence, own, route="GET /api/users/search", function="rm_rf")

    await run(world, evil)

    semgrep_target = dict(spies)["code.semgrep"]
    assert semgrep_target["file"] == "app/routes/accounts.py"       # the finding's handler, not users.py
    assert semgrep_target["function"] == "get_account" and semgrep_target["route"] == "GET /api/accounts/{id}"
    assert "rm_rf" not in json.dumps(spies)


async def test_when_no_handler_can_be_located_the_file_scan_is_not_run(world, spies):
    runtime = seed_runtime_bac(world["store"], world["scan"])  # no handler map, and the extractor finds nothing
    own = world["store"].evidence_for(runtime)[0].id

    await run(world, pending(runtime, N.request_source_evidence, own))

    assert [c[0] for c in spies] == ["code.extract_routes"]
    out = json.loads(dispatch_rows(world)[0].output_json)
    assert out["handler"] is None and out["note"] == "no handler located"


async def test_the_matched_handler_is_the_one_declaring_the_route(world):
    seed_handlers(world["store"], world["scan"])
    runtime = world["store"].get_finding(seed_runtime_bac(world["store"], world["scan"]))
    handlers = load_handlers(world["store"], world["scan"])
    assert matched_handler(handlers, runtime).function == "get_account"
    no_route = world["store"].add_finding(world["scan"], type="x", file="a.py")
    assert matched_handler(handlers, no_route) is None


# --- request_runtime_retest ----------------------------------------------------------------------------------- #
async def test_a_retest_proves_a_static_finding_and_merges_it_into_the_runtime_finding(world):
    store = world["store"]
    seed_handlers(store, world["scan"])
    seed_static(store, world["scan"])  # the owner-check finding, with no runtime twin yet
    (static,) = [f for f in store.list_findings(world["scan"]) if f.type == "broken_access_control"]
    own = store.evidence_for(static.id)[0].id

    out = await run(world, pending(static.id, N.request_runtime_retest, own))

    runtime = [f for f in store.list_findings(world["scan"]) if f.route == "GET /api/accounts/{id}"]
    assert len(runtime) == 1 and runtime[0].state.value == "confirmed"   # proven against the running app
    assert (runtime[0].function, runtime[0].correlation_score) == ("get_account", 1.0)
    assert merged_ids(store, world["scan"]) == {static.id}               # the static twin is absorbed
    assert out["open_findings"][0] == runtime[0].id                      # the new, proven finding leads the worklist
    assert static.id not in out["open_findings"]                         # …and its twin is not worked on twice
    row = json.loads(dispatch_rows(world)[0].output_json)
    assert row["check"] == "check_bola" and row["target"] == {"route": "GET /api/accounts/{param}"}
    assert row["steps_run"][-1] == "check_bola"


async def test_a_retest_against_a_fixed_app_proves_nothing(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, demo="patched")
    state["mode"] = Mode.correlated
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)
    (static,) = [f for f in store.list_findings(scan_id) if f.type == "broken_access_control"]
    state["pending_actions"] = [pending(static.id, N.request_runtime_retest, store.evidence_for(static.id)[0].id)]

    out = await dispatch(state, config)

    assert [f for f in store.list_findings(scan_id) if f.route] == []     # nothing was reproduced
    assert merged_ids(store, scan_id) == set() and static.id in out["open_findings"]
    assert out["errors"] == []


async def test_a_retest_is_narrowed_to_the_one_route(world, monkeypatch):
    seen: list[list[str]] = []

    async def fake_bola(client, base_url, model, sessions, **kw):
        seen.append([m.route.template for m in model])
        return []

    monkeypatch.setattr(runtime_subgraph, "check_bola", fake_bola)
    store = world["store"]
    seed_handlers(store, world["scan"])
    seed_static(store, world["scan"])
    (static,) = [f for f in store.list_findings(world["scan"]) if f.type == "broken_access_control"]

    await run(world, pending(static.id, N.request_runtime_retest, store.evidence_for(static.id)[0].id))
    assert seen == [["GET /api/accounts/{id}"]]

    # a route that is not the one we asked about is left alone
    seen.clear()
    world["state"]["pending_actions"] = []
    from aegis.agent.nodes.worker_stage import run_steps
    await run_steps("runtime", ["validate_target", "discover_routes", "authenticate", "build_request_model", "check_bola"],
                    world["state"], world["config"], target={"route": "GET /api/somewhere/else"})
    assert seen == []


async def test_a_retest_of_ssrf_runs_only_the_ssrf_check(world, monkeypatch):
    ran: list[str] = []

    async def spy(name):
        ran.append(name)

    async def fake_bola(*a, **k):
        ran.append("check_bola"); return []

    async def fake_ssrf(client, base_url, candidates, *a, **k):
        ran.append(f"check_ssrf:{[r.template for r, _ in candidates]}"); return []

    monkeypatch.setattr(runtime_subgraph, "check_bola", fake_bola)
    monkeypatch.setattr(runtime_subgraph, "check_ssrf", fake_ssrf)
    store = world["store"]
    finding = store.add_finding(world["scan"], type="ssrf", route="GET /api/fetch")
    ev = store.add_evidence(world["scan"], "oob_hit", "ssrf", payload={"param": "url"}, finding_id=finding.id)

    await run(world, pending(finding.id, N.request_runtime_retest, ev.id))

    assert ran == ["check_ssrf:['GET /api/fetch']"]


async def test_a_finding_that_cannot_be_replayed_is_reported_not_crashed(world):
    finding = world["store"].add_finding(world["scan"], type="sqli", file="app/routes/users.py", line=42)
    ev = world["store"].add_evidence(world["scan"], "code_location", "semgrep", payload={}, finding_id=finding.id)
    out = await run(world, pending(finding.id, N.request_runtime_retest, ev.id))
    assert out["errors"] == []
    assert "no runtime check or endpoint" in json.loads(dispatch_rows(world)[0].output_json)["note"]


# --- request_crypto_scan --------------------------------------------------------------------------------------------- #
async def test_a_crypto_scan_runs_the_engine_steps_on_the_findings_file(world, spies):
    store = world["store"]
    seed_static(store, world["scan"])
    (weak,) = [f for f in store.list_findings(world["scan"]) if f.type == "weak_crypto"]

    await run(world, pending(weak.id, N.request_crypto_scan, store.evidence_for(weak.id)[0].id))

    assert spies == [(f"crypto.{n}", {"file": "app/auth.py"}) for n in ["discover", "classical_rules", "quantum_rules", "build_cbom"]]


# --- link_and_score / terminal steps ---------------------------------------------------------------------------------- #
async def test_link_and_score_runs_no_tool_but_refreshes_the_analysis(world, spies):
    store = world["store"]
    runtime = seed_runtime_bac(store, world["scan"])
    store.update_finding_fields(runtime, risk=0.0)
    own = store.evidence_for(runtime)[0].id

    await run(world, pending(runtime, N.link_and_score, own))

    assert spies == []
    assert store.get_finding(runtime).risk == 0.792                      # re-scored deterministically
    assert json.loads(dispatch_rows(world)[0].output_json) == {"action": "link_and_score", "tool": False}


@pytest.mark.parametrize("step", [N.mark_sufficient, N.escalate_to_human])
async def test_terminal_steps_run_nothing(world, spies, step):
    runtime = seed_runtime_bac(world["store"], world["scan"])
    own = world["store"].evidence_for(runtime)[0].id
    await run(world, pending(runtime, step, own))
    assert spies == []
    assert json.loads(dispatch_rows(world)[0].output_json) == {"action": step.value, "tool": False}


# --- robustness ----------------------------------------------------------------------------------------------------------- #
async def test_a_failed_action_is_recorded_and_the_rest_still_run(world, monkeypatch, spies):
    seed_handlers(world["store"], world["scan"])
    store = world["store"]
    runtime = seed_runtime_bac(store, world["scan"])
    other = store.add_finding(world["scan"], type="weak_crypto", file="app/auth.py", line=14)
    e1 = store.evidence_for(runtime)[0].id
    e2 = store.add_evidence(world["scan"], "code_location", "semgrep", payload={}, finding_id=other.id).id

    original = dispatch_module.run_steps
    calls = {"n": 0}

    async def flaky(stage, steps, state, config, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("worker exploded")
        return await original(stage, steps, state, config, **kw)

    monkeypatch.setattr(dispatch_module, "run_steps", flaky)
    out = await run(world, pending(runtime, N.request_source_evidence, e1), pending(other.id, N.request_crypto_scan, e2))

    assert any("RuntimeError: worker exploded" in e for e in out["errors"])
    assert [c[0] for c in spies][:1] == ["crypto.discover"]               # the second action still ran
    assert len(dispatch_rows(world)) == 2                                  # both are in the audit trail


async def test_dispatch_advances_the_loop_and_clears_the_queue(world):
    runtime = seed_runtime_bac(world["store"], world["scan"])
    own = world["store"].evidence_for(runtime)[0].id
    world["state"]["iterations"] = 1
    out = await run(world, pending(runtime, N.link_and_score, own))
    assert out["pending_actions"] == [] and out["iterations"] == 2 and out["completed_stages"] == ["dispatch"]


async def test_dispatch_with_nothing_queued_just_refreshes(world):
    out = await run(world)
    assert out["pending_actions"] == [] and out["errors"] == [] and dispatch_rows(world) == []
