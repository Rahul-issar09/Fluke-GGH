"""AG08 — the real ``score`` node in a full graph run, in every mode."""

from __future__ import annotations

import pytest

from _corr_helpers import seed_handlers, seed_static
from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.evidence.links import merged_ids
from aegis.evidence.models import Mode
from aegis.graph.security_graph import SecurityGraph, graph_path
from aegis.risk.engine import rank_findings

pytestmark = pytest.mark.phase("AG08")


def _types(store, ids):
    return [store.get_finding(i).type for i in ids]


def _ranked_ids(store, scan_id):
    """The scan's ranking. (``final["open_findings"]`` is the investigation worklist: empty once closed.)"""
    return [f.id for f in rank_findings(store, scan_id)]


async def test_mode3_ranks_the_demo_bug_first_and_hands_the_worklist_on(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)

    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == []
    assert final["completed_stages"].index("correlate") < final["completed_stages"].index("score")

    ranked = _ranked_ids(store, scan_id)  # what the investigation loop worked through, best first
    assert _types(store, ranked) == ["broken_access_control", "ssrf", "sqli", "weak_crypto"]
    top = store.get_finding(ranked[0])
    assert top.risk == 0.792 and top.route == "GET /api/accounts/{id}"
    assert [store.get_finding(i).risk for i in ranked] == [0.792, 0.464, 0.202, 0.106]
    assert set(ranked).isdisjoint(merged_ids(store, scan_id))  # the static twin is not a separate item


async def test_the_scored_graph_carries_the_final_risk(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)
    final = await build_aegis_graph().ainvoke(state, config)

    graph = SecurityGraph.load(graph_path(tmp_path / "data", scan_id))
    for finding_id in _ranked_ids(store, scan_id):
        assert graph.backend.node(finding_id)["risk"] == store.get_finding(finding_id).risk


async def test_runtime_only_scan_is_scored_too(store, tmp_path):
    """No ``correlate`` in Mode 1 — the score node must still build the graph it needs."""
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    final = await build_aegis_graph().ainvoke(state, config)

    assert "correlate" not in final["completed_stages"]
    ranked = _ranked_ids(store, scan_id)
    assert _types(store, ranked) == ["broken_access_control", "ssrf"]
    bac, ssrf = (store.get_finding(i) for i in ranked)
    assert bac.risk == 0.792  # route sensitivity + 1 hop to the endpoint, no handler map needed
    assert (ssrf.exposure, ssrf.criticality, ssrf.path_factor) == (0.6, 0.3, 0.0) and ssrf.risk == 0.464
    assert graph_path(tmp_path / "data", scan_id).is_file()


async def test_code_only_scan_gets_a_path_factor_from_the_handler_map(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)

    final = await build_aegis_graph().ainvoke(state, config)
    assert "correlate" not in final["completed_stages"]

    ranked = _ranked_ids(store, scan_id)
    by_type = {store.get_finding(i).type: store.get_finding(i) for i in ranked}
    owner_check = by_type["broken_access_control"]
    # static only: candidate, dataflow, behind the sensitive /api/accounts endpoint 2 hops away
    assert (owner_check.exploitability, owner_check.exposure, owner_check.criticality) == (0.5, 0.6, 0.7)
    assert owner_check.path_factor == 0.6
    assert owner_check.risk == round(0.9 * 0.4 * (1 + 0.5 + 0.6 + 0.7 + 0.6) / 5, 3) == 0.245
    assert ranked[0] == owner_check.id  # the top static risk comes first


async def test_scoring_does_not_change_state_or_evidence(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    final = await build_aegis_graph().ainvoke(state, config)
    for finding_id in _ranked_ids(store, scan_id):
        assert store.get_finding(finding_id).state.value == "confirmed"  # risk never moves state
    assert final["errors"] == []
