"""AG10.1 — validate_claims: a claim survives only if all of its evidence is real and the finding's."""

from __future__ import annotations

import pytest

from aegis.agent.schemas import Claim
from aegis.agent.validator import MAX_CLAIMS_PER_FIELD, correlated_evidence_ids, validate_claims
from aegis.graph.security_graph import SecurityGraph

pytestmark = pytest.mark.phase("AG10")


@pytest.fixture
def world(store):
    scan = store.add_scan(mode="code").id
    mine = store.add_finding(scan, type="broken_access_control")
    other = store.add_finding(scan, type="sqli")
    own = store.add_evidence(scan, "http_exchange", "bola", payload={}, finding_id=mine.id)
    own2 = store.add_evidence(scan, "dataflow_path", "semgrep", payload={}, finding_id=mine.id)
    foreign = store.add_evidence(scan, "code_location", "semgrep", payload={}, finding_id=other.id)
    return dict(store=store, scan=scan, finding=mine.id, own=own.id, own2=own2.id, foreign=foreign.id)


def claim(field="what", text="A sentence.", *ids) -> Claim:
    return Claim(field=field, text=text, evidence_ids=list(ids) or ["E-0001"])


def run(w, claims, **kw):
    allowed = correlated_evidence_ids(w["store"], None, w["finding"])
    return validate_claims(claims, finding_id=w["finding"], allowed_evidence_ids=allowed, store=w["store"], **kw)


def test_a_claim_citing_the_findings_own_evidence_is_kept(world):
    (v,) = run(world, [claim("what", "It is wrong.", world["own"], world["own2"])])
    assert v.kept and v.reasons == ()


def test_a_claim_citing_evidence_that_does_not_exist_is_dropped(world):
    (v,) = run(world, [claim("what", "x", "E-9999")])
    assert not v.kept and v.reasons == ("evidence E-9999 does not exist",)


def test_a_claim_citing_another_findings_evidence_is_dropped(world):
    (v,) = run(world, [claim("impact", "x", world["foreign"])])
    assert not v.kept and v.reasons == (f"evidence {world['foreign']} does not belong to {world['finding']}",)


def test_every_cited_id_must_be_valid_not_just_one(world):
    (v,) = run(world, [claim("what", "x", world["own"], "E-9999")])
    assert not v.kept


def test_the_fix_field_is_not_written_here(world):
    (v,) = run(world, [claim("fix", "Add an owner check.", world["own"])])
    assert not v.kept and v.reasons == ("field 'fix' is not written by explain",)


def test_empty_or_control_character_text_is_handled(world):
    kept, empty = run(world, [claim("what", "ok\x00 text\x07 here \n", world["own"]), claim("what", " \x00 \t ", world["own"])])
    assert kept.kept and kept.claim.text == "ok text here"       # control characters removed, text trimmed
    assert not empty.kept and empty.reasons == ("claim text is empty",)


def test_a_repeated_claim_is_dropped(world):
    a, b = run(world, [claim("what", "Same.", world["own"]), claim("what", "Same.", world["own2"])])
    assert a.kept and not b.kept and b.reasons == ("duplicate claim",)


def test_there_is_a_cap_per_field(world):
    claims = [claim("exploit", f"Step {i}.", world["own"]) for i in range(MAX_CLAIMS_PER_FIELD + 2)]
    verdicts = run(world, claims)
    assert [v.kept for v in verdicts] == [True] * MAX_CLAIMS_PER_FIELD + [False, False]
    assert "more than 3 'exploit' claims" in verdicts[-1].reasons[0]


def test_verdicts_keep_the_order_and_the_other_fields_unaffected(world):
    verdicts = run(world, [claim("what", "a", "E-9999"), claim("impact", "b", world["own"]), claim("exploit", "c", world["own"])])
    assert [v.kept for v in verdicts] == [False, True, True]
    assert [v.claim.field for v in verdicts] == ["what", "impact", "exploit"]


def test_reasons_never_include_evidence_content(world):
    world["store"].add_evidence(world["scan"], "http_exchange", "bola", payload={"response": "SECRET RECORD"}, finding_id=None)
    verdicts = run(world, [claim("what", "x", "E-9999", world["foreign"])])
    assert "SECRET" not in " ".join(verdicts[0].reasons)


# --- correlated neighbours ------------------------------------------------------------------- #
def _graph_with_neighbour_evidence(world, neighbour_evidence: str) -> SecurityGraph:
    g = SecurityGraph()
    g.add_function("a.py::f", name="f", file="a.py")
    g.add_sink("a.py", 5, "db.execute")
    g.flows_to("a.py::f", "a.py:5::db.execute", neighbour_evidence)
    g.add_finding(world["finding"])
    g.on(world["finding"], "a.py::f")
    return g


def test_evidence_on_the_handlers_graph_edges_is_citable_by_its_findings(world):
    graph = _graph_with_neighbour_evidence(world, world["foreign"])  # recorded on the function it sits in
    allowed = correlated_evidence_ids(world["store"], graph, world["finding"])
    assert allowed == {world["own"], world["own2"], world["foreign"]}
    (v,) = validate_claims([claim("exploit", "The flow reaches a sink.", world["foreign"])],
                           finding_id=world["finding"], allowed_evidence_ids=allowed, store=world["store"])
    assert v.kept


def test_evidence_not_connected_to_the_finding_stays_uncitable(world):
    other_scan_ev = world["store"].add_evidence(world["scan"], "code_location", "semgrep", payload={}, finding_id=None)
    graph = _graph_with_neighbour_evidence(world, world["foreign"])
    allowed = correlated_evidence_ids(world["store"], graph, world["finding"])
    assert other_scan_ev.id not in allowed


def test_without_a_graph_only_own_evidence_counts(world):
    assert correlated_evidence_ids(world["store"], None, world["finding"]) == {world["own"], world["own2"]}
    assert correlated_evidence_ids(world["store"], SecurityGraph(), world["finding"]) == {world["own"], world["own2"]}
