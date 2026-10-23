"""AG09.2 — validate_decision: everything a model answer can get wrong."""

from __future__ import annotations

import pytest

from _corr_helpers import seed_handlers, seed_runtime_bac, seed_static
from aegis.agent.rules import summarize_finding, valid_steps
from aegis.agent.schemas import NextStep as N
from aegis.agent.schemas import NextStepDecision, Target
from aegis.agent.validator import validate_decision
from aegis.graph.correlator import build_graph, load_handlers

pytestmark = pytest.mark.phase("AG09")


@pytest.fixture
def world(store):
    """A runtime finding that has already had its source lookup (so two steps are valid) + a second finding."""
    scan = store.add_scan(mode="correlated").id
    seed_handlers(store, scan)
    seed_static(store, scan)
    runtime = seed_runtime_bac(store, scan)
    other = store.add_finding(scan, type="sqli", file="app/routes/users.py", line=42)
    foreign = store.add_evidence(scan, "code_location", "semgrep", payload={"file": "x"}, finding_id=other.id)
    store.add_decision(scan, "investigate", "rule", finding_id=runtime, output={"next_step": "request_source_evidence"})

    graph = build_graph(store, scan, load_handlers(store, scan))
    summary = summarize_finding(store, store.get_finding(runtime), scan_mode="correlated", graph=graph)
    return dict(store=store, scan=scan, runtime=runtime, graph=graph, summary=summary,
                valid=valid_steps(summary), own=summary.evidence_ids[0], foreign=foreign.id)


def check(world, **overrides) -> list[str]:
    fields = dict(
        finding_id=world["runtime"],
        next_step=N.mark_sufficient,
        target=Target(),
        reason_evidence_ids=[world["own"]],
    )
    fields.update(overrides)
    return validate_decision(
        NextStepDecision(**fields), summary=world["summary"], valid=world["valid"],
        store=world["store"], graph=world["graph"],
    )


def test_the_setup_really_is_a_two_step_judgment_call(world):
    assert world["valid"] == [N.mark_sufficient, N.escalate_to_human]


def test_a_correct_answer_has_no_problems(world):
    assert check(world) == []
    assert check(world, next_step=N.escalate_to_human) == []


@pytest.mark.parametrize("step", [N.request_runtime_retest, N.request_crypto_scan, N.link_and_score, N.request_source_evidence])
def test_a_step_the_rules_did_not_allow_is_rejected(world, step):
    errors = check(world, next_step=step)
    assert len(errors) == 1 and f"'{step.value}' is not allowed" in errors[0]
    assert "mark_sufficient" in errors[0] and "escalate_to_human" in errors[0]  # tells the model what is allowed


def test_the_wrong_finding_is_rejected(world):
    errors = check(world, finding_id="F-0099")
    assert errors == [f"finding_id must be '{world['runtime']}', not 'F-0099'"]


def test_an_invented_evidence_id_is_rejected(world):
    assert check(world, reason_evidence_ids=["E-9999"]) == ["evidence E-9999 does not exist"]


def test_evidence_that_exists_but_belongs_to_another_finding_is_rejected(world):
    errors = check(world, reason_evidence_ids=[world["foreign"]])
    assert errors == [f"evidence {world['foreign']} does not belong to {world['runtime']}"]


def test_one_bad_id_among_good_ones_still_fails(world):
    assert check(world, reason_evidence_ids=[world["own"], "E-9999"]) == ["evidence E-9999 does not exist"]


def test_repeated_ids_are_reported_once(world):
    assert len(check(world, reason_evidence_ids=["E-9999", "E-9999"])) == 1


def test_scan_level_evidence_is_not_the_findings_own(world):
    scan_level = world["store"].add_evidence(world["scan"], "http_exchange", "httpx", payload={"route": "/openapi.json"})
    assert check(world, reason_evidence_ids=[scan_level.id]) == [
        f"evidence {scan_level.id} does not belong to {world['runtime']}"
    ]


def test_targets_must_exist(world):
    assert check(world, target=Target(route="GET /api/accounts/{id}", function="get_account")) == []  # its own
    assert check(world, target=Target(route="GET /api/users/search")) == []                            # a real endpoint
    assert check(world, target=Target(function="search_users")) == []                                  # a real function
    assert check(world, target=Target(route="GET /etc/passwd")) == ["target route 'GET /etc/passwd' is not a known endpoint"]
    assert check(world, target=Target(function="os.system")) == ["target function 'os.system' is not a known function"]


def test_without_a_graph_only_the_findings_own_target_is_accepted(world):
    kw = dict(summary=world["summary"], valid=world["valid"], store=world["store"], graph=None)
    ok = NextStepDecision(finding_id=world["runtime"], next_step=N.mark_sufficient,
                          target=Target(route=world["summary"].route), reason_evidence_ids=[world["own"]])
    assert validate_decision(ok, **kw) == []
    bad = ok.model_copy(update={"target": Target(route="GET /api/users/search")})
    assert validate_decision(bad, **kw)


def test_every_problem_is_reported_at_once(world):
    errors = check(world, finding_id="F-0099", next_step=N.link_and_score, reason_evidence_ids=["E-9999"],
                   target=Target(route="GET /nope"))
    assert len(errors) == 4  # so one corrective retry can fix them all


def test_messages_never_contain_evidence_content(world):
    errors = check(world, reason_evidence_ids=[world["foreign"], "E-9999"], target=Target(function="x"))
    assert not any("alice" in e or "payload" in e for e in errors)
