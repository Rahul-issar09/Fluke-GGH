"""AG09.1 — rules-first next-step policy (PHASES P11.1)."""

from __future__ import annotations

import ast
import dataclasses

import pytest

from _corr_helpers import seed_handlers, seed_runtime_bac, seed_static
from aegis.agent import rules
from aegis.agent.rules import FindingSummary, decide, default, summarize_finding, valid_steps
from aegis.agent.schemas import NextStep as N
from aegis.agent.schemas import NextStepDecision
from aegis.evidence.adapters.base import EvidenceDraft, FindingDraft
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.normalizer import ingest
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("AG09")

ROUTE = "GET /api/accounts/{id}"


def S(**kw) -> FindingSummary:
    """A summary of the demo's confirmed runtime finding, overridable per test."""
    base = dict(
        finding_id="F-0012",
        type="broken_access_control",
        state="confirmed",
        mode="correlated",
        route=ROUTE,
        evidence=(("E-0041", "http_exchange"),),
        runtime_proven=True,
    )
    base.update(kw)
    return FindingSummary(**base)


# --- the five rows of PHASES P11.1 -------------------------------------------------- #
def test_row1_confirmed_runtime_finding_without_a_function_asks_for_source_evidence():
    s = S()
    assert valid_steps(s) == [N.request_source_evidence]
    d = decide(s)
    assert (d.finding_id, d.next_step) == ("F-0012", N.request_source_evidence)
    assert d.target.route == ROUTE and d.target.function is None
    assert d.reason_evidence_ids == ["E-0041"]


def test_row1_does_not_apply_outside_correlated_mode():
    # a runtime-only scan has no source to look at: nothing left to request
    assert valid_steps(S(mode="runtime")) == [N.mark_sufficient]


def test_row2_route_and_function_but_no_correlation_score_asks_to_link_and_score():
    s = S(function="get_account", file="app/routes/accounts.py", correlation=None)
    assert valid_steps(s) == [N.link_and_score]
    assert decide(s).next_step == N.link_and_score
    assert decide(s).target.function == "get_account"


def test_row3_correlated_with_enough_evidence_is_sufficient():
    s = S(function="get_account", correlation=1.0)
    assert valid_steps(s) == [N.mark_sufficient]
    assert decide(s).next_step == N.mark_sufficient


def test_row4_tls_finding_without_a_crypto_asset_asks_for_a_crypto_scan():
    s = S(type="weak_tls", route=None, state="candidate", runtime_proven=False,
          evidence=(("E-0010", "tls_scan"),))
    assert valid_steps(s) == [N.request_crypto_scan]
    d = decide(s)
    assert d.next_step == N.request_crypto_scan and d.reason_evidence_ids == ["E-0010"]


def test_row4_needs_source_code_a_runtime_only_tls_finding_is_sufficient():
    # TNW-2: a runtime-only https scan has no code for the crypto engine to search
    s = S(type="weak_tls", route=None, state="candidate", mode="runtime", runtime_proven=False,
          evidence=(("E-0010", "tls_scan"),))
    assert valid_steps(s) == [N.mark_sufficient]


def test_row4_outranks_the_generic_runtime_row_even_when_a_tls_finding_has_a_route():
    s = S(type="weak_tls", route="GET /", state="candidate", runtime_proven=False,
          evidence=(("E-0010", "tls_scan"),))
    assert valid_steps(s) == [N.request_crypto_scan]  # not request_source_evidence


def test_row4_a_tls_finding_with_a_crypto_asset_needs_nothing_more():
    s = S(type="weak_tls", route=None, state="candidate", has_crypto_asset=True,
          evidence=(("E-0010", "tls_scan"), ("E-0011", "crypto_asset")))
    assert valid_steps(s) == [N.mark_sufficient]


def test_row5_static_finding_that_can_be_proven_at_runtime_asks_for_a_retest():
    s = S(route=None, file="app/routes/accounts.py", line=27, state="candidate", runtime_proven=False,
          handler_route="GET /api/accounts/{param}",
          evidence=(("E-0050", "code_location"), ("E-0051", "dataflow_path")))
    assert valid_steps(s) == [N.request_runtime_retest]
    d = decide(s)
    assert d.next_step == N.request_runtime_retest
    assert d.target.route == "GET /api/accounts/{param}"  # the endpoint to replay, from the graph
    assert d.reason_evidence_ids == ["E-0050", "E-0051"]  # the static evidence that motivates it


@pytest.mark.parametrize(
    "override",
    [
        dict(type="sqli"),                       # no runtime check exists for it
        dict(mode="code"),                       # no running app in a code-only scan
        dict(mode="runtime"),
        dict(runtime_proven=True),               # already proven
        dict(handler_route=None),                # no known endpoint to replay against
    ],
)
def test_row5_only_applies_when_a_runtime_check_is_possible(override):
    base = dict(route=None, file="a.py", state="candidate", runtime_proven=False,
                handler_route="GET /x", evidence=(("E-1", "code_location"),))
    assert valid_steps(S(**{**base, **override})) == [N.mark_sufficient]


# --- precedence and edges ------------------------------------------------------------- #
def test_a_resolved_finding_needs_nothing():
    assert valid_steps(S(state="resolved", function="f", correlation=1.0)) == [N.mark_sufficient]
    assert valid_steps(S(state="resolved")) == [N.mark_sufficient]  # even without a root cause


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.70, [N.mark_sufficient]),            # exactly at the threshold counts as linked
        (0.71, [N.mark_sufficient]),
        (0.69, [N.request_source_evidence]),    # just below it: still no accepted root cause
    ],
)
def test_the_correlation_threshold_is_inclusive(score, expected):
    # no function recorded, so the score alone decides between "done" and "go and look at the source"
    assert valid_steps(S(function=None, correlation=score), threshold=0.70) == expected


def test_the_threshold_is_a_parameter_not_a_constant():
    s = S(function=None, correlation=0.8)
    assert valid_steps(s, threshold=0.9) == [N.request_source_evidence]
    assert valid_steps(s, threshold=0.8) == [N.mark_sufficient]


def test_correlation_alone_is_not_enough_when_the_evidence_is_weak():
    # candidate: one signal only. Not "sufficient" via row 3; a runtime finding without a function still asks
    s = S(state="candidate", correlation=0.9, runtime_proven=False)
    assert valid_steps(s) == [N.request_source_evidence, N.mark_sufficient]


# --- a tool action is offered once; then the finding is exhausted ----------------------- #
@pytest.mark.parametrize(
    "summary",
    [
        S(attempted=("request_source_evidence",)),
        S(function="get_account", correlation=None, attempted=("link_and_score",)),
        S(type="weak_tls", route=None, state="candidate", evidence=(("E-1", "tls_scan"),),
          attempted=("request_crypto_scan",)),
        S(route=None, file="a.py", state="candidate", runtime_proven=False, handler_route="GET /x",
          evidence=(("E-1", "code_location"),), attempted=("request_runtime_retest",)),
    ],
)
def test_after_the_obvious_step_was_tried_the_finding_is_exhausted(summary):
    assert valid_steps(summary) == [N.mark_sufficient, N.escalate_to_human]
    assert decide(summary) is None                      # two valid steps: not an obvious case
    assert default(summary).next_step == N.escalate_to_human  # the cautious fallback


def test_escalation_is_never_offered_for_a_fresh_finding():
    for summary in (S(), S(function="f", correlation=None), S(correlation=1.0, function="f")):
        assert N.escalate_to_human not in valid_steps(summary)


# --- the cases left to the LLM ----------------------------------------------------------- #
def test_a_weaker_runtime_finding_without_a_root_cause_is_a_judgment_call():
    s = S(state="candidate", runtime_proven=False, evidence=(("E-0070", "http_exchange"),))
    assert valid_steps(s) == [N.request_source_evidence, N.mark_sufficient]
    assert decide(s) is None                                     # more than one valid step → LLM
    assert default(s).next_step == N.request_source_evidence     # the fallback keeps investigating
    assert valid_steps(S(state="corroborated", runtime_proven=False)) == [N.request_source_evidence, N.mark_sufficient]


def test_that_judgment_call_also_ends_once_the_source_lookup_was_tried():
    s = S(state="candidate", runtime_proven=False, attempted=("request_source_evidence",))
    assert valid_steps(s) == [N.mark_sufficient, N.escalate_to_human]


# --- default() ------------------------------------------------------------------------------ #
def test_default_agrees_with_decide_whenever_decide_answers():
    for s in (S(), S(function="f", correlation=1.0), S(function="f", correlation=None), S(mode="runtime")):
        assert decide(s) is not None and default(s) == decide(s)


def test_default_always_picks_a_valid_step():
    cases = [S(), S(state="candidate", runtime_proven=False), S(attempted=("request_source_evidence",)),
             S(state="resolved"), S(mode="code")]
    for s in cases:
        assert default(s).next_step in valid_steps(s)


# --- decisions are well-formed and honest about their evidence ---------------------------------- #
def test_decisions_must_cite_evidence_so_a_finding_without_any_cannot_be_decided():
    assert decide(S(evidence=())) is None
    assert default(S(evidence=(), attempted=("request_source_evidence",))) is None


def test_reasons_are_a_subset_of_the_findings_evidence_and_capped():
    many = tuple((f"E-{i:04d}", "http_exchange") for i in range(1, 10))
    d = decide(S(evidence=many))
    assert set(d.reason_evidence_ids) <= {e for e, _ in many} and len(d.reason_evidence_ids) == 5


def test_reasons_fall_back_to_whatever_evidence_exists():
    # row 1 prefers the runtime proof, but cites something rather than nothing
    d = decide(S(evidence=(("E-0099", "code_location"),)))
    assert d.reason_evidence_ids == ["E-0099"]


def test_every_decision_is_a_valid_schema_object():
    for s in (S(), S(function="f", correlation=1.0), S(state="resolved")):
        d = decide(s)
        assert NextStepDecision.model_validate(d.model_dump()) == d


def test_the_policy_is_deterministic():
    s = S(state="candidate", runtime_proven=False)
    assert [valid_steps(s) for _ in range(5)] == [valid_steps(s)] * 5
    assert default(s) == default(s)


# --- building the summary from a real store --------------------------------------------------------- #
@pytest.fixture
def scan(store):
    return store.add_scan(mode="correlated").id


def test_before_correlation_the_demo_bug_asks_for_source_evidence(store, scan):
    runtime = seed_runtime_bac(store, scan)
    finding = store.get_finding(runtime)
    s = summarize_finding(store, finding, scan_mode="correlated")

    assert (s.type, s.state, s.function, s.correlation) == ("broken_access_control", "confirmed", None, None)
    assert s.runtime_proven is True and s.runtime_origin and not s.is_static
    d = decide(s)
    assert d.next_step == N.request_source_evidence
    assert store.evidence_exists(d.reason_evidence_ids, runtime) == []  # cites its own, real evidence


def test_after_correlation_the_demo_bug_is_sufficient(store, scan):
    seed_handlers(store, scan)
    seed_static(store, scan)
    runtime = seed_runtime_bac(store, scan)
    correlate_scan(store, scan, load_handlers(store, scan))

    s = summarize_finding(store, store.get_finding(runtime), scan_mode="correlated")
    assert (s.function, s.correlation) == ("get_account", 1.0)
    assert decide(s).next_step == N.mark_sufficient


def test_a_static_finding_with_no_runtime_twin_is_offered_a_retest(store, scan):
    seed_handlers(store, scan)
    seed_static(store, scan)  # the owner-check finding, with no runtime finding to merge into
    handlers = load_handlers(store, scan)
    graph = build_graph(store, scan, handlers)
    (owner_check,) = [f for f in store.list_findings(scan) if f.type == "broken_access_control"]

    s = summarize_finding(store, owner_check, scan_mode="correlated", graph=graph)
    assert s.is_static and s.handler_route == "GET /api/accounts/{param}" and not s.runtime_proven
    d = decide(s)
    assert d.next_step == N.request_runtime_retest and d.target.route == "GET /api/accounts/{param}"
    assert store.evidence_exists(d.reason_evidence_ids, owner_check.id) == []


def test_a_static_finding_of_an_unprovable_type_is_just_sufficient(store, scan):
    seed_handlers(store, scan)
    seed_static(store, scan)
    graph = build_graph(store, scan, load_handlers(store, scan))
    (sqli,) = [f for f in store.list_findings(scan) if f.type == "sqli"]
    assert decide(summarize_finding(store, sqli, scan_mode="correlated", graph=graph)).next_step == N.mark_sufficient


def test_a_nuclei_candidate_is_not_runtime_proven_and_is_a_judgment_call(store, scan):
    nuclei = [{"template-id": "x", "info": {"name": "Missing headers", "severity": "info"},
               "matched-at": "http://demo-app:5000/health"}]
    (fid,) = ingest(store, scan, NucleiAdapter().parse(nuclei, scan))
    s = summarize_finding(store, store.get_finding(fid), scan_mode="correlated")
    assert s.runtime_proven is False  # an HTTP exchange that was never reproduced
    assert valid_steps(s) == [N.request_source_evidence, N.mark_sufficient]


def test_tls_finding_detected_by_type_or_by_evidence(store, scan):
    (fid,) = ingest(store, scan, [(FindingDraft(type="weak_tls", route="GET /", source="worker3.sslyze"),
                                   [EvidenceDraft(kind="tls_scan", tool="sslyze", payload={"protocol": "TLS1.0"})])])
    s = summarize_finding(store, store.get_finding(fid), scan_mode="correlated")
    assert s.is_tls and not s.has_crypto_asset
    assert decide(s).next_step == N.request_crypto_scan
    store.add_evidence(scan, "crypto_asset", "cbom", payload={"algo": "RSA"}, finding_id=fid)
    assert summarize_finding(store, store.get_finding(fid), scan_mode="correlated").has_crypto_asset


def test_attempted_steps_come_from_the_decision_history(store, scan):
    runtime = seed_runtime_bac(store, scan)

    def record(step: str, valid: bool = True):
        store.add_decision(scan, "investigate", "rule", finding_id=runtime, output={"next_step": step}, valid=valid)

    record("request_source_evidence", valid=False)  # rejected decisions never ran
    record("mark_sufficient")                       # not a tool step
    assert rules.attempted_steps(store, scan, runtime) == ()
    record("request_source_evidence")
    record("request_source_evidence")               # de-duplicated
    assert rules.attempted_steps(store, scan, runtime) == ("request_source_evidence",)

    s = summarize_finding(store, store.get_finding(runtime), scan_mode="correlated")
    assert valid_steps(s) == [N.mark_sufficient, N.escalate_to_human]
    assert default(s).next_step == N.escalate_to_human


def test_the_summary_carries_ids_and_fields_never_raw_evidence(store, scan):
    runtime = seed_runtime_bac(store, scan)  # its response excerpt contains the leaked record ("alice")
    s = summarize_finding(store, store.get_finding(runtime), scan_mode="correlated")
    flat = repr(dataclasses.asdict(s)).lower()
    for raw in ("alice", "response", "owner", "payload", "cookie"):
        assert raw not in flat
    assert all(eid.startswith("E-") for eid, _ in s.evidence)


# --- structural guarantee ------------------------------------------------------------------------ #
def test_the_rules_module_never_touches_the_llm_or_the_network():
    tree = ast.parse((ROOT / "aegis" / "agent" / "rules.py").read_text(encoding="utf-8"))
    banned = ("langchain", "aegis.agent.llm", "aegis.agent.prompt_guard", "httpx", "random", "requests", "ollama")
    for node in ast.walk(tree):
        names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
            [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
        for name in names:
            assert not any(name == b or name.startswith(b + ".") for b in banned), name
