"""AG07 — route normalization (P9.1) and link scoring (P9.3)."""

from __future__ import annotations

import pytest

from aegis.graph.correlator import (
    CORRELATION_THRESHOLD,
    Dataflow,
    Handler,
    RuntimeTarget,
    link_score,
)
from aegis.graph.route_normalize import normalize_path, normalize_route, split_route

pytestmark = pytest.mark.phase("AG07")


# --- P9.1 route normalization ------------------------------------------------ #
@pytest.mark.parametrize(
    "method,path,expected",
    [
        # the table from PHASES P9.1
        ("GET", "/api/accounts/<int:id>", "GET /api/accounts/{param}"),
        ("get", "/api/accounts/12/", "GET /api/accounts/{param}"),
        ("GET", "/api/files/550e8400-e29b-41d4-a716-446655440000", "GET /api/files/{param}"),
        ("GET", "/api/accounts/{id}", "GET /api/accounts/{param}"),
        # more placeholder / identifier shapes
        ("GET", "/api/accounts/<id>", "GET /api/accounts/{param}"),
        ("GET", "/api/files/{file_path:path}", "GET /api/files/{param}"),
        ("GET", "/api/files/550E8400-E29B-41D4-A716-446655440000", "GET /api/files/{param}"),
        ("GET", "/api/users/7/orders/99", "GET /api/users/{param}/orders/{param}"),
        ("GET", "/files/{name}.{ext}", "GET /files/{param}.{param}"),
        # literals are kept exactly
        ("GET", "/api/v1/accounts", "GET /api/v1/accounts"),
        ("GET", "/api/v2/users/7", "GET /api/v2/users/{param}"),
        ("GET", "/api/12abc/x", "GET /api/12abc/x"),
        ("GET", "/API/Accounts", "GET /API/Accounts"),  # path case is significant
        # shape clean-up
        ("GET", "/api//accounts///", "GET /api/accounts"),
        ("GET", "/api/accounts?name=bob&x=1", "GET /api/accounts"),
        ("GET", "/api/accounts/12#frag", "GET /api/accounts/{param}"),
        ("GET", "http://demo-app:5000/api/accounts/12/", "GET /api/accounts/{param}"),
        ("  post ", "/login", "POST /login"),
        ("GET", "/", "GET /"),
        ("GET", "", "GET /"),
    ],
)
def test_normalize_route_table(method, path, expected):
    assert normalize_route(method, path) == expected


def test_code_and_runtime_spellings_converge():
    forms = ["/api/accounts/<int:id>", "/api/accounts/{account_id}", "/api/accounts/12", "/api/accounts/12/"]
    assert len({normalize_path(f) for f in forms}) == 1


@pytest.mark.parametrize(
    "route,expected",
    [("GET /api/accounts/{id}", ("GET", "/api/accounts/{id}")), ("post /x", ("POST", "/x")), ("  PUT   /a/b ", ("PUT", "/a/b"))],
)
def test_split_route(route, expected):
    assert split_route(route) == expected


@pytest.mark.parametrize("route", ["", "/api/accounts", "GET", "12 /x"])
def test_split_route_rejects_things_that_are_not_method_and_path(route):
    assert split_route(route) is None


# --- P9.3 link score ---------------------------------------------------------- #
def _handler(**kw) -> Handler:
    base = dict(
        path="/api/accounts/<int:id>",
        methods=("GET",),
        qualname="app/routes/accounts.py::get_account",
        function="get_account",
        file="app/routes/accounts.py",
        line=22,
        end_line=30,
    )
    base.update(kw)
    return Handler(**base)


_TARGET = RuntimeTarget("GET", "/api/accounts/{id}")
_FLOW = Dataflow(evidence_id="E-0057", file="app/routes/accounts.py", line=27, sink_name="db.execute", sink_line=27)


def test_demo_pair_scores_1_0_with_all_three_signals():
    score, signals = link_score(_TARGET, _handler(), [_FLOW])
    assert score == 1.0
    assert signals == {"route": True, "method": True, "dataflow": True, "dataflow_evidence": ["E-0057"]}


def test_route_and_method_without_dataflow_is_exactly_the_threshold():
    score, signals = link_score(_TARGET, _handler(), [])
    assert score == 0.7 and score >= CORRELATION_THRESHOLD
    assert signals == {"route": True, "method": True}


def test_route_only_is_0_5_and_below_the_threshold():
    score, signals = link_score(_TARGET, _handler(methods=("POST",)), [])
    assert score == 0.5 and score < CORRELATION_THRESHOLD
    assert signals == {"route": True}


def test_method_plus_dataflow_on_a_different_route_is_0_5():
    score, _ = link_score(_TARGET, _handler(path="/api/other"), [_FLOW])
    assert score == 0.5


def test_nothing_matching_scores_zero():
    assert link_score(_TARGET, _handler(path="/x", methods=("POST",)), []) == (0.0, {})


def test_method_comparison_ignores_case():
    assert link_score(RuntimeTarget("get", "/api/accounts/1"), _handler(methods=("get", "post")), [])[0] == 0.7


def test_concrete_runtime_path_matches_the_declared_template():
    assert link_score(RuntimeTarget("GET", "/api/accounts/12"), _handler(), [])[0] == 0.7


def test_dataflow_is_matched_by_qualname_or_by_span():
    by_name = Dataflow(evidence_id="E-1", function="app/routes/accounts.py::get_account")
    by_span = Dataflow(evidence_id="E-2", file="app/routes/accounts.py", line=29)
    outside = Dataflow(evidence_id="E-3", file="app/routes/accounts.py", line=31)
    other_file = Dataflow(evidence_id="E-4", file="app/routes/users.py", line=27)
    assert link_score(_TARGET, _handler(), [by_name])[1].get("dataflow_evidence") == ["E-1"]
    assert link_score(_TARGET, _handler(), [by_span])[1].get("dataflow_evidence") == ["E-2"]
    assert "dataflow" not in link_score(_TARGET, _handler(), [outside, other_file])[1]


def test_a_handler_without_end_line_owns_only_its_first_line():
    flow_in_body = Dataflow(evidence_id="E-1", file="app/routes/accounts.py", line=27)
    assert "dataflow" not in link_score(_TARGET, _handler(end_line=None), [flow_in_body])[1]
    on_first_line = Dataflow(evidence_id="E-2", file="app/routes/accounts.py", line=22)
    assert "dataflow" in link_score(_TARGET, _handler(end_line=None), [on_first_line])[1]


def test_score_is_deterministic_and_dataflow_ids_are_sorted():
    flows = [Dataflow(evidence_id="E-0090", file="app/routes/accounts.py", line=25), _FLOW]
    first = link_score(_TARGET, _handler(), flows)
    assert first == link_score(_TARGET, _handler(), list(reversed(flows)))
    assert first[1]["dataflow_evidence"] == ["E-0057", "E-0090"]
