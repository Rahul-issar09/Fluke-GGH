"""AG08 — risk factor calculators (P10.2), one rule at a time."""

from __future__ import annotations

import json

import pytest

from aegis.evidence.models import Evidence, Finding, FindingState
from aegis.graph.security_graph import SecurityGraph
from aegis.risk import factors

pytestmark = pytest.mark.phase("AG08")

SENSITIVE = ("/api/accounts", "/admin")


def finding(**kw) -> Finding:
    base = dict(id="F-0001", scan_id="S-0001", type="broken_access_control", state=FindingState.candidate)
    base.update(kw)
    return Finding(**base)


def ev(kind: str, tool: str = "t", **payload) -> Evidence:
    return Evidence(id="E-0001", scan_id="S-0001", kind=kind, tool=tool, payload_json=json.dumps(payload))


# --- confidence ---------------------------------------------------------------- #
@pytest.mark.parametrize(
    "state,expected",
    [("candidate", 0.4), ("corroborated", 0.7), ("confirmed", 1.0), ("resolved", 1.0),
     (FindingState.confirmed, 1.0)],
)
def test_confidence_follows_the_evidence_state(state, expected):
    assert factors.confidence(state) == expected


# --- exploitability ------------------------------------------------------------- #
@pytest.mark.parametrize("kind", ["http_exchange", "oob_hit", "retest"])
def test_a_confirmed_finding_with_runtime_proof_is_runtime_proven(kind):
    assert factors.exploitability(finding(state=FindingState.confirmed), [ev(kind)]) == 1.0


def test_a_resolved_finding_keeps_its_proven_exploitability():
    assert factors.exploitability(finding(state=FindingState.resolved), [ev("retest")]) == 1.0


def test_a_candidate_with_an_http_exchange_is_not_runtime_proven():
    # a Nuclei / Schemathesis match: the evidence is an HTTP exchange, but nothing was reproduced
    assert factors.exploitability(finding(state=FindingState.candidate), [ev("http_exchange", "nuclei")]) == 0.3
    assert factors.exploitability(finding(state=FindingState.corroborated), [ev("http_exchange")]) == 0.3


def test_a_dataflow_to_a_sink_is_0_5():
    assert factors.exploitability(finding(), [ev("code_location"), ev("dataflow_path")]) == 0.5
    # proven beats dataflow when both exist (the correlated demo bug)
    assert factors.exploitability(
        finding(state=FindingState.confirmed), [ev("http_exchange"), ev("dataflow_path")]
    ) == 1.0


def test_pattern_only_is_0_3():
    assert factors.exploitability(finding(), [ev("code_location")]) == 0.3
    assert factors.exploitability(finding(), []) == 0.3


def test_only_a_verified_secret_counts_as_proven():
    secret = finding(type="secret", state=FindingState.confirmed)
    assert factors.exploitability(secret, [ev("secret", verified=True)]) == 1.0
    assert factors.exploitability(finding(type="secret"), [ev("secret", verified=False)]) == 0.3


# --- exposure -------------------------------------------------------------------- #
def _graph_with_endpoint_handler() -> SecurityGraph:
    g = SecurityGraph()
    g.add_endpoint("GET /api/x/{param}")
    g.add_function("a.py::f", name="f", file="a.py")
    g.handled_by("GET /api/x/{param}", "a.py::f", score=1.0, signals={}, origin="static")
    g.add_finding("F-0001")
    return g


def test_reproduced_without_credentials_is_fully_exposed():
    assert factors.exposure(finding(), [ev("http_exchange", auth_context="unauthenticated")]) == 1.0


def test_reproduced_with_credentials_is_0_6():
    assert factors.exposure(finding(), [ev("http_exchange", auth_context="authenticated")]) == 0.6


def test_the_most_exposed_observation_wins():
    both = [ev("http_exchange", auth_context="authenticated"), ev("http_exchange", auth_context="unauthenticated")]
    assert factors.exposure(finding(), both) == 1.0


def test_a_static_finding_on_an_endpoint_handler_is_assumed_authenticated():
    g = _graph_with_endpoint_handler()
    g.on("F-0001", "a.py::f")
    assert factors.exposure(finding(), [ev("code_location")], g) == 0.6


def test_a_finding_on_an_endpoint_node_is_0_6():
    g = _graph_with_endpoint_handler()
    g.on("F-0001", "GET /api/x/{param}")
    assert factors.exposure(finding(), [], g) == 0.6


def test_a_finding_not_reachable_from_any_endpoint_is_internal():
    g = _graph_with_endpoint_handler()  # F-0001 attached to nothing
    assert factors.exposure(finding(), [ev("code_location")], g) == 0.2
    assert factors.exposure(finding(), [ev("code_location")], None) == 0.2


# --- criticality ------------------------------------------------------------------ #
@pytest.mark.parametrize(
    "route,expected",
    [
        ("GET /api/accounts/{id}", True),
        ("GET /api/accounts/12", True),
        ("GET /api/accounts", True),
        ("/api/accounts/{param}", True),
        ("GET /admin/users", True),
        ("GET /admin", True),
        ("GET /api/accountsx", False),  # a path-segment boundary, not a string prefix
        ("GET /api/account", False),
        ("GET /api/fetch", False),
    ],
)
def test_sensitive_route_matching_is_segment_aware(route, expected):
    assert factors.is_sensitive_route(route, SENSITIVE) is expected


def test_sensitive_route_gives_full_criticality():
    assert factors.criticality(finding(route="GET /api/accounts/{id}"), SENSITIVE) == 1.0


@pytest.mark.parametrize(
    "kw,expected",
    [
        (dict(file="app/routes/users.py"), 0.7),                  # user data
        (dict(file="app/auth.py"), 0.7),                          # authentication code
        (dict(function="process_payment"), 0.7),
        (dict(route="GET /api/billing/invoices"), 0.7),
        (dict(file="app/config.py"), 0.3),
        (dict(route="GET /api/fetch", file="app/routes/fetch.py", function="fetch"), 0.3),
        (dict(type="secret", file="app/config.py"), 0.8),         # a credential unlocks everything behind it
        (dict(type="secret", file="app/routes/users.py"), 0.8),
        (dict(), 0.3),
    ],
)
def test_criticality_heuristics(kw, expected):
    assert factors.criticality(finding(**kw), SENSITIVE) == expected


def test_a_sensitive_route_outranks_every_heuristic():
    assert factors.criticality(finding(type="secret", route="GET /admin/x"), SENSITIVE) == 1.0


# --- path factor ------------------------------------------------------------------ #
def _chain_graph() -> SecurityGraph:
    g = SecurityGraph()
    g.add_endpoint("GET /api/accounts/{param}")  # sensitive
    g.add_endpoint("GET /api/other/{param}")
    g.add_function("a.py::f", name="f", file="a.py")
    g.add_function("b.py::g", name="g", file="b.py")
    g.add_sink("a.py", 5, "db.execute")
    g.handled_by("GET /api/accounts/{param}", "b.py::g", score=1.0, signals={}, origin="static")
    g.handled_by("GET /api/other/{param}", "a.py::f", score=1.0, signals={}, origin="static")
    g.handled_by("GET /api/other/{param}", "b.py::g", score=1.0, signals={}, origin="static")  # shared function
    g.flows_to("a.py::f", "a.py:5::db.execute", "E-1")
    for fid in ("F-0001", "F-0002", "F-0003", "F-0004"):
        g.add_finding(fid)
    return g


def test_path_factor_decays_with_distance():
    g = _chain_graph()
    g.on("F-0001", "GET /api/accounts/{param}")     # 1 hop
    g.on("F-0002", "b.py::g")                        # g <- accounts endpoint: 2 hops
    g.on("F-0003", "GET /api/other/{param}")        # other -> g <- accounts: 3 hops
    g.on("F-0004", "a.py::f")                        # f <- other -> g <- accounts: 4 hops (too far)
    assert factors.path_factor("F-0001", g, SENSITIVE) == 0.8
    assert factors.path_factor("F-0002", g, SENSITIVE) == 0.6
    assert factors.path_factor("F-0003", g, SENSITIVE) == 0.4
    assert factors.path_factor("F-0004", g, SENSITIVE) == 0.0


def test_the_nearest_sensitive_node_counts():
    g = _chain_graph()
    g.on("F-0001", "GET /api/accounts/{param}")
    g.on("F-0001", "GET /api/other/{param}")
    assert factors.path_factor("F-0001", g, SENSITIVE) == 0.8


def test_no_graph_or_unknown_finding_means_no_path():
    assert factors.path_factor("F-0001", None, SENSITIVE) == 0.0
    assert factors.path_factor("F-9999", _chain_graph(), SENSITIVE) == 0.0


def test_no_sensitive_routes_configured_means_no_path():
    g = _chain_graph()
    g.on("F-0001", "GET /api/accounts/{param}")
    assert factors.path_factor("F-0001", g, ()) == 0.0
