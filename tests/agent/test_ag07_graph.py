"""AG07 — security graph (P9.2), persistence + attack paths (P9.5), and the
real ``correlate`` node inside a Mode 3 run."""

from __future__ import annotations

import ast
import json

import pytest

from _corr_helpers import (
    by_type,
    handler_rows,
    seed_handlers,
    seed_runtime_bac,
    seed_static,
)
from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.evidence.models import Mode
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers
from aegis.graph.security_graph import (
    EDGE_KINDS,
    NODE_TYPES,
    NetworkXBackend,
    SecurityGraph,
    graph_path,
)
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("AG07")


def _correlated_scan(store):
    scan_id = store.add_scan(mode="correlated").id
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)
    runtime = seed_runtime_bac(store, scan_id)
    handlers = load_handlers(store, scan_id)
    correlate_scan(store, scan_id, handlers)
    return scan_id, runtime, handlers


# --- P9.2 structure ----------------------------------------------------------- #
def test_demo_graph_has_endpoint_function_sink_chain(store):
    scan_id, runtime, handlers = _correlated_scan(store)
    graph = build_graph(store, scan_id, handlers)
    b = graph.backend

    endpoint = "GET /api/accounts/{param}"  # the code's <int:id> and runtime's {id} are one node
    function = "app/routes/accounts.py::get_account"
    sink = "app/routes/accounts.py:27::db.execute"
    assert b.node(endpoint)["type"] == "endpoint"
    assert b.node(function)["type"] == "function" and b.node(function)["label"] == "get_account"
    assert b.node(sink)["type"] == "sink"
    assert b.successors(endpoint, "HANDLED_BY") == [function]
    assert b.successors(function, "FLOWS_TO") == [sink]
    assert set(b.successors(runtime, "ON")) == {endpoint, function}


def test_correlated_edge_carries_the_score_and_signals(store):
    scan_id, runtime, handlers = _correlated_scan(store)
    graph = build_graph(store, scan_id, handlers)
    edges = {(s, d): a for s, d, k, a in graph.backend.edges("HANDLED_BY")}
    attrs = edges[("GET /api/accounts/{param}", "app/routes/accounts.py::get_account")]
    assert attrs["score"] == 1.0 and attrs["origin"] == "correlated"
    assert attrs["signals"]["route"] and attrs["signals"]["method"] and attrs["signals"]["dataflow"]
    # a handler no runtime finding touched keeps an honest, static edge
    static = {(s, d): a for s, d, k, a in graph.backend.edges("HANDLED_BY")}[
        ("GET /api/users/search", "app/routes/users.py::search_users")
    ]
    assert static["origin"] == "static" and static["signals"] == {"static_route_map": True}


def test_merged_duplicates_are_not_drawn_but_recorded_on_the_primary(store):
    scan_id, runtime, handlers = _correlated_scan(store)
    graph = build_graph(store, scan_id, handlers)
    finding_nodes = {k for k, _ in graph.backend.nodes("finding")}
    (dup,) = [f.id for f in by_type(store, scan_id, "broken_access_control") if f.id != runtime]
    assert runtime in finding_nodes and dup not in finding_nodes
    assert graph.backend.node(runtime)["merged"] == [dup]


def test_static_findings_attach_to_the_handler_that_contains_them(store):
    scan_id, _, handlers = _correlated_scan(store)
    graph = build_graph(store, scan_id, handlers)
    (sqli,) = by_type(store, scan_id, "sqli")
    assert graph.backend.successors(sqli.id, "ON") == ["app/routes/users.py::search_users"]
    (secret_hash,) = by_type(store, scan_id, "weak_crypto")  # auth.py is not a handler
    assert graph.backend.successors(secret_hash.id, "ON") == []


def test_crypto_assets_and_libraries_hang_off_the_functions_that_use_them(store):
    scan_id, _, handlers = _correlated_scan(store)
    store.add_evidence(scan_id, "crypto_asset", "cbom", payload={"algo": "MD5", "file": "app/routes/accounts.py", "line": 25})
    store.add_evidence(scan_id, "dependency", "osv", payload={"package": "requests", "version": "2.19.0"})
    graph = build_graph(store, scan_id, handlers)
    asset = "algo:MD5@app/routes/accounts.py:25"
    assert graph.backend.node(asset)["type"] == "crypto_asset"
    assert graph.backend.successors("app/routes/accounts.py::get_account", "USES") == [asset]
    assert graph.backend.node("pkg:pypi/requests@2.19.0")["type"] == "library"


def test_graph_vocabulary_matches_the_design():
    assert NODE_TYPES == ("endpoint", "function", "sink", "finding", "library", "crypto_asset")
    assert EDGE_KINDS == ("HANDLED_BY", "FLOWS_TO", "ON", "USES")


def test_re_adding_an_edge_updates_it_instead_of_duplicating():
    g = SecurityGraph()
    g.add_endpoint("GET /x")
    g.add_function("a.py::f", name="f", file="a.py")
    g.handled_by("GET /x", "a.py::f", score=0.7, signals={"route": True}, origin="correlated")
    g.handled_by("GET /x", "a.py::f", score=1.0, signals={"route": True}, origin="correlated")
    (edge,) = g.backend.edges("HANDLED_BY")
    assert edge[3]["score"] == 1.0


# --- P9.5 attack paths + persistence ------------------------------------------ #
def test_attack_path_matches_the_documented_chain(store):
    scan_id, runtime, handlers = _correlated_scan(store)
    paths = build_graph(store, scan_id, handlers).attack_paths()
    assert ["GET /api/accounts/{param}", "get_account", "db.execute", runtime] in paths
    (sqli,) = by_type(store, scan_id, "sqli")
    # a static finding still shows the endpoint that reaches it
    assert ["GET /api/users/search", "search_users", "cursor.execute", sqli.id] in paths


def test_a_finding_without_a_sink_yields_a_shorter_chain():
    g = SecurityGraph()
    g.add_endpoint("GET /x")
    g.add_function("a.py::f", name="f", file="a.py")
    g.handled_by("GET /x", "a.py::f", score=1.0, signals={}, origin="static")
    g.add_finding("F-0001")
    g.on("F-0001", "GET /x")
    assert g.attack_paths() == [["GET /x", "f", "F-0001"]]


def test_graph_reloads_identically_from_json(store, tmp_path):
    scan_id, _, handlers = _correlated_scan(store)
    graph = build_graph(store, scan_id, handlers)
    path = graph.save(graph_path(tmp_path / "data", scan_id))
    assert path.name == f"{scan_id}.json" and path.parent.name == "graphs"

    reloaded = SecurityGraph.load(path)
    assert reloaded.to_node_link() == graph.to_node_link()
    assert reloaded.attack_paths() == graph.attack_paths()
    assert reloaded.to_api() == graph.to_api()


def test_serialization_is_stable_regardless_of_insertion_order(tmp_path):
    def build(order, name):
        g = SecurityGraph()
        for key in order:
            g.add_endpoint(key)
        g.add_function("a.py::f", name="f", file="a.py", line=1)
        for key in order:
            g.handled_by(key, "a.py::f", score=1.0, signals={}, origin="static")
        return g.save(tmp_path / f"{name}.json").read_text(encoding="utf-8")

    assert build(["GET /a", "GET /b", "GET /c"], "one") == build(["GET /c", "GET /a", "GET /b"], "two")


def test_api_view_is_cytoscape_shaped_and_shows_the_edge_score(store):
    scan_id, _, handlers = _correlated_scan(store)
    view = build_graph(store, scan_id, handlers).to_api()
    assert {"nodes", "edges"} == set(view)
    assert all("id" in n["data"] and "type" in n["data"] for n in view["nodes"])
    handled = [e["data"] for e in view["edges"] if e["data"]["kind"] == "HANDLED_BY"]
    assert any(e["score"] == 1.0 and e["origin"] == "correlated" for e in handled)
    json.dumps(view)  # JSON-serialisable for the API


def test_graph_path_rejects_anything_that_is_not_a_scan_id(tmp_path):
    assert graph_path(tmp_path, "S-0001").name == "S-0001.json"
    for bad in ("../etc/passwd", "S-1/../../x", "F-0001", "", "S-0001.json"):
        with pytest.raises(ValueError):
            graph_path(tmp_path, bad)


def test_backend_is_swappable_behind_the_protocol():
    needed = {"add_node", "add_edge", "node", "nodes", "edges", "successors", "predecessors", "to_node_link"}
    assert needed <= set(dir(NetworkXBackend))
    SecurityGraph(NetworkXBackend()).add_endpoint("GET /x")  # accepts any backend object


# --- through the real graph (Mode 3) ------------------------------------------ #
async def test_mode3_run_correlates_in_the_real_node_and_persists_the_graph(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    seed_handlers(store, scan_id)  # what the code worker will provide
    seed_static(store, scan_id)

    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    assert final["completed_stages"].index("correlate") < final["completed_stages"].index("score")

    bac = by_type(store, scan_id, "broken_access_control")
    (primary,) = [f for f in bac if f.route]  # the runtime finding
    assert (primary.file, primary.function, primary.line) == ("app/routes/accounts.py", "get_account", 27)
    assert primary.correlation_score == 1.0 and primary.mode == Mode.correlated

    (ssrf,) = by_type(store, scan_id, "ssrf")  # runtime-only: route + method, no static twin
    assert (ssrf.function, ssrf.correlation_score) == ("fetch", 0.7)

    saved = graph_path(tmp_path / "data", scan_id)
    assert saved.is_file()
    graph = SecurityGraph.load(saved)
    assert ["GET /api/accounts/{param}", "get_account", "db.execute", primary.id] in graph.attack_paths()


async def test_correlate_without_a_handler_map_still_completes(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)  # code worker not built yet
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and graph_path(tmp_path / "data", scan_id).is_file()
    assert all(f.correlation_score is None for f in store.list_findings(scan_id))


# --- structural guarantee ------------------------------------------------------ #
def test_graph_package_is_deterministic_and_llm_free():
    banned = ("langchain", "aegis.agent", "aegis.chat", "random", "ollama", "httpx", "requests")
    for py in (ROOT / "aegis" / "graph").glob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not any(name == b or name.startswith(b + ".") for b in banned), f"{py.name} imports {name}"
