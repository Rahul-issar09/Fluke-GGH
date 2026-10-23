"""AG14 — route → handler extraction for Django, Express and Spring (beyond FastAPI/Flask)."""

from __future__ import annotations

import json

import pytest

from aegis.graph.correlator import Handler, RuntimeTarget, link_score
from aegis.graph.route_normalize import normalize_path
from aegis.workers.code.routes_fastapi import extract_routes
from aegis.workers.code.routes_more import ANY_METHODS
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("AG14")

SAMPLES = ROOT / "tests" / "fixtures" / "route_samples"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"


@pytest.mark.parametrize("framework", ["django", "express", "express-ts", "spring"])
def test_routes_match_golden(framework):
    routes, skipped = extract_routes(SAMPLES / framework)
    assert skipped == [] and routes == json.loads((GOLDEN / f"routes_{framework}.json").read_text(encoding="utf-8"))


def by_route(framework):
    return {(tuple(r["methods"]), r["path"]): r for r in extract_routes(SAMPLES / framework)[0]}


def test_django_includes_regexes_decorators_and_class_based_views():
    routes = by_route("django")
    assert routes[(("GET",), "/api/orders/")]["qualname"] == "shop/views.py::order_list"            # @require_GET
    detail = routes[(("GET", "DELETE"), "/api/orders/<int:order_id>/")]                              # @require_http_methods
    assert (detail["function"], detail["line"]) == ("order_detail", 14)                              # imported by name
    assert (tuple(ANY_METHODS), "/api/invoices/{number}/") in routes                                 # re_path named group
    assert routes[(("GET", "POST"), "/api/profile/")]["function"] == "ProfileView"                   # methods the class defines
    assert (tuple(ANY_METHODS), "/health/ping/") in routes                                           # second include prefix


def test_express_prefixes_named_and_inline_handlers_and_route_chains():
    routes = by_route("express")
    assert routes[(("GET",), "/api/orders/:id")]["qualname"] == "routes/orders.js::getOrder"        # app.use prefix + last handler
    assert routes[(("GET",), "/health")]["line"] == 9                                                # the named function declaration
    assert routes[(("POST",), "/login")]["function"] == "post_login"                                  # inline arrow function
    assert routes[(("GET",), "/api/orders/:id/items")]["function"] == "listItems"                     # .route().get(named fn)
    assert (("POST",), "/api/orders/:id/items") in routes                                             # ...and the chained .post


def test_express_in_typescript_finds_the_same_routes_as_javascript():
    # TNW-5: .ts files are parsed with the TypeScript grammar (type annotations, import/export default)
    js = {key: (r["function"], r["line"]) for key, r in by_route("express").items()}
    ts = {key: (r["function"], r["line"]) for key, r in by_route("express-ts").items()}
    assert ts == js
    assert by_route("express-ts")[(("GET",), "/api/orders/:id")]["qualname"] == "routes/orders.ts::getOrder"
    assert all(not r["file"].endswith(".d.ts") for r in by_route("express-ts").values())


def test_spring_class_prefix_mapping_annotations_and_methods():
    routes = by_route("spring")
    get = routes[(("GET",), "/api/orders/{id}")]
    assert get["qualname"].endswith("OrderController.java::getOrder") and get["line"] == 15
    assert (("POST",), "/api/orders") in routes                                                       # @PostMapping without a path
    assert (("POST", "PUT"), "/api/orders/{id}/cancel") in routes                                     # @RequestMapping(method = {...})
    assert (("DELETE",), "/api/orders/{id}") in routes                                                # @DeleteMapping(path = ...)
    assert {(("GET",), "/health"), (("GET",), "/healthz")} <= set(routes)                             # an array of paths


@pytest.mark.parametrize(
    "written",
    ["/api/orders/:id", "/api/orders/<int:order_id>", "/api/orders/{id}"],
)
def test_every_frameworks_parameter_syntax_matches_the_runtime_route(written):
    assert normalize_path(written) == normalize_path("/api/orders/12") == "/api/orders/{param}"


def test_an_express_handler_links_to_a_runtime_finding():
    handler = Handler(path="/api/orders/:id", methods=("GET",), qualname="routes/orders.js::getOrder", function="getOrder",
                      file="routes/orders.js", line=8, end_line=11, evidence_id="E-1")
    score, signals = link_score(RuntimeTarget("GET", "/api/orders/{id}"), handler, [])
    assert score == 0.7 and signals == {"route": True, "method": True}


def test_a_broken_javascript_or_java_file_does_not_stop_the_others(tmp_path):
    (tmp_path / "ok.js").write_text("app.get('/ok', (req, res) => res.end());\n", encoding="utf-8")
    (tmp_path / "broken.js").write_text("app.get('/x', (req, res => {\n", encoding="utf-8")       # tree-sitter recovers
    (tmp_path / "Ok.java").write_text("class A { @GetMapping(\"/j\") void f() {} }\n", encoding="utf-8")
    routes, skipped = extract_routes(tmp_path)
    assert {r["path"] for r in routes} >= {"/ok", "/j"}
