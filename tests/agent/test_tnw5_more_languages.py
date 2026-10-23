"""TNW-5 — more languages and deeper data flow.

* the rules: a framework-independent Python SQL injection rule (the dvpwa gap), Express rules
  (JavaScript + TypeScript) and Spring rules (Java) — each mapped to a finding type, with bad and
  good examples that real semgrep checks line by line (``test_ag14_tools_integration``, -m tools),
* data flow one call level deep: a route handler's input, passed to a helper in the same file,
  followed into the helper to the sink — and the correlator merging such a helper finding into the
  runtime finding of the handler's route,
* ``-m tools``: real semgrep over a small Express (JS + TS) shop and a Spring controller.
"""

from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path

import pytest

from aegis.evidence.adapters.base import EvidenceDraft, FindingDraft
from aegis.evidence.adapters.semgrep import _RULE_MAP, SemgrepAdapter
from aegis.evidence.links import merged_ids
from aegis.evidence.normalizer import ingest
from aegis.graph.correlator import correlate_scan, load_handlers
from aegis.workers.code.dataflow import TRACED_BY_CALL, trace_through_call
from aegis.workers.code.routes_fastapi import extract_routes, route_handlers
from aegis.workers.code.semgrep import add_dataflow_traces
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("TNW-5")

RULES = ROOT / "rules" / "semgrep"
POLYGLOT = ROOT / "tests" / "fixtures" / "polyglot"

HELPER_APP = textwrap.dedent('''\
    from fastapi import APIRouter
    router = APIRouter()


    def find_users(db, term):
        pattern = "%" + term + "%"
        sql = "SELECT * FROM users WHERE name LIKE '" + pattern + "'"
        return db.execute(sql).fetchall()


    @router.get("/api/users/search")
    def search(name: str, request):
        cleaned = name.strip()
        return find_users(request.app.state.db, cleaned)


    @router.get("/api/users/count")
    def count(request):
        return find_users(request.app.state.db, "fixed")


    class Repo:
        def lookup(self, db, key):
            return db.execute("SELECT * FROM t WHERE k = '" + key + "'")


    @router.get("/api/lookup")
    def lookup(key: str, request):
        return Repo().lookup(db=request.app.state.db, key=key)
    ''')


# --------------------------------------------------------------------------------------------- #
# the rules
# --------------------------------------------------------------------------------------------- #
NEW_RULES = {
    "python-sqli": ("sqli", "python"),
    "js-sqli": ("sqli", "javascript"), "js-command-injection": ("command_injection", "javascript"),
    "js-code-injection": ("code_injection", "javascript"), "js-ssrf": ("ssrf", "javascript"),
    "js-path-traversal": ("path_traversal", "javascript"),
    "java-sqli": ("sqli", "java"), "java-command-injection": ("command_injection", "java"),
    "java-ssrf": ("ssrf", "java"), "java-path-traversal": ("path_traversal", "java"),
}


@pytest.mark.parametrize("rule", sorted(NEW_RULES))
def test_each_new_rule_is_mapped_and_has_examples(rule):
    import yaml

    (spec,) = yaml.safe_load((RULES / f"{rule}.yml").read_text(encoding="utf-8"))["rules"]
    ftype, language = NEW_RULES[rule]
    assert spec["id"] == rule and language in spec["languages"] and _RULE_MAP[rule][0] == ftype
    if language == "javascript":
        assert "typescript" in spec["languages"]
    examples = {p.name for p in (ROOT / "tests" / "fixtures" / "semgrep_cases" / rule).iterdir()}
    assert any(n.startswith("bad.") for n in examples) and any(n.startswith("good.") for n in examples)


def test_a_typescript_sqli_example_exists():
    assert (ROOT / "tests" / "fixtures" / "semgrep_cases" / "js-sqli" / "bad.ts").is_file()


# --------------------------------------------------------------------------------------------- #
# data flow, one call level
# --------------------------------------------------------------------------------------------- #
def _trace(line: int):
    tree = ast.parse(HELPER_APP)
    return trace_through_call(HELPER_APP, line, route_handlers(tree), tree=tree)


def test_a_handlers_input_is_followed_into_a_helper():
    payload = _trace(8).as_payload()
    assert payload["source"] == ["search(name)", 12]
    assert payload["steps"] == [
        {"line": 13, "var": "cleaned", "from": ["name"]},                              # in the handler
        {"line": 14, "var": "find_users(term)", "from": ["cleaned"], "call": "find_users"},  # the call
        {"line": 6, "var": "pattern", "from": ["term"]},                               # in the helper
        {"line": 7, "var": "sql", "from": ["pattern"]},
    ]
    assert payload["sink"] == ["return db.execute(sql).fetchall()", 8]
    assert payload["traced_by"] == TRACED_BY_CALL


def test_keyword_arguments_and_method_calls_are_followed():
    payload = _trace(24).as_payload()
    assert payload["source"] == ["lookup(key)", 28]
    assert payload["steps"] == [{"line": 29, "var": "lookup(key)", "from": ["key"], "call": "lookup"}]


def test_no_trace_without_a_tainted_argument_or_inside_a_handler():
    tree = ast.parse(HELPER_APP)
    only_count = [h for h in route_handlers(tree) if h.name == "count"]   # passes a constant
    assert trace_through_call(HELPER_APP, 8, only_count, tree=tree) is None
    assert _trace(14) is None                                              # line 14 is in a handler itself


def test_helpers_of_helpers_and_other_files_are_not_followed():
    deeper = textwrap.dedent('''\
        from fastapi import APIRouter
        router = APIRouter()


        def inner(db, v):
            return db.execute("SELECT " + v)


        def outer(db, v):
            return inner(db, v)


        @router.get("/x")
        def handler(v: str, request):
            return outer(request.app.state.db, v)
        ''')
    tree = ast.parse(deeper)
    assert trace_through_call(deeper, 6, route_handlers(tree), tree=tree) is None


def test_semgrep_results_in_a_helper_get_the_traced_flow(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "users.py").write_text(HELPER_APP, encoding="utf-8")
    results = add_dataflow_traces([{"check_id": "rules.semgrep.python-sqli", "path": "app\\users.py", "start": {"line": 8}}], tmp_path)
    trace = results[0]["extra"]["dataflow_trace"]
    assert trace["taint_source"] == ["search(name)", 12] and trace["handler"] == "app/users.py::search"
    assert trace["traced_by"] == TRACED_BY_CALL


def test_the_correlator_merges_a_helper_finding_into_the_handlers_runtime_finding(store, tmp_path):
    scan_id = store.add_scan(mode="correlated").id
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "users.py").write_text(HELPER_APP, encoding="utf-8")
    routes, _ = extract_routes(tmp_path)
    for row in routes:
        store.add_evidence(scan_id, kind="code_location", tool="treesitter", payload={"role": "route_handler", **row})
    raw = {"results": add_dataflow_traces(
        [{"check_id": "rules.semgrep.python-sqli", "path": "app/users.py", "start": {"line": 8}, "extra": {"message": "sql"}}], tmp_path)}
    (static_id,) = ingest(store, scan_id, SemgrepAdapter(mode="code").parse(raw, scan_id))
    (runtime_id,) = ingest(store, scan_id, [(
        FindingDraft(type="sqli", owasp="A03", title="SQL error on search", route="GET /api/users/search",
                     severity=0.9, source="worker1.probe", mode="runtime"),
        [EvidenceDraft(kind="http_exchange", tool="httpx", payload={"method": "GET", "route": "/api/users/search", "status": 500})],
    )])

    report = correlate_scan(store, scan_id, load_handlers(store, scan_id))
    (entry,) = report.correlated
    assert entry["finding_id"] == runtime_id and entry["handler"] == "app/users.py::search"
    assert entry["score"] == 1.0 and entry["merged"] == [static_id]       # route + method + the traced flow
    assert merged_ids(store, scan_id) == {static_id}
    f = store.get_finding(runtime_id)
    assert (f.file, f.line, f.function) == ("app/users.py", 8, "search")   # the root cause is the helper's line


# --------------------------------------------------------------------------------------------- #
# real semgrep over Express (JS + TS) and Spring (-m tools)
# --------------------------------------------------------------------------------------------- #
@pytest.mark.tools
@pytest.mark.parametrize("app, expected", [
    ("express-shop", {("sqli", "app.js", 11), ("command_injection", "app.js", 15), ("sqli", "routes/items.ts", 7)}),
    ("spring-shop", {("sqli", "src/main/java/shop/ItemController.java", 19),
                     ("command_injection", "src/main/java/shop/ItemController.java", 24)}),
])
async def test_real_semgrep_on_express_and_spring_apps(store, tmp_path, monkeypatch, app, expected):
    import os
    import shutil

    from _graph_helpers import make_run
    from aegis.agent.nodes.worker_stage import run_steps
    from aegis.evidence.models import Mode
    from aegis.workers import executor

    import aegis.agent.nodes.code_subgraph  # noqa: F401 - registers the code steps

    semgrep = ROOT / ".tools" / "semgrep" / "Scripts"
    monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [str(semgrep), os.environ.get("AEGIS_TOOL_DIRS")])))
    if executor.find_binary("semgrep") is None:
        pytest.skip("semgrep is not installed")
    scan_id, state, config = make_run(store, tmp_path, Mode.code, tool_executor=executor.execute_tool)
    src = tmp_path / "scan"
    shutil.rmtree(src)
    shutil.copytree(POLYGLOT / app, src)
    store.update_scan(scan_id, source_path=str(src))
    out = await run_steps("code", ["extract_routes", "semgrep"], state, config)
    assert out.get("errors", []) == [], out
    found = {(f.type, f.file, f.line) for f in store.list_findings(scan_id)}
    assert found == expected
    handlers = [json.loads(e.payload_json) for e in store.list_evidence(scan_id, kind="code_location")
                if json.loads(e.payload_json).get("role") == "route_handler"]
    assert handlers, "the routes are mapped too"
    if app == "express-shop":
        assert {"/api/items/:id", "/api/users", "/api/ping"} <= {h["path"] for h in handlers}
