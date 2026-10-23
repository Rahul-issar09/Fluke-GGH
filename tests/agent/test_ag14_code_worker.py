"""AG14.1 — Worker 2 (code): routes → handlers, Semgrep, Gitleaks, inventory.

Default tests use the semgrep / gitleaks stand-ins (``fakes.tool_executors``), which mirror the
real tools on the demo code; ``test_ag14_tools_integration.py`` (``-m tools``) runs the real ones.
"""

from __future__ import annotations

import io
import json
import shutil

import pytest

from _graph_helpers import make_run
from aegis import observability as obs
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.worker_stage import run_steps
from aegis.evidence.models import FindingState, Mode
from aegis.safety.models import ToolResult
from aegis.workers.code.gitleaks import clean_report
from aegis.workers.code.inventory import components
from aegis.workers.code.routes_fastapi import extract_routes, routes_in_source
from aegis.workers.code.semgrep import add_dataflow_traces
from aegis.workers.executor import _gitleaks, _syft, no_tools_executor
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor
from test_ag10_remediate import SECRET_VALUE
from test_ag10_remediate_support import FixesTheAccessBug

pytestmark = pytest.mark.phase("AG14")

GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "routes_demo_app.json"
ROUTE_COUNT = 10  # the demo's six API routes and its four web pages (TNW-4)
STEPS = ["inventory", "extract_routes", "semgrep", "gitleaks"]


def code_scan(store, tmp_path, app="demo-app", executor=fix_executor, mode=Mode.code, **deps):
    scan_id, state, config = make_run(store, tmp_path, mode, tool_executor=executor, **deps)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / app / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    return scan_id, state, config, src


def by_type(store, scan_id):
    out: dict[str, list] = {}
    for f in store.list_findings(scan_id):
        out.setdefault(f.type, []).append(f)
    return out


# --------------------------------------------------------------------------------------------- #
# the tests the plan names
# --------------------------------------------------------------------------------------------- #
def test_ag14_routes_match_golden():
    routes, skipped = extract_routes(ROOT / "demo-app")
    assert skipped == [] and routes == json.loads(GOLDEN.read_text(encoding="utf-8"))
    # the six API routes the runtime worker discovers from the running app's OpenAPI document,
    # plus the four web pages (TNW-4) that the document leaves out (include_in_schema=False)
    assert {(tuple(r["methods"]), r["path"]) for r in routes} == {
        (("GET",), "/health"), (("POST",), "/login"), (("GET",), "/api/accounts"),
        (("GET",), "/api/accounts/{id}"), (("GET",), "/api/fetch"), (("GET",), "/api/users/search"),
        (("GET",), "/"), (("GET",), "/static/app.js"), (("GET",), "/login-form"), (("POST",), "/login-form"),
    }


async def test_ag14_sqli_dataflow(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path)
    await run_steps("code", STEPS, state, config)

    (sqli,) = by_type(store, scan_id)["sqli"]
    assert (sqli.file, sqli.line, sqli.owasp, sqli.mode.value) == ("app/routes/users.py", 16, "A03", "code")
    kinds = {e.kind: json.loads(e.payload_json) for e in store.evidence_for(sqli.id)}
    # one finding, two rules: the FastAPI taint rule and the framework-independent one (TNW-5)
    rules = {json.loads(e.payload_json)["rule"] for e in store.evidence_for(sqli.id) if e.kind == "code_location"}
    assert rules == {"fastapi-sqli", "python-sqli"}
    flow = kinds["dataflow_path"]
    assert flow["source"] == ["search_users(name)", 12]                   # the request input...
    assert flow["steps"] == [{"line": 15, "var": "query", "from": ["name"]}]  # ...builds the query...
    assert flow["sink"][1] == 16 and ".execute(query)" in flow["sink"][0]      # ...which reaches execute
    assert flow["traced_by"] == "aegis ast def-use (intra-function)"


async def test_ag14_ownercheck_finding(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path)
    await run_steps("code", STEPS, state, config)
    (bac,) = by_type(store, scan_id)["broken_access_control"]
    assert (bac.file, bac.line, bac.owasp) == ("app/routes/accounts.py", 37, "A01")
    (flow,) = [json.loads(e.payload_json) for e in store.evidence_for(bac.id) if e.kind == "dataflow_path"]
    assert flow["source"] == ["get_account(id)", 34] and flow["sink"][1] == 37   # the path id is the lookup key
    assert "weak_crypto" not in by_type(store, scan_id)      # weak crypto is Worker 3's job (AG15), not counted twice


async def test_ag14_secret_redacted(store, tmp_path):
    obs.reset_logging()
    stream = io.StringIO()
    obs.configure_logging(level="DEBUG", json=True, stream=stream)
    try:
        leaky = _leaky_gitleaks  # a gitleaks that (wrongly) reports the raw value
        scan_id, state, config, _ = code_scan(store, tmp_path, executor=leaky)
        await run_steps("code", STEPS, state, config)
    finally:
        logs = stream.getvalue()
        obs.reset_logging()

    (secret,) = by_type(store, scan_id)["secret"]
    assert (secret.file, secret.line, secret.state) == ("app/config.py", 6, FindingState.candidate)
    everything = [e.payload_json for e in store.list_evidence(scan_id)] + [json.dumps(f.model_dump(), default=str) for f in store.list_findings(scan_id)]
    assert SECRET_VALUE not in "\n".join(everything) and SECRET_VALUE not in logs   # neither stored nor logged
    payload = json.loads(store.evidence_for(secret.id)[0].payload_json)
    assert payload["value"] == "***REDACTED***" and payload["rule"] == "stripe-access-token"


async def _leaky_gitleaks(call, args, inputs):
    if call.tool != "gitleaks":
        return await fix_executor(call, args, inputs)
    out = (await fix_executor(call, args, inputs)).output
    for row in out:
        row["Secret"], row["Match"] = SECRET_VALUE, f'API_KEY = "{SECRET_VALUE}"'
    return ToolResult(ok=True, tool="gitleaks", exit_code=0, output=out)


async def test_the_patched_app_is_clean(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, app="demo-app-patched")
    await run_steps("code", STEPS, state, config)
    assert store.list_findings(scan_id) == []
    handlers = [e for e in store.list_evidence(scan_id, kind="code_location") if json.loads(e.payload_json).get("role") == "route_handler"]
    assert len(handlers) == ROUTE_COUNT                                   # routes are still mapped


# --------------------------------------------------------------------------------------------- #
# the whole graph: a code scan, and a correlated scan that now links runtime proof to code
# --------------------------------------------------------------------------------------------- #
async def test_a_code_only_scan_finds_every_planted_code_weakness(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path)
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    found = {(f.type, f.file, f.line) for f in store.list_findings(scan_id)}
    assert {
        ("sqli", "app/routes/users.py", 16),
        ("broken_access_control", "app/routes/accounts.py", 37),
        ("secret", "app/config.py", 6),
        ("ssrf", "app/routes/fetch.py", 17),
        ("weak_crypto", "app/auth.py", 12),          # found by the crypto stage (Worker 3), which code scans also run
    } <= found
    assert {t for t, _, _ in found} == {"sqli", "broken_access_control", "secret", "ssrf", "weak_crypto", "quantum_risk"}


async def test_a_correlated_scan_links_the_runtime_proof_to_the_handler(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, mode=Mode.correlated, llm=FixesTheAccessBug())
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == []
    (runtime,) = [f for f in store.list_findings(scan_id) if f.type == "broken_access_control" and f.route]
    assert (runtime.file, runtime.function, runtime.state) == ("app/routes/accounts.py", "get_account", FindingState.confirmed)
    assert runtime.correlation_score == 1.0 and runtime.risk == 0.792   # route + method + data flow
    (draft,) = store.list_fix_attempts(runtime.id)                       # it has a file and line now, so a fix is drafted
    assert draft.status == "drafted" and 'row["owner_id"] != user["id"]' in draft.diff


# --------------------------------------------------------------------------------------------- #
# failure cases
# --------------------------------------------------------------------------------------------- #
async def test_missing_tools_are_skipped_and_the_scan_goes_on(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, executor=no_tools_executor)
    out = await run_steps("code", STEPS, state, config)
    assert out.get("errors", []) == [] and not out.get("aborted")
    assert store.list_findings(scan_id) == []                             # nothing to find without the tools...
    assert len(store.list_evidence(scan_id, kind="code_location")) == ROUTE_COUNT    # ...but the routes are still mapped
    assert store.list_evidence(scan_id, kind="tool_error") == []


async def test_a_failing_tool_is_recorded_and_the_stage_goes_on(store, tmp_path):
    async def semgrep_crashes(call, args, inputs):
        if call.tool == "semgrep":
            return ToolResult(ok=False, tool="semgrep", exit_code=2, stderr_tail="Fatal error: out of memory")
        return await fix_executor(call, args, inputs)

    scan_id, state, config, _ = code_scan(store, tmp_path, executor=semgrep_crashes)
    out = await run_steps("code", STEPS, state, config)
    assert any("semgrep failed" in e for e in out["errors"])
    assert [f.type for f in store.list_findings(scan_id)] == ["secret"]   # gitleaks still ran
    assert any("semgrep" in e.tool for e in store.list_evidence(scan_id, kind="tool_error"))


async def test_a_file_that_does_not_parse_is_skipped_and_logged(store, tmp_path):
    scan_id, state, config, src = code_scan(store, tmp_path)
    (src / "app" / "broken.py").write_text("def nope(:\n", encoding="utf-8")
    await run_steps("code", ["extract_routes"], state, config)
    (error,) = store.list_evidence(scan_id, kind="tool_error")
    assert "app/broken.py" in json.loads(error.payload_json)["reason"]
    assert len(store.list_evidence(scan_id, kind="code_location")) == ROUTE_COUNT


async def test_a_follow_up_scans_only_the_requested_file_and_adds_no_duplicates(store, tmp_path):
    seen = []

    async def recording(call, args, inputs):
        seen.append((call.tool, args.get("files"), args["path"]))
        return await fix_executor(call, args, inputs)

    scan_id, state, config, src = code_scan(store, tmp_path, executor=recording)
    await run_steps("code", ["extract_routes"], state, config)
    await run_steps("code", ["extract_routes", "semgrep"], state, config, target={"file": "app/routes/accounts.py"})
    assert ("semgrep", ["app/routes/accounts.py"], str(src)) in seen
    assert [f.type for f in store.list_findings(scan_id)] == ["broken_access_control"]
    assert len(store.list_evidence(scan_id, kind="code_location")) == ROUTE_COUNT + 1   # handlers once, plus the finding's location

    seen.clear()
    await run_steps("code", ["semgrep"], state, config, target={"file": "../../etc/passwd"})
    assert seen and seen[0][1] is None                                    # a target outside the source is ignored


async def test_a_scan_without_source_aborts_the_code_stage_with_a_reason(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code, tool_executor=fix_executor)
    store.update_scan(scan_id, source_path=str(tmp_path / "missing"))
    out = await run_steps("code", STEPS, state, config)
    assert out["aborted"] and any("no source folder" in e for e in out["errors"])


# --------------------------------------------------------------------------------------------- #
# building blocks
# --------------------------------------------------------------------------------------------- #
def test_flask_and_prefixed_fastapi_routes_are_understood():
    flask = (
        "from flask import Blueprint\n"
        "bp = Blueprint('acct', __name__, url_prefix='/api/v2')\n"
        "@bp.route('/accounts/<int:id>', methods=['GET', 'DELETE'])\n"
        "def account(id):\n    return id\n"
        "@app.route('/ping')\n"
        "def ping():\n    return 'ok'\n"
    )
    rows = {(r["path"], tuple(r["methods"])) for r in routes_in_source(flask, "a.py")}
    assert rows == {("/api/v2/accounts/<int:id>", ("GET", "DELETE")), ("/ping", ("GET",))}

    fastapi = (
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/items')\n"
        "@router.api_route('/{item_id}', methods=['PUT', 'PATCH'])\n"
        "async def update(item_id: int):\n    ...\n"
    )
    (row,) = routes_in_source(fastapi, "items.py")
    assert (row["path"], row["methods"], row["function"], row["line"]) == ("/api/items/{item_id}", ["PUT", "PATCH"], "update", 4)


def test_include_router_prefixes_apply_across_modules(tmp_path):
    (tmp_path / "app" / "routes").mkdir(parents=True)
    (tmp_path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom .routes import users\napp = FastAPI()\napp.include_router(users.router, prefix='/v1')\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "routes" / "users.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/users')\ndef users():\n    return []\n", encoding="utf-8"
    )
    (row,) = extract_routes(tmp_path)[0]
    assert row["path"] == "/v1/users" and row["file"] == "app/routes/users.py"


def test_flows_are_traced_only_inside_route_handlers(tmp_path):
    source = """@router.get('/x')
def h(request, name: str, page: int = 1):
    prefix = 'SELECT '
    q = prefix + name
    q2 = q.strip()
    db.execute(q2)
def helper(value):
    db.execute(value)
"""
    (tmp_path / "h.py").write_text(source, encoding="utf-8")
    results = [
        {"check_id": "rules.semgrep.fastapi-sqli", "path": "h.py", "start": {"line": 6}, "extra": {}},
        {"check_id": "rules.semgrep.fastapi-sqli", "path": "h.py", "start": {"line": 8}, "extra": {}},
    ]
    handler, helper = add_dataflow_traces(results, tmp_path)
    trace = handler["extra"]["dataflow_trace"]
    assert trace["taint_source"] == ["h(name)", 2] and trace["taint_sink"] == ["db.execute(q2)", 6]
    assert [s["var"] for s in trace["steps"]] == ["q", "q2"]          # name -> q -> q2 -> execute
    assert "dataflow_trace" not in helper["extra"]                     # a plain function's input is not a request


def test_an_overwritten_variable_carries_no_flow():
    from aegis.workers.code.dataflow import trace_to_line

    source = """def h(name):
    q = name
    q = 'SELECT 1'
    db.execute(q)
"""
    assert trace_to_line(source, 4) is None


def test_gitleaks_reports_are_cleaned_of_anything_that_could_hold_the_value(tmp_path):
    raw = [{"RuleID": "r", "File": str(tmp_path / "app" / "c.py"), "StartLine": 3, "Secret": "s3cret", "Match": "k='s3cret'", "Line": "k='s3cret'"}]
    (row,) = clean_report(raw, tmp_path)
    assert row == {"RuleID": "r", "File": "app/c.py", "StartLine": 3}
    assert clean_report([{"File": "./.env", "RuleID": "r"}], tmp_path)[0]["File"] == ".env"


def test_the_gitleaks_and_syft_command_lines(tmp_path):
    gl = _gitleaks({"path": str(tmp_path)})
    try:
        assert gl.argv[:3] == ["gitleaks", "dir", str(tmp_path.resolve())]
        assert {"--redact", "--no-banner"} <= set(gl.argv) and gl.argv[gl.argv.index("--exit-code") + 1] == "0"
        assert gl.report_parse == "json" and gl.report_file.endswith("report.json")
    finally:
        shutil.rmtree(gl.cleanup_dir, ignore_errors=True)
    sy = _syft({"path": str(tmp_path)})
    assert sy.argv[:2] == ["syft", f"dir:{tmp_path.resolve()}"] and "cyclonedx-json" in sy.argv


async def test_the_inventory_keeps_a_compact_component_list(store, tmp_path):
    sbom = {"components": [{"name": "fastapi", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0", "type": "library", "hashes": ["…"]}, {"bom-ref": "x"}]}
    assert components(sbom) == [{"name": "fastapi", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0", "type": "library"}]

    async def with_syft(call, args, inputs):
        if call.tool == "syft":
            return ToolResult(ok=True, tool="syft", exit_code=0, output=sbom)
        return await fix_executor(call, args, inputs)

    scan_id, state, config, _ = code_scan(store, tmp_path, executor=with_syft)
    await run_steps("code", ["inventory"], state, config)
    (dep,) = store.list_evidence(scan_id, kind="dependency")
    assert (dep.tool, json.loads(dep.payload_json)["count"]) == ("syft", 1)


# --------------------------------------------------------------------------------------------- #
# the rule set: every rule is wired end to end
# --------------------------------------------------------------------------------------------- #
RULES_DIR = ROOT / "rules" / "semgrep"
CASES_DIR = ROOT / "tests" / "fixtures" / "semgrep_cases"


def test_every_rule_has_a_type_a_severity_a_template_and_examples():
    import yaml

    from aegis.agent.explanation import TEMPLATES
    from aegis.evidence.adapters.semgrep import _RULE_MAP
    from aegis.risk.engine import load_severity

    severity = load_severity()
    demo_rules = {"fastapi-sqli", "fastapi-missing-owner-check", "weak-hash"}  # proven on the demo apps instead
    for path in sorted(RULES_DIR.glob("*.yml")):
        (rule,) = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
        assert rule["id"] == path.stem, path
        ftype, owasp, _ = _RULE_MAP[rule["id"]]
        assert rule["metadata"]["owasp"] == owasp
        assert ftype in TEMPLATES and severity.for_type(ftype) != severity.for_type("an-unknown-type"), ftype
        if rule["id"] not in demo_rules:
            examples = {p.stem for p in (CASES_DIR / rule["id"]).glob("*.*")}
            assert {"bad", "good"} <= examples, rule["id"]
