"""AG06.2 (part 2) — Nuclei + Schemathesis: adapters, executor, steps."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest
from sqlmodel import select

from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.adapters.schemathesis import JunitRejected, SchemathesisAdapter
from aegis.evidence.models import Evidence, FindingState, Mode, ToolCallLog
from aegis.evidence.normalizer import ingest
from aegis.safety.models import ToolCall, ToolResult
from aegis.safety.policies import PolicyError, validate_args
from aegis.workers import executor
from aegis.workers.base import run_tool

pytestmark = pytest.mark.phase("AG06")

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "tools"


def _nuclei_rows() -> list[dict]:
    text = (FIXTURES / "nuclei_sample.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _junit(name: str) -> dict:
    return {"junit_xml": (FIXTURES / name).read_text(encoding="utf-8")}


# --- Nuclei adapter ----------------------------------------------------------- #
def test_nuclei_results_become_candidate_misconfig_findings(store):
    scan = store.add_scan(mode="runtime")
    ids = ingest(store, scan.id, NucleiAdapter(mode="runtime").parse(_nuclei_rows(), scan.id))
    findings = store.list_findings(scan.id)

    # two matchers of one template on "/" stay two findings; plus the exposed spec
    assert len(ids) == 3 and len(findings) == 3
    assert {f.type for f in findings} == {"misconfig"} and {f.owasp for f in findings} == {"A05"}
    assert {f.state for f in findings} == {FindingState.candidate}  # one tool signal only
    assert {f.route for f in findings} == {"GET /", "GET /openapi.json"}
    by_title = {f.title: f for f in findings if f.route == "GET /openapi.json"}
    assert by_title["OpenAPI Specification Exposed"].severity == 0.5  # nuclei "medium"
    assert all(f.severity == 0.1 for f in findings if f.route == "GET /")  # nuclei "info"


def test_nuclei_adapter_never_stores_curl_commands_or_headers(store):
    scan = store.add_scan(mode="runtime")
    ingest(store, scan.id, NucleiAdapter().parse(_nuclei_rows(), scan.id))
    with store.session() as s:
        blobs = " ".join(e.payload_json for e in s.exec(select(Evidence)))
    assert "SHOULD-NEVER-BE-STORED" not in blobs and "curl" not in blobs


def test_nuclei_adapter_ignores_malformed_rows():
    assert NucleiAdapter().parse([{"no": "template-id"}, "junk", None], "S-1") == []
    assert NucleiAdapter().parse(None, "S-1") == []


# --- Schemathesis adapter (real recorded report) ------------------------------ #
def test_schemathesis_failure_becomes_an_api_conformance_candidate(store):
    scan = store.add_scan(mode="runtime")
    ids = ingest(store, scan.id, SchemathesisAdapter(mode="runtime").parse(_junit("schemathesis_junit_authed.xml"), scan.id))
    (finding,) = store.list_findings(scan.id)
    assert ids == [finding.id]
    assert (finding.type, finding.owasp, finding.route) == ("api_conformance", "A05", "GET /api/accounts/{id}")
    assert finding.state == FindingState.candidate and finding.severity == 0.3

    (evidence,) = store.evidence_for(finding.id)
    payload = json.loads(evidence.payload_json)
    assert payload["status"] == 404 and payload["checks"] == ["Undocumented HTTP status code"]


def test_schemathesis_adapter_drops_the_repro_block_and_echoed_body(store):
    scan = store.add_scan(mode="runtime")
    ingest(store, scan.id, SchemathesisAdapter().parse(_junit("schemathesis_junit_authed.xml"), scan.id))
    with store.session() as s:
        blobs = " ".join(e.payload_json for e in s.exec(select(Evidence)))
    for leaked in ("Reproduce", "curl", "Cookie", "account not found", "127.0.0.1"):
        assert leaked not in blobs


def test_schemathesis_unauthenticated_report_yields_one_finding_per_operation(store):
    scan = store.add_scan(mode="runtime")
    ingest(store, scan.id, SchemathesisAdapter().parse(_junit("schemathesis_junit_unauthed.xml"), scan.id))
    assert {f.route for f in store.list_findings(scan.id)} == {
        "GET /api/accounts", "GET /api/users/search", "GET /api/accounts/{id}",
    }


def test_server_errors_rank_above_conformance_noise():
    raw = _junit("schemathesis_junit_authed.xml")
    raw["junit_xml"] = raw["junit_xml"].replace("Received: 404", "Received: 500")
    ((draft, _),) = SchemathesisAdapter().parse(raw, "S-1")
    assert draft.severity == 0.5


def test_schemathesis_adapter_refuses_dtd_and_bad_xml():
    with pytest.raises(JunitRejected):
        SchemathesisAdapter().parse({"junit_xml": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><testsuites/>'}, "S-1")
    with pytest.raises(JunitRejected):
        SchemathesisAdapter().parse({"junit_xml": "<testsuites><oops>"}, "S-1")


def test_schemathesis_runtime_errors_are_not_findings():
    xml = '<testsuites><testsuite><testcase name="GET /a"><error type="error">Runtime Error</error></testcase></testsuite></testsuites>'
    assert SchemathesisAdapter().parse({"junit_xml": xml}, "S-1") == []
    assert SchemathesisAdapter().parse({}, "S-1") == [] and SchemathesisAdapter().parse(None, "S-1") == []


# --- argument policy + command-line builders ---------------------------------- #
def test_schemathesis_policy_allows_only_credential_headers():
    assert validate_args("schemathesis", {"openapi": "http://x/o.json", "url": "http://x", "headers": {"Cookie": "s=1"}})
    with pytest.raises(PolicyError):
        validate_args("schemathesis", {"openapi": "o", "url": "u", "headers": {"X-Forwarded-For": "1.2.3.4"}})
    with pytest.raises(PolicyError):
        validate_args("schemathesis", {"openapi": "o", "url": "u", "extra_flag": "--anything"})


def test_nuclei_command_line_is_fixed_and_offline():
    spec = executor.BUILDERS["nuclei"]({"url": "http://demo-app:5000", "templates": "/offline-db/nuclei-templates", "rate_limit": 5})
    argv = spec.argv
    assert argv[0] == "nuclei" and argv[argv.index("-u") + 1] == "http://demo-app:5000"
    # the AEGIS profile (TNW-3): three HTTP template folders of the staged snapshot, nothing else
    folders = [pathlib.PurePath(argv[i + 1]).as_posix() for i, a in enumerate(argv) if a == "-t"]
    assert folders == [f"/offline-db/nuclei-templates/{d}" for d in ("http/misconfiguration", "http/exposures", "http/exposed-panels")]
    excluded = argv[argv.index("-etags") + 1].split(",")
    assert {"intrusive", "dos", "bruteforce", "oast", "osint", "token-spray", "default-login"} <= set(excluded)
    assert argv[argv.index("-tc") + 1].startswith("severity != 'info' || id == 'fastapi-docs'")
    for flag in ("-jsonl", "-disable-update-check", "-no-interactsh", "-disable-redirects"):  # nothing may phone home or leave the host
        assert flag in argv
    assert argv[argv.index("-rate-limit") + 1] == "5"
    assert spec.parse == "jsonl" and spec.ok_exit_codes == (0,)
    assert executor.BUILDERS["nuclei"]({"url": "u", "templates": "t", "rate_limit": 50}).timeout < spec.timeout <= 3600


def test_schemathesis_command_line_is_read_only_deterministic_and_utf8():
    spec = executor.BUILDERS["schemathesis"](
        {"openapi": "http://demo-app:5000/openapi.json", "url": "http://demo-app:5000", "headers": {"Cookie": "session=abc"}}
    )
    try:
        argv = spec.argv
        assert argv[argv.index("--include-method") + 1] == "GET"  # never mutating methods
        assert argv.count("--include-method") == 1
        assert argv[argv.index("--seed") + 1] == "1234" and "--generation-deterministic" in argv
        assert argv[argv.index("-H") + 1] == "Cookie: session=abc"
        assert spec.ok_exit_codes == (0, 1)  # exit 1 == "found failures"
        assert spec.env["PYTHONUTF8"] == "1"
        assert "junit" in argv and pathlib.Path(spec.report_file).parent.is_dir()
    finally:
        import shutil

        shutil.rmtree(spec.cleanup_dir, ignore_errors=True)


# --- executor ------------------------------------------------------------------ #
def _call(tool: str = "nuclei") -> ToolCall:
    return ToolCall(tool=tool, scan_id="S-0001", target_host="demo-app:5000", args={})


async def test_executor_reports_a_missing_binary_as_not_installed(monkeypatch):
    monkeypatch.setattr(executor, "find_binary", lambda name: None)
    res = await executor.execute_tool(_call("nuclei"), {"url": "http://x", "templates": "/t"}, [])
    assert res.ok is False and res.blocked_reason == "tool not installed: nuclei"


async def test_executor_has_no_command_for_unknown_tools():
    res = await executor.execute_tool(_call("treesitter"), {}, [])  # parsed in-process, never a subprocess
    assert res.ok is False and "no executor" in res.blocked_reason


async def test_executor_accepts_exit_1_and_returns_the_report(monkeypatch):
    def builder(args):
        report = pathlib.Path(args["dir"]) / "junit.xml"
        script = f"import pathlib,sys; pathlib.Path(r'{report}').write_text('<testsuites/>'); sys.exit(1)"
        return executor.RunSpec(argv=["fake", "-c", script], parse="text", ok_exit_codes=(0, 1), report_file=str(report))

    monkeypatch.setitem(executor.BUILDERS, "schemathesis", builder)
    monkeypatch.setattr(executor, "find_binary", lambda name: sys.executable)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        res = await executor.execute_tool(_call("schemathesis"), {"dir": tmp}, [])
    assert res.ok is True and res.exit_code == 1 and res.output == {"junit_xml": "<testsuites/>"}


async def test_executor_fails_when_the_report_is_missing(monkeypatch):
    def builder(args):
        return executor.RunSpec(
            argv=["fake", "-c", "pass"], parse="text", ok_exit_codes=(0, 1), report_file="/no/such/report.xml"
        )

    monkeypatch.setitem(executor.BUILDERS, "schemathesis", builder)
    monkeypatch.setattr(executor, "find_binary", lambda name: sys.executable)
    res = await executor.execute_tool(_call("schemathesis"), {}, [])
    assert res.ok is False and "no report written" in res.stderr_tail


async def test_run_tool_env_and_accepted_exit_codes():
    argv = [sys.executable, "-c", "import os,sys; print(os.environ['AEGIS_PROBE']); sys.exit(1)"]
    strict = await run_tool("x", argv, parse="text", env={"AEGIS_PROBE": "hello"})
    lenient = await run_tool("x", argv, parse="text", env={"AEGIS_PROBE": "hello"}, ok_exit_codes=(0, 1))
    assert strict.ok is False and lenient.ok is True
    assert lenient.output == {"text": "hello" + ("\r\n" if sys.platform == "win32" else "\n")}


# --- steps through SafetyController -------------------------------------------- #
def _stage_deps(config):
    return config["configurable"]["deps"]


def _stage_nuclei_templates(tmp_path):
    (tmp_path / "offline-db" / "nuclei-templates").mkdir(parents=True)


async def test_nuclei_step_ingests_results_and_audits_the_call(store, tmp_path):
    calls: list[ToolCall] = []

    async def fake(call, args, inputs):
        calls.append(call)
        return ToolResult(ok=True, tool=call.tool, exit_code=0, output=_nuclei_rows())

    _stage_nuclei_templates(tmp_path)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fake)
    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == []
    nuclei = [c for c in calls if c.tool == "nuclei"]
    assert len(nuclei) == 1 and nuclei[0].target_host == "demo-app:5000"
    assert nuclei[0].args["templates"].endswith("nuclei-templates")
    assert len([f for f in store.list_findings(scan_id) if f.type == "misconfig"]) == 3
    with store.session() as s:  # audited by SafetyController (hash only, no arguments)
        rows = [r for r in s.exec(select(ToolCallLog)) if r.tool == "nuclei"]
    assert len(rows) == 1 and len(rows[0].args_hash) == 16


async def test_nuclei_step_skips_quietly_when_templates_are_not_staged(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)  # no offline-db/nuclei-templates
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == []
    assert not [f for f in store.list_findings(scan_id) if f.type == "misconfig"]


async def test_missing_scanner_binary_skips_without_failing_the_scan(store, tmp_path):
    _stage_nuclei_templates(tmp_path)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)  # default: no tools installed
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    assert not [f for f in store.list_findings(scan_id) if f.type in ("misconfig", "api_conformance")]


async def test_a_scanner_that_runs_and_fails_is_recorded_as_a_tool_error(store, tmp_path):
    async def broken(call, args, inputs):
        return ToolResult(ok=False, tool=call.tool, exit_code=2, stderr_tail="templates unreadable")

    _stage_nuclei_templates(tmp_path)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=broken)
    final = await build_aegis_graph().ainvoke(state, config)

    assert any("runtime.check_misconfig" in e and "templates unreadable" in e for e in final["errors"])
    assert any("runtime.check_api" in e for e in final["errors"])
    assert final["completed_stages"][-1] == "finalize"  # the scan carries on
    with store.session() as s:
        errors = list(s.exec(select(Evidence).where(Evidence.scan_id == scan_id, Evidence.kind == "tool_error")))
    assert {e.tool for e in errors} == {"runtime.check_misconfig", "runtime.check_api"}


async def test_schemathesis_step_runs_as_identity_a_and_keeps_the_cookie_out_of_storage(store, tmp_path):
    seen: list[ToolCall] = []

    async def fake(call, args, inputs):
        seen.append(call)
        return ToolResult(ok=True, tool=call.tool, exit_code=1, output=_junit("schemathesis_junit_authed.xml"))

    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fake)
    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == []
    (call,) = [c for c in seen if c.tool == "schemathesis"]
    assert call.args["openapi"] == "http://demo-app:5000/openapi.json"
    assert call.args["headers"]["Cookie"].startswith("session=")  # authenticated as identity A
    assert [f.route for f in store.list_findings(scan_id) if f.type == "api_conformance"] == ["GET /api/accounts/{id}"]

    cookie = call.args["headers"]["Cookie"]
    with store.session() as s:
        stored = " ".join(e.payload_json for e in s.exec(select(Evidence)))
        logged = " ".join(f"{r.args_hash}{r.target_host}{r.blocked_reason}" for r in s.exec(select(ToolCallLog)))
    assert cookie not in stored and cookie not in logged and cookie.split("=")[1] not in stored


async def test_scanner_wrappers_are_refused_for_hosts_off_the_allowlist():
    from aegis.safety.allowlist import Allowlist
    from aegis.safety.controller import SafetyController
    from aegis.safety.rate_limiter import RateLimiter
    from aegis.safety.test_inputs import TestInputLibrary
    from aegis.workers.runtime.nuclei import run_nuclei
    from aegis.workers.runtime.schemathesis import run_schemathesis

    ran: list[str] = []

    async def executor_spy(call, args, inputs):  # pragma: no cover - must not run
        ran.append(call.tool)
        return ToolResult(ok=True, tool=call.tool, output=[])

    controller = SafetyController(
        Allowlist(["only-this-host:1"]), TestInputLibrary.load(), RateLimiter(1000, 1000), executor=executor_spy
    )
    nuclei = await run_nuclei(controller, "S-0001", "http://demo-app:5000", "/offline-db/nuclei-templates")
    st = await run_schemathesis(
        controller, "S-0001", "http://demo-app:5000", "http://demo-app:5000/openapi.json"
    )
    assert ran == []  # the executor is never reached
    assert "not allowlisted" in nuclei.blocked_reason and "not allowlisted" in st.blocked_reason
