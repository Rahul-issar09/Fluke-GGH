"""N1 — every read command through the API (cli_new_phases.md).

Same data, two ways: through the running API (default) and from the data folder (``--local``). The
``--json`` output must be identical; errors map to the same exit codes; evidence never shows a
credential even though the API's own evidence route returns the raw payload.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.main import app
from aegis.config import AppSettings, ModelSettings
from aegis.evidence.models import ScanStatus
from aegis.services.report_service import write_reports
from fakes import api_server

pytestmark = pytest.mark.phase("N1")

runner = CliRunner()
TOKEN = "s3cr3t-session-token-value-0042"


@pytest.fixture
def world(store, tmp_path, monkeypatch):
    scan = store.add_scan(mode="correlated", target_url="http://127.0.0.1:5000").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, source="worker1.bola", title="Broken access control")
    ev = store.add_evidence(scan, "http_exchange", "bola", finding_id=f.id, payload={
        "method": "GET", "route": "/api/accounts/1", "status": 200, "identity": "B",
        "request": f"GET /api/accounts/1\nAuthorization: Bearer {TOKEN}\n", "session_token": TOKEN})
    store.update_finding_fields(f.id, severity=0.9, risk=0.79, what="Any account by id.", impact="Read others' data.")
    low = store.add_finding(scan, type="misconfig", owasp="A05", route="GET /docs", source="nuclei", title="Docs public")
    store.update_finding_fields(low.id, severity=0.4, risk=0.05)
    store.update_scan(scan, status=ScanStatus.completed)
    write_reports(store, scan, str(tmp_path))
    stop = api_server.serve(monkeypatch, AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://127.0.0.1:9")))
    yield {"dir": str(tmp_path), "scan": scan, "fid": f.id, "ev": ev.id}
    stop()


def api(*args):
    return runner.invoke(app, list(args))


def local(world, *args):
    return runner.invoke(app, ["--local", "--data-dir", world["dir"], *args])


def _json(result):
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("args", [
    ["scan", "list"], ["scan", "status"], ["scan", "audit"], ["findings", "list"], ["findings", "list", "--owasp", "A01"],
    ["graph"],
])
def test_api_and_local_give_identical_json(world, args):
    assert _json(api("--json", *args)) == _json(local(world, "--json", *args))


def test_gate_verdict_and_exit_code_are_identical(world):
    through_api, from_disk = api("--json", "gate"), local(world, "--json", "gate")
    assert through_api.exit_code == from_disk.exit_code == 1                     # blocked by the A01 finding
    assert json.loads(through_api.stdout) == json.loads(from_disk.stdout) == {
        "passed": False, "exit_code": 1, "blocking_findings": [world["fid"]]}


def test_finding_and_evidence_are_identical_through_the_api(world):
    assert _json(api("--json", "findings", "show", world["fid"])) == _json(local(world, "--json", "findings", "show", world["fid"]))
    for extra in ([], ["--raw"]):
        through_api = _json(api("--json", "evidence", "show", world["ev"], *extra))
        assert through_api == _json(local(world, "--json", "evidence", "show", world["ev"], *extra))
        assert TOKEN not in json.dumps(through_api)          # the API sends the raw payload; the CLI redacts it


def test_reports_through_the_api(world, tmp_path):
    printed = api("report", "-f", "json", "-o", "-")
    assert printed.exit_code == 0 and json.loads(printed.stdout)["scan"]["id"] == world["scan"]
    target = tmp_path / "r.html"
    assert api("report", "-o", str(target)).exit_code == 0 and "<html" in target.read_text(encoding="utf-8").lower()
    assert api("report", "-f", "sarif").exit_code == errors.UNAVAILABLE


def test_tables_render_the_same_way(world):
    result = api("findings", "list")
    assert result.exit_code == 0 and world["fid"] in result.stdout and "highest risk first" in result.stdout


def test_errors_map_to_the_same_exit_codes(world):
    for args, code in ((["findings", "show", "F-9999"], errors.NOT_FOUND), (["scan", "status", "S-9999"], errors.NOT_FOUND),
                       (["evidence", "show", "E-9999"], errors.NOT_FOUND), (["findings", "show", "nope"], errors.USAGE)):
        assert api(*args).exit_code == code == local(world, *args).exit_code, args


def test_api_not_running():
    result = runner.invoke(app, ["--api", "http://127.0.0.1:9", "findings", "list"])
    assert result.exit_code == errors.UNAVAILABLE and "not running" in result.stderr
