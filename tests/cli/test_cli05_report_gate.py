"""CLI05 — reports and the CI gate (CLI_PHASES.md).

The gate's verdict is the process exit code (0 clean · 1 blocking · 2 not complete) and equals the
REST API's; reports follow the API's rules (stored file, else built on demand for a finished scan;
a running scan has none; SARIF not built yet) and can be written, printed or opened.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.commands import report as report_cmd
from aegis.cli.main import app
from aegis.config import AppSettings
from aegis.evidence.models import ScanStatus
from aegis.services.report_service import report_paths, write_reports
from aegis.services.scan_service import ScanService

pytestmark = pytest.mark.phase("CLI05")

runner = CliRunner()


@pytest.fixture
def world(store, tmp_path):
    done = store.add_scan(mode="correlated").id
    f = store.add_finding(done, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}", source="w",
                          title="Broken object-level access control")
    store.add_evidence(done, "http_exchange", "bola", finding_id=f.id, payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f.id, severity=0.9, risk=0.79, what="Any account by id.")
    low = store.add_finding(done, type="misconfig", owasp="A05", route="GET /docs", source="w")
    store.update_finding_fields(low.id, severity=0.4, risk=0.9)          # high risk, but A05 is not a blocking category
    store.update_scan(done, status=ScanStatus.completed)
    running = store.add_scan(mode="code").id
    store.update_scan(running, status=ScanStatus.running)
    return {"dir": str(tmp_path), "done": done, "running": running, "fid": f.id, "store": store}


def run(world, *args):
    return runner.invoke(app, ["--local", "--data-dir", world["dir"], *args])


# ------------------------------------------------------------------------------------------ gate
def test_gate_blocks_with_exit_1_and_lists_the_blocking_findings(world):
    result = run(world, "gate", world["done"])
    assert result.exit_code == 1 and "BLOCKED" in result.stdout and world["fid"] in result.stdout
    data = json.loads(run(world, "--json", "gate", world["done"]).stdout)
    assert data == {"passed": False, "exit_code": 1, "blocking_findings": [world["fid"]]}


def test_gate_equals_the_api_verdict(world):
    api = ScanService(world["store"], None, None, AppSettings(data_dir=world["dir"])).gate(world["done"])
    cli = json.loads(run(world, "--json", "gate", world["done"]).stdout)
    assert cli == api.model_dump(mode="json")


def test_gate_threshold_and_a_clean_verdict(world):
    result = run(world, "gate", world["done"], "--threshold", "0.8")
    assert result.exit_code == 0 and "PASSED" in result.stdout


def test_gate_on_an_unfinished_scan_exits_2(world):
    result = run(world, "gate", world["running"])
    assert result.exit_code == 2 and "NOT COMPLETE" in result.stdout


def test_gate_on_an_unknown_scan_is_not_found(world):
    assert run(world, "gate", "S-9999").exit_code == errors.NOT_FOUND


# ------------------------------------------------------------------------------------------ report
def test_report_uses_the_stored_file(world):
    write_reports(world["store"], world["done"], world["dir"])
    stored = report_paths(world["dir"], world["done"])["html"]
    info = json.loads(run(world, "--json", "report", world["done"]).stdout)
    assert info["path"] == str(stored) and info["format"] == "html" and info["bytes"] == stored.stat().st_size


def test_report_is_built_on_demand_into_the_current_folder(world, tmp_path, monkeypatch):
    here = tmp_path / "here"
    here.mkdir()
    monkeypatch.chdir(here)
    result = run(world, "report", world["done"])
    target = here / f"aegis-{world['done']}.html"
    assert result.exit_code == 0 and target.is_file() and "<html" in target.read_text(encoding="utf-8").lower()


def test_report_to_a_file_and_to_stdout(world, tmp_path):
    target = tmp_path / "out" / "r.json"
    assert run(world, "report", world["done"], "-f", "json", "-o", str(target)).exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["scan"]["id"] == world["done"]
    printed = run(world, "report", world["done"], "-f", "json", "-o", "-")
    assert printed.exit_code == 0 and json.loads(printed.stdout)["scan"]["id"] == world["done"]


def test_report_rules_match_the_api(world):
    assert run(world, "report", world["running"]).exit_code == errors.CONFLICT           # not finished
    assert run(world, "report", world["done"], "-f", "cbom").exit_code == errors.CONFLICT  # no CBOM
    sarif = run(world, "report", world["done"], "-f", "sarif")
    assert sarif.exit_code == errors.UNAVAILABLE and "not built yet" in sarif.stderr
    assert run(world, "--json", "report", world["done"], "-o", "-").exit_code == errors.USAGE


def test_report_open_opens_the_file(world, monkeypatch):
    write_reports(world["store"], world["done"], world["dir"])
    opened = []
    monkeypatch.setattr(report_cmd.webbrowser, "open", lambda uri: opened.append(uri))
    assert run(world, "report", world["done"], "--open").exit_code == 0
    assert opened and opened[0].startswith("file:") and opened[0].endswith("report.html")
