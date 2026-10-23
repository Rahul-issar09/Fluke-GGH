"""CLI04 — read commands: scans, findings, evidence, graph, CBOM (CLI_PHASES.md).

Each command runs on a seeded data folder through the real CLI, as a table and as ``--json``; the
JSON equals what the REST API's service returns; evidence never shows a credential; nothing is written.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.main import app
from aegis.cli.ui.views import risk_expression
from aegis.evidence.models import ScanStatus
from aegis.services.query_service import QueryService

pytestmark = pytest.mark.phase("CLI04")

runner = CliRunner()
TOKEN = "s3cr3t-session-token-value-0042"
SEV, EXPL, EXPO, CRIT, PATH = 0.9, 0.3, 0.6, 1.0, 0.8
RISK = round(SEV * 0.4 * (1 + EXPL + EXPO + CRIT + PATH) / 5, 3)   # candidate → confidence 0.4


@pytest.fixture
def world(store, tmp_path):
    old = store.add_scan(mode="code")
    store.update_scan(old.id, status=ScanStatus.completed)
    scan = store.add_scan(mode="correlated", target_url="http://127.0.0.1:5000").id
    hi = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                           file="app/routes/accounts.py", line=37, function="get_account", source="worker1.bola",
                           title="Broken object-level access control on GET /api/accounts/{id}")
    ev = store.add_evidence(scan, "http_exchange", "bola", finding_id=hi.id, payload={
        "method": "GET", "route": "/api/accounts/1", "status": 200, "identity": "B", "contains_owner_fields": True,
        "request": f"GET /api/accounts/1\nAuthorization: Bearer {TOKEN}\n", "session_token": TOKEN,
    })
    store.update_finding_fields(hi.id, severity=SEV, exploitability=EXPL, exposure=EXPO, criticality=CRIT,
                                path_factor=PATH, risk=RISK, what="Any account is returned by id.",
                                impact="A user can read another user's account.", exploit="Ask for another id.")
    lo = store.add_finding(scan, type="misconfig", owasp="A05", route="GET /docs", source="nuclei", title="Docs are public")
    store.add_evidence(scan, "http_exchange", "nuclei", finding_id=lo.id, payload={"method": "GET", "route": "/docs", "status": 200})
    store.update_finding_fields(lo.id, severity=0.4, risk=0.05, what="The API docs are public.")
    store.update_scan(scan, status=ScanStatus.completed)
    return {"dir": str(tmp_path), "scan": scan, "old": old.id, "hi": hi.id, "lo": lo.id, "ev": ev.id,
            "store": store, "db": tmp_path / "aegis.db"}


def run(world, *args):
    return runner.invoke(app, ["--local", "--data-dir", world["dir"], *args])


def as_json(world, *args):
    result = run(world, "--json", *args)
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)


# ------------------------------------------------------------------------------------------ scans
def test_scan_list_newest_first(world):
    data = as_json(world, "scan", "list")
    assert [s["id"] for s in data] == [world["scan"], world["old"]] and data[0]["findings"] == 2
    table = run(world, "scan", "list")
    assert table.exit_code == 0 and world["scan"] in table.stdout and "correlated" in table.stdout


def test_scan_status_defaults_to_the_latest_scan(world):
    data = as_json(world, "scan", "status")
    assert data["id"] == world["scan"] and data["status"] == "completed" and data["counts"]["findings"] == 2
    assert as_json(world, "scan", "status", world["old"])["id"] == world["old"]
    assert "Scan " + world["scan"] in run(world, "scan", "status").stdout


def test_scan_audit_summary_and_json(world):
    data = as_json(world, "scan", "audit")
    # "llm": which model the scan used and whether it could answer (LLM_PROVIDER_PHASES LP3)
    assert set(data) == {"scan_id", "llm", "tool_calls", "decisions", "transitions"} and data["scan_id"] == world["scan"]
    assert "Audit of " + world["scan"] in run(world, "scan", "audit").stdout


# ------------------------------------------------------------------------------------------ findings
def test_findings_list_is_ranked_and_matches_the_api_service(world):
    data = as_json(world, "findings", "list")
    assert [f["id"] for f in data] == [world["hi"], world["lo"]]
    direct = [f.model_dump(mode="json") for f in QueryService(world["store"], world["dir"]).list_findings(world["scan"])]
    assert data == direct                                    # same data the REST API returns


def test_findings_list_filters_and_limit(world):
    assert [f["id"] for f in as_json(world, "findings", "list", "--owasp", "a05")] == [world["lo"]]
    assert [f["id"] for f in as_json(world, "findings", "list", "--severity-min", "0.8")] == [world["hi"]]
    assert len(as_json(world, "findings", "list", "-n", "1")) == 1
    table = run(world, "findings", "list", "-n", "1")
    assert "1 of 2" in table.stdout
    assert run(world, "findings", "list", "--owasp", "XYZ").exit_code == errors.USAGE


def test_findings_show_explains_and_recomputes_the_risk(world):
    detail = as_json(world, "findings", "show", world["hi"].lower())       # ids are case-insensitive
    assert detail["id"] == world["hi"] and world["ev"] in detail["evidence_ids"]
    expr, recomputed = risk_expression(detail)
    assert recomputed == detail["risk"] == RISK
    text = run(world, "findings", "show", world["hi"]).stdout
    for part in ("What", "Impact", "Exploit", "Where", "Fix", "Risk", "Any account is returned by id."):
        assert part in text
    assert expr in text


# ------------------------------------------------------------------------------------------ evidence
def test_evidence_shows_a_digest_by_default(world):
    data = as_json(world, "evidence", "show", world["ev"])
    assert data["digest"].startswith(world["ev"]) and "payload" not in data
    assert TOKEN not in json.dumps(data) and TOKEN not in run(world, "evidence", "show", world["ev"]).stdout


def test_raw_evidence_is_still_redacted(world):
    data = as_json(world, "evidence", "show", world["ev"], "--raw")
    assert data["payload"]["route"] == "/api/accounts/1"
    assert TOKEN not in json.dumps(data)                    # neither the named field nor the header in the request
    assert TOKEN not in run(world, "evidence", "show", world["ev"], "--raw").stdout


# ------------------------------------------------------------------------------------------ graph / cbom
def test_graph_and_export(world, tmp_path):
    data = as_json(world, "graph")
    assert data["scan_id"] == world["scan"] and "attack_paths" in data
    target = tmp_path / "out" / "graph.json"
    result = run(world, "graph", "--export", str(target))
    assert result.exit_code == 0 and json.loads(target.read_text(encoding="utf-8"))["scan_id"] == world["scan"]
    assert "wrote" in result.stderr                          # notes go to stderr


def test_cbom_missing_then_present(world, tmp_path):
    from aegis.workers.crypto.cbom import cbom_path

    missing = run(world, "cbom")
    assert missing.exit_code == errors.NOT_FOUND and "no CBOM" in missing.stderr
    path = cbom_path(world["dir"], world["scan"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
        "type": "cryptographic-asset", "name": "MD5",
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
        "evidence": {"occurrences": [{"location": "app/auth.py", "line": 12}]},
        "properties": [{"name": "aegis:classical_risk", "value": "MD5 is broken"}, {"name": "aegis:quantum_risk", "value": "none"}],
    }]}), encoding="utf-8")
    table = run(world, "cbom")
    assert table.exit_code == 0 and "MD5" in table.stdout and "app/auth.py:12" in table.stdout
    assert as_json(world, "cbom")["components"][0]["name"] == "MD5"


# ------------------------------------------------------------------------------------------ errors
def test_unknown_and_malformed_ids(world):
    unknown = run(world, "findings", "show", "F-9999")
    assert unknown.exit_code == errors.NOT_FOUND and "unknown finding F-9999" in unknown.stderr
    bad = run(world, "findings", "show", "../etc")
    assert bad.exit_code == errors.USAGE and "'../etc'" in bad.output
    assert run(world, "scan", "status", "S-9999").exit_code == errors.NOT_FOUND
    assert run(world, "evidence", "show", "E-9999").exit_code == errors.NOT_FOUND


def test_missing_data_folder_and_no_scans(store, tmp_path):
    nowhere = runner.invoke(app, ["--local", "--data-dir", str(tmp_path / "nowhere"), "findings", "list"])
    assert nowhere.exit_code == errors.UNAVAILABLE and "no AEGIS data at" in nowhere.stderr
    empty = runner.invoke(app, ["--local", "--data-dir", str(tmp_path), "findings", "list"])     # aegis.db exists, no scans
    assert empty.exit_code == errors.NOT_FOUND and "no scans yet" in empty.stderr


# ------------------------------------------------------------------------------------------ read-only
def test_read_commands_never_change_the_database(world):
    before = hashlib.sha256(world["db"].read_bytes()).hexdigest()
    for args in (["scan", "list"], ["scan", "status"], ["scan", "audit"], ["findings", "list"],
                 ["findings", "show", world["hi"]], ["evidence", "show", world["ev"], "--raw"], ["graph"]):
        assert run(world, *args).exit_code == 0, args
    assert hashlib.sha256(world["db"].read_bytes()).hexdigest() == before
