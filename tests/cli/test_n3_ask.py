"""N3 — `aegis ask` and `aegis chat` through the API (cli_new_phases.md).

The API runs in-process with Ollama unreachable, so: counts/lists are answered from the findings (no
model), unrelated questions get "No finding matches." (scope gate), and "why" questions fall back to an
answer built from the findings themselves — always with real citations.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.main import app
from aegis.config import AppSettings, ModelSettings
from aegis.evidence.models import ScanStatus
from fakes import api_server

pytestmark = pytest.mark.phase("N3")

runner = CliRunner()


@pytest.fixture
def world(store, tmp_path, monkeypatch):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, source="w", title="Broken access control on accounts")
    ev = store.add_evidence(scan, "http_exchange", "bola", finding_id=f.id,
                            payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f.id, severity=0.9, risk=0.79,
                                what="The accounts endpoint returns any account by id without an ownership check.",
                                impact="A signed-in user can read another user's account balance.")
    low = store.add_finding(scan, type="misconfig", owasp="A05", route="GET /docs", source="w", title="API docs are public")
    store.update_finding_fields(low.id, severity=0.4, risk=0.05, what="The API documentation page is public.")
    store.update_scan(scan, status=ScanStatus.completed)
    stop = api_server.serve(monkeypatch, AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://127.0.0.1:9")))
    yield {"scan": scan, "fid": f.id, "ev": ev.id}
    stop()


def cli(*args, input=None):
    return runner.invoke(app, list(args), input=input)


def test_a_count_question_is_answered_from_the_findings(world):
    data = json.loads(cli("--json", "ask", "how many findings are there?").stdout)
    assert data["answer"].startswith("2 finding") and world["fid"] in data["finding_ids"]


def test_an_unrelated_question_gets_no_finding_matches(world):
    result = cli("ask", "what is k8s")
    assert result.exit_code == 0 and "aegis> No finding matches." in result.stdout


def test_a_why_question_is_answered_with_citations(world):
    result = cli("ask", "why is the accounts ownership check a risk?", "--scan", world["scan"])
    assert result.exit_code == 0, result.stderr
    assert "aegis> " in result.stdout and f"cited: {world['fid']}" in result.stdout
    assert "thinking" in result.stderr                            # the wait note goes to stderr


def test_ask_errors(world):
    assert cli("ask", "why?", "--scan", "S-9999").exit_code == errors.NOT_FOUND
    assert cli("ask", "   ").exit_code == errors.USAGE
    assert cli("--local", "ask", "why?").exit_code == errors.USAGE
    assert cli("--json", "chat").exit_code == errors.USAGE


def test_chat_session(world):
    script = "how many findings are there?\n/findings\n/scan S-9999\n/bogus\nwhat is k8s\n/quit\n"
    result = cli("chat", input=script)
    assert result.exit_code == 0, result.stderr
    out = result.stdout
    assert f"Ask about {world['scan']}" in out and "2 finding" in out
    assert world["fid"] in out                                    # /findings listed them
    assert "No finding matches." in out
    assert "unknown scan S-9999" in result.stderr and "unknown command /bogus" in result.stderr


def test_chat_ends_at_end_of_input(world):
    assert cli("chat", input="how many findings are there?\n").exit_code == 0
