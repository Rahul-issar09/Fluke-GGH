"""N0 — `aegis doctor` and the API client (cli_new_phases.md).

The CLI talks to the API over HTTP; in tests the "server" is the real FastAPI app run in-process by
``TestClient`` (no network). Covers: doctor against a healthy API, an API that is not running, an API
that needs a token, the address precedence, and HTTP status → exit code.
"""

from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from aegis.cli import errors, remote
from aegis.cli.main import app
from aegis.config import ApiSettings, AppSettings, ModelSettings
from fakes import api_server

pytestmark = pytest.mark.phase("N0")

runner = CliRunner()
DOWN = "http://127.0.0.1:9"          # nothing listens here


@pytest.fixture
def serve(tmp_path, monkeypatch):
    """Start the real API in-process (``fakes.api_server``); returns a starter taking ApiSettings fields."""
    stops = []

    def start(**api) -> None:
        settings = AppSettings(data_dir=str(tmp_path / "data"), model=ModelSettings(ollama_url=DOWN), api=ApiSettings(**api))
        stops.append(api_server.serve(monkeypatch, settings))

    yield start
    for stop in stops:
        stop()


def test_doctor_reports_a_healthy_api(serve):
    serve()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stderr
    assert "AEGIS doctor" in result.stdout and "Database" in result.stdout
    assert "not reachable" in result.stdout                  # Ollama is down in this test: reported, not fatal
    data = json.loads(runner.invoke(app, ["--json", "doctor"]).stdout)
    assert data["reachable"] is True and data["health"]["status"] == "ok" and data["api"] == remote.DEFAULT_API


def test_doctor_when_the_api_is_not_running():
    result = runner.invoke(app, ["--api", DOWN, "doctor"])
    assert result.exit_code == errors.UNAVAILABLE
    assert f"AEGIS API is not running at {DOWN}" in result.stderr and "run_local.cmd" in result.stderr


def test_a_token_protected_api(serve):
    serve(auth_token="s3cret-token")
    refused = runner.invoke(app, ["doctor"])
    assert refused.exit_code == errors.UNAVAILABLE and "--token" in refused.stderr
    assert runner.invoke(app, ["--token", "s3cret-token", "doctor"]).exit_code == 0
    assert "s3cret-token" not in refused.stderr                # never echoed


def test_api_address_precedence(monkeypatch):
    monkeypatch.delenv("AEGIS_API_URL", raising=False)
    assert remote.api_url() == "http://127.0.0.1:8000"
    monkeypatch.setenv("AEGIS_API_URL", "http://10.0.0.5:8000/")
    assert remote.api_url() == "http://10.0.0.5:8000"
    assert remote.api_url("http://192.168.1.9:9000") == "http://192.168.1.9:9000"


@pytest.mark.parametrize("status, code", [(404, errors.NOT_FOUND), (409, errors.CONFLICT), (422, errors.USAGE),
                                          (413, errors.USAGE), (501, errors.UNAVAILABLE), (500, errors.FAILED)])
def test_http_status_maps_to_exit_code_with_the_api_reason(status, code):
    client = remote.ApiClient("http://x", client=httpx.Client())
    response = httpx.Response(status, json={"error": "e", "detail": "folder is outside the allowed source roots"})
    with pytest.raises(errors.CliError) as err:
        client.raise_for_status(response)
    assert err.value.code == code and "folder is outside the allowed source roots" in str(err.value)
