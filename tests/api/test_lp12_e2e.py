"""LP12 — end to end, over HTTP, with a real Mode 3 scan of the demo app (in-process network).

Default suite (fakes for the model):
* going offline in the middle of an online scan stops cloud calls at once — the scan finishes on
  rules and templates, with exactly one cloud call and no silent switch to the local model;
* the API, the CLI and the MCP server report the same model configuration.

Opt-in, against real models:
* ``-m ollama``: the whole flow with the real local model; only this machine is contacted (the network
  guard) and no Google SDK is imported;
* ``-m gemini``: the whole flow with real Gemini (``AEGIS_TEST_GEMINI_API_KEY``); the key ends up in
  no file.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from aegis.api.main import create_app
from aegis.config import ModelSettings
from aegis.llm.base import ProviderId
from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput
from fakes import api_server
from fakes.fake_provider import FakeGemini, FakeProvider, TEST_KEY, manager_with, memory_secrets
from test_ag13_routes import demo, events, mode3_body  # noqa: F401  (demo is a fixture)

pytestmark = pytest.mark.phase("LP12")

LOCAL = dict(base_url="http://127.0.0.1:8000", raise_server_exceptions=False)
SDK_MODULES = ("google.genai", "langchain_google_genai")


def run_scan(c: TestClient, body: dict) -> dict:
    started = c.post("/api/scans", json=body)
    assert started.status_code == 202, started.text
    scan_id = started.json()["scan_id"]
    stream = events(c, scan_id)
    assert stream[-1]["status"] == "completed", stream[-1]
    return {"scan_id": scan_id, "audit": c.get(f"/api/scans/{scan_id}/audit").json()}


async def online(mgr, model="gemini-2.5-flash", key=None, **consent):
    _, vid = await mgr.validate(ProviderId.gemini, model, key)
    await mgr.activate(ProviderId.gemini, model, validation_id=vid, actor="ui",
                       consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True, **consent))


# ---------------------------------------------------------------- switching in the middle of a scan
async def test_going_offline_mid_scan_stops_cloud_calls_at_once(demo):  # noqa: F811
    data = Path(demo["settings"].data_dir)

    class GoesOfflineOnFirstCall:
        calls = 0

        async def ainvoke(self, messages):
            GoesOfflineOnFirstCall.calls += 1
            if GoesOfflineOnFirstCall.calls == 1:
                await mgr.go_offline(actor="ui")      # the user clicks "Go offline now" during the scan
            raise ValueError("not JSON")

    local = FakeProvider([])                           # would fail the test if it were called (empty script)
    cloud = FakeGemini(TEST_KEY)
    cloud.runnable = GoesOfflineOnFirstCall()
    mgr = manager_with(data, local, cloud)
    await online(mgr)
    overrides = {k: v for k, v in demo["overrides"].items() if k != "llm"} | {"llm_manager": mgr}
    with TestClient(create_app(demo["settings"], agent_overrides=overrides), **LOCAL) as c:
        result = run_scan(c, mode3_body(demo))

    assert GoesOfflineOnFirstCall.calls == 1                       # the retry and every later call stayed home
    assert local.used == []                                         # and nothing was silently re-routed locally
    llm = result["audit"]["llm"]
    assert (llm["provider"], llm["location"]) == ("gemini", "cloud")   # the scan was pinned to the cloud model…
    revoked = [d for d in result["audit"]["decisions"] if (d["error"] or "").endswith("revoked")]
    assert revoked                                                   # …and was cut off from it
    assert not (data / "config" / "llm.json").read_text(encoding="utf-8").count('"consent": {')


# ---------------------------------------------------------------- one configuration, three interfaces
async def test_api_cli_and_mcp_agree(store, tmp_path, monkeypatch):
    from mcp import Client

    from aegis.cli.main import app as cli
    from aegis.config import AppSettings
    from aegis.mcp.server import build_mcp
    from aegis.config import McpSettings
    from aegis.services.read_services import build_read_services

    settings = AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://127.0.0.1:9"))
    mgr = manager_with(tmp_path, FakeProvider(), FakeGemini(TEST_KEY), secrets=memory_secrets(None))
    stop = api_server.serve(monkeypatch, settings, agent_overrides={"llm_manager": mgr})
    runner = CliRunner()

    async def views() -> tuple[dict, dict, dict]:
        api = json.loads(runner.invoke(cli, ["--json", "llm", "status"]).stdout)   # the API's own JSON
        mcp_server = build_mcp(build_read_services(settings), McpSettings(audit_path=str(tmp_path / "mcp.jsonl")))
        async with Client(mcp_server) as c:
            mcp = (await c.call_tool("llm_status", {})).structured_content
        return api, mgr.status(), mcp

    try:
        assert runner.invoke(cli, ["llm", "offline", "--model", "llama3"]).exit_code == 0
        api, core, mcp = await views()
        assert (api["provider"], api["model"], api["location"]) == (core["provider"], core["model"], core["location"]) \
            == (mcp["provider"], mcp["model"], mcp["location"]) == ("ollama", "llama3", "local")

        result = runner.invoke(cli, ["llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-env", "K",
                                     "--accept-cloud-disclosure", DISCLOSURE_VERSION], env={"K": TEST_KEY})
        assert result.exit_code == 0, result.stderr
        api, core, mcp = await views()
        assert (api["provider"], api["model"], api["location"]) == ("gemini", "gemini-2.5-flash", "cloud") \
            == (core["provider"], core["model"], core["location"])
        # the MCP process never has the key typed into the app (asked every run): it says so, and agrees
        # on what is chosen
        assert (mcp["online_model"], mcp["online_chosen_but_inactive"], mcp["location"]) == ("gemini-2.5-flash", True, "local")
    finally:
        stop()


# ---------------------------------------------------------------- the real models (opt-in)
@pytest.mark.ollama
def test_offline_end_to_end_with_the_real_local_model(demo):  # noqa: F811
    url = os.getenv("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434")
    settings = demo["settings"].__class__(**{**demo["settings"].__dict__, "model": ModelSettings(ollama_url=url)})
    overrides = {k: v for k, v in demo["overrides"].items() if k != "llm"}   # the real model answers
    before = set(sys.modules)
    with TestClient(create_app(settings, agent_overrides=overrides), **LOCAL) as c:
        result = run_scan(c, mode3_body(demo))
        answer = c.post("/api/ask", json={"scan_id": result["scan_id"],
                                          "question": "why is the access control on accounts a risk?"}, timeout=300)
    llm = result["audit"]["llm"]
    assert (llm["provider"], llm["location"]) == ("ollama", "local") and llm["answered"] > 0, llm
    assert answer.status_code == 200 and answer.json()["finding_ids"]
    assert not [m for m in set(sys.modules) - before if m.startswith(SDK_MODULES)]   # no cloud SDK touched
    # (only this machine was contacted: the autouse network guard fails the test otherwise)


@pytest.mark.gemini
@pytest.mark.skipif(not os.getenv("AEGIS_TEST_GEMINI_API_KEY"), reason="AEGIS_TEST_GEMINI_API_KEY is not set")
async def test_online_end_to_end_with_real_gemini(demo):  # noqa: F811
    from aegis.llm.manager import ProviderManager

    key = os.environ["AEGIS_TEST_GEMINI_API_KEY"]
    data = Path(demo["settings"].data_dir)
    mgr = ProviderManager(demo["settings"], data, environ={}, secrets=memory_secrets(None))
    model = next(m for m in await mgr.list_models(ProviderId.gemini, key) if m.stage == "stable").id
    await online(mgr, model=model, key=key)
    overrides = {k: v for k, v in demo["overrides"].items() if k != "llm"} | {"llm_manager": mgr}
    with TestClient(create_app(demo["settings"], agent_overrides=overrides), **LOCAL) as c:
        result = run_scan(c, mode3_body(demo))
    llm = result["audit"]["llm"]
    assert (llm["provider"], llm["model"], llm["location"]) == ("gemini", model, "cloud") and llm["answered"] > 0, llm
    assert [p for p in data.rglob("*") if p.is_file() and key.encode() in p.read_bytes()] == []
    await mgr.go_offline(actor="ui")
