"""Local (no-Docker) setup: a configurable callback listener and a clear model check at startup."""

from __future__ import annotations

import io
import asyncio
import json

import httpx
import pytest

from _graph_helpers import make_run
from aegis import observability as obs
from aegis.agent.nodes.prepare import prepare
from aegis.api.main import check_model
from aegis.api.routers import health as health_router
from aegis.config import AppSettings, ModelSettings
from aegis.evidence.models import Mode
from aegis.safety.test_inputs import TestInputLibrary, check_callback_url

pytestmark = pytest.mark.phase("AG13")


# --- the callback listener ------------------------------------------------------------------------ #
def test_the_probe_is_built_from_the_configured_listener():
    assert TestInputLibrary.load().resolve("SSRF-CB-001", "S-0001") == "http://callback:8080/hit/S-0001"  # Docker default
    local = TestInputLibrary.load(callback_url="http://127.0.0.1:8080/")
    assert local.resolve("SSRF-CB-001", "S-0007") == "http://127.0.0.1:8080/hit/S-0007"


@pytest.mark.parametrize(
    "bad", ["callback:8080", "ftp://x:21", "http://x:8080/hit/other", "http://x:8080?a=1", "http://user:pw@x:8080", "javascript:alert(1)", ""],
)
def test_only_a_bare_listener_address_is_accepted(bad):
    with pytest.raises(ValueError):
        check_callback_url(bad)


def test_the_configured_listener_is_always_on_the_scans_allowlist(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, default_allowlist=("127.0.0.1:5000",), callback_url="http://127.0.0.1:8080")
    asyncio.run(prepare(state, config))
    allowlist = json.loads(store.get_scan(scan_id).config_json)["allowlist"]
    assert allowlist == ["127.0.0.1:5000", "demo-app:5000", "127.0.0.1:8080"]   # configured, target, listener


def test_the_callback_url_setting_reads_the_environment(monkeypatch):
    from aegis.config import get_app_settings

    assert get_app_settings().callback_url == "http://callback:8080"
    monkeypatch.setenv("AEGIS_SAFETY__CALLBACK_URL", "http://127.0.0.1:8080")
    assert get_app_settings().callback_url == "http://127.0.0.1:8080"


# --- the model check at startup -------------------------------------------------------------------- #
@pytest.fixture
def logs():
    obs.reset_logging()
    stream = io.StringIO()
    obs.configure_logging(level="INFO", json=True, stream=stream)
    yield lambda: [json.loads(line) for line in stream.getvalue().splitlines() if line.startswith("{")]
    obs.reset_logging()


def _ollama_with(monkeypatch, names):
    def tags(request):
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    real = httpx.AsyncClient
    monkeypatch.setattr(health_router.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(tags), **kw))


async def test_a_missing_model_is_named_with_what_is_available(monkeypatch, logs):
    _ollama_with(monkeypatch, ["qwen2.5:7b-instruct-q4_K_M", "bge-m3:latest"])
    probe = await check_model(AppSettings(model=ModelSettings(name="qwen2.5:7b", ollama_url="http://localhost:11434")))
    assert probe["reachable"] is True and probe["model_present"] is False
    (warning,) = [r for r in logs() if r["event"] == "startup.model_missing"]
    assert warning["available"] == ["bge-m3:latest", "qwen2.5:7b-instruct-q4_K_M"] and "127.0.0.1" in warning["hint"]


async def test_a_present_model_is_confirmed(monkeypatch, logs):
    _ollama_with(monkeypatch, ["qwen2.5:7b"])
    await check_model(AppSettings(model=ModelSettings(name="qwen2.5:7b", ollama_url="http://127.0.0.1:11434")))
    assert [r["event"] for r in logs() if r["event"].startswith("startup.")] == ["startup.model_ok"]


async def test_an_unreachable_ollama_is_reported_and_startup_goes_on(logs):
    await check_model(AppSettings(model=ModelSettings(ollama_url="http://127.0.0.1:9")))
    (warning,) = [r for r in logs() if r["event"] == "startup.ollama_unreachable"]
    assert "templates" in warning["hint"]


# --- a one-off server error from the model --------------------------------------------------------- #
class ServerError(Exception):
    def __init__(self, status_code: int):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


async def _call(script, monkeypatch):
    from aegis.agent import llm as llm_module
    from aegis.agent.schemas import Target
    from fakes.fake_llm import FakeLLM

    monkeypatch.setattr(llm_module, "TRANSIENT_RETRY_DELAY_S", 0.0)
    fake = FakeLLM(script)
    result = await llm_module.structured_call(Target, "system", {"finding_id": "F-1"}, lambda out: [], llm=fake)
    return result, fake


async def test_a_one_off_server_error_is_retried_once(monkeypatch):
    from aegis.agent.schemas import Target

    (out, source), fake = await _call([ServerError(500), Target()], monkeypatch)
    assert source == "llm" and out == Target() and len(fake.calls) == 2


@pytest.mark.parametrize("script", [[ServerError(500), ServerError(500)], [ServerError(404)], [ConnectionError("down")]])
async def test_other_model_errors_are_not_retried_and_reach_the_caller(monkeypatch, script):
    with pytest.raises(Exception):
        await _call(script, monkeypatch)
