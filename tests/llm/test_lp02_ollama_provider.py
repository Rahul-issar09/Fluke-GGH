"""LP2 — the Ollama provider builds today's client, lists models, reports health, classifies errors."""

from __future__ import annotations

import httpx
import pytest

from aegis.agent import llm
from aegis.config import ModelSettings
from aegis.llm.base import LlmError, LlmProvider, ProviderId
from aegis.llm.providers.ollama import OllamaProvider
from aegis.safety.model_host import ModelHostRefused

pytestmark = pytest.mark.phase("LP2")

TAGS = {"models": [
    {"name": "qwen2.5:7b", "details": {"context_length": 32768}, "capabilities": ["completion", "tools"]},
    {"name": "bge-m3:latest", "capabilities": ["embedding"]},
    {"name": "llama3:latest"},
]}


def _tags_transport(body=TAGS, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def _down(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


def test_is_a_provider():
    assert isinstance(OllamaProvider(ModelSettings()), LlmProvider)


@pytest.mark.parametrize("cfg", [
    ModelSettings(),
    ModelSettings(name="llama3", ollama_url="http://localhost:11434", temperature=0.3, num_ctx=4096),
])
def test_builds_exactly_the_client_make_llm_builds(cfg):
    provider = OllamaProvider(cfg)
    built = provider.chat_model(provider.snapshot())
    legacy = llm.make_llm(cfg)
    for attr in ("model", "base_url", "temperature", "num_ctx", "format"):
        assert getattr(built, attr) == getattr(legacy, attr), attr
    assert (built.model, built.base_url, built.temperature, built.num_ctx, built.format) == (
        cfg.name, cfg.ollama_url, cfg.temperature, cfg.num_ctx, "json")


def test_snapshot_is_local_and_carries_options():
    snap = OllamaProvider(ModelSettings(temperature=0.2, num_ctx=2048)).snapshot("llama3", generation=4)
    assert (snap.provider, snap.model, snap.location, snap.generation) == (ProviderId.ollama, "llama3", "local", 4)
    assert snap.options == {"temperature": 0.2, "num_ctx": 2048}


def test_structured_binds_the_schema_without_connecting():
    from aegis.chat.schemas import Answer

    provider = OllamaProvider(ModelSettings(ollama_url="http://127.0.0.1:9"))
    runnable = provider.structured(provider.snapshot(), Answer)
    assert hasattr(runnable, "ainvoke")


async def test_list_models():
    models = await OllamaProvider(ModelSettings(), transport=_tags_transport()).list_models()
    by_id = {m.id: m for m in models}
    assert list(by_id) == ["bge-m3:latest", "llama3:latest", "qwen2.5:7b"]
    assert by_id["qwen2.5:7b"].capabilities == {"generate"}
    assert by_id["qwen2.5:7b"].input_token_limit == 32768
    assert by_id["bge-m3:latest"].capabilities == {"embedding"}
    assert by_id["llama3:latest"].capabilities == frozenset()  # an older Ollama: unknown, not guessed


async def test_list_models_when_ollama_is_down():
    with pytest.raises(LlmError) as err:
        await OllamaProvider(ModelSettings(), transport=httpx.MockTransport(_down)).list_models()
    assert err.value.kind == "unavailable"


@pytest.mark.parametrize("model, present", [("qwen2.5:7b", True), ("llama3", True), ("mistral", False)])
async def test_health_matches_probe_ollama(model, present):
    provider = OllamaProvider(ModelSettings(), transport=_tags_transport())
    health = await provider.health(provider.snapshot(model))
    assert health.reachable is True and health.model_present is present
    assert health.detail["models"] == ["bge-m3:latest", "llama3:latest", "qwen2.5:7b"]


async def test_health_never_raises_when_down():
    provider = OllamaProvider(ModelSettings(), transport=httpx.MockTransport(_down))
    health = await provider.health(provider.snapshot())
    assert (health.reachable, health.model_present, health.error) == (False, False, "ConnectError")


async def test_validate():
    provider = OllamaProvider(ModelSettings(), transport=_tags_transport())
    assert (await provider.validate("qwen2.5:7b")).ok is True
    missing = await provider.validate("mistral")
    assert (missing.ok, missing.error_kind) == (False, "model_not_found")
    assert "ollama pull mistral" in missing.error


class _StatusError(Exception):
    def __init__(self, status_code):
        super().__init__(f"status {status_code}")
        self.status_code = status_code


@pytest.mark.parametrize("exc, kind, retryable", [
    (_StatusError(500), "unavailable", True),       # today's one quiet retry on 5xx
    (_StatusError(503), "unavailable", True),
    (_StatusError(404), "model_not_found", False),
    (_StatusError(400), "invalid_request", False),
    (httpx.ConnectError("refused"), "unavailable", False),   # "Ollama is down" is not retried today
    (ConnectionError("Failed to connect to Ollama"), "unavailable", False),
    (httpx.ReadTimeout("slow"), "timeout", False),
    (RuntimeError("?"), "unknown", False),
])
def test_classify_keeps_todays_retry_rule(exc, kind, retryable):
    err = OllamaProvider(ModelSettings()).classify(exc)
    assert (err.kind, err.retryable, err.provider) == (kind, retryable, "ollama")


def test_classify_real_ollama_client_error():
    from ollama import ResponseError

    err = OllamaProvider(ModelSettings()).classify(ResponseError("model runner crashed", 500))
    assert (err.kind, err.retryable) == ("unavailable", True)


def test_url_guard_is_available_but_not_applied_on_construction():
    OllamaProvider(ModelSettings(ollama_url="http://8.8.8.8:11434"))  # constructing never checks
    with pytest.raises(ModelHostRefused):
        OllamaProvider(ModelSettings(ollama_url="http://8.8.8.8:11434")).check_url()
    assert OllamaProvider(ModelSettings(ollama_url="http://127.0.0.1:11434")).check_url() == ["127.0.0.1"]
