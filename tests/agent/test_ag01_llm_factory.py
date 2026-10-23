"""AG01.1 — ChatOllama factory tests (offline; construction only)."""

from __future__ import annotations

import pytest

from aegis.agent import llm
from aegis.config import ModelSettings

pytestmark = pytest.mark.phase("AG01")


def test_factory_uses_config():
    cfg = ModelSettings(
        name="llama3", ollama_url="http://localhost:11434", temperature=0.1, num_ctx=4096
    )
    client = llm.make_llm(cfg)
    assert client.model == "llama3"
    assert client.base_url == "http://localhost:11434"
    assert client.num_ctx == 4096
    assert client.format == "json"


def test_temperature_is_0_1_by_default():
    client = llm.make_llm(ModelSettings())
    assert client.temperature == 0.1
    assert client.model == "qwen2.5:7b"
    assert client.num_ctx == 8192


def test_env_overrides_model_and_url(monkeypatch):
    monkeypatch.setenv("AEGIS_MODEL", "mistral")
    monkeypatch.setenv("AEGIS_OLLAMA_URL", "http://ollama-host:11434")
    client = llm.make_llm()  # reads settings from env
    assert client.model == "mistral"
    assert client.base_url == "http://ollama-host:11434"


def test_construction_opens_no_connection():
    # Must be safe to build under the offline guard — no socket on construct.
    llm.make_llm(ModelSettings())
