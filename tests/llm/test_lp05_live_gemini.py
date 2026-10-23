"""LP5 — the real Gemini API (opt-in: ``-m gemini`` with ``AEGIS_TEST_GEMINI_API_KEY``; uses a little quota).

Discovery must return what the key can use (no list is hard-coded here either), and the first stable
model must pass validation, including every AEGIS schema (the deep probe).
"""

from __future__ import annotations

import os

import pytest

from aegis.config import AppSettings, LlmSettings
from aegis.llm.providers.gemini import GeminiProvider, installed
from aegis.llm.secrets import SecretRegistry, SecretStore

pytestmark = [
    pytest.mark.phase("LP5"),
    pytest.mark.gemini,
    pytest.mark.skipif(not installed(), reason="the gemini extra is not installed"),
    pytest.mark.skipif(not os.getenv("AEGIS_TEST_GEMINI_API_KEY"), reason="AEGIS_TEST_GEMINI_API_KEY is not set"),
]


@pytest.fixture
def key():
    return os.environ["AEGIS_TEST_GEMINI_API_KEY"]


def _provider() -> GeminiProvider:
    return GeminiProvider(AppSettings(llm=LlmSettings()), secrets=SecretStore({}, registry=SecretRegistry()))


async def test_live_discovery_and_deep_validation(key):
    provider = _provider()
    models = await provider.list_models(key)
    assert models, "the key can use no text-generation model"
    stable = [m for m in models if m.stage == "stable"]
    target = (stable or models)[0]
    result = await provider.validate(target.id, key, deep=True)
    assert result.ok, f"{target.id}: {result.error_kind}: {result.error}"
    assert "structured_output" in result.capabilities


async def test_live_wrong_key_is_reported(key):
    result = await _provider().validate("gemini-2.5-flash", "AIzaSy" + "0" * 33)
    assert result.error_kind == "invalid_api_key"
