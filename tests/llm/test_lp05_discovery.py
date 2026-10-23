"""LP5 — Gemini model discovery: no hard-coded list, header auth, pinned host, capability filters."""

from __future__ import annotations

import httpx
import pytest

from aegis.config import AppSettings, LlmSettings
from aegis.llm.base import LlmError
from aegis.llm.providers import gemini_rest
from aegis.llm.providers.gemini import GeminiProvider
from aegis.llm.secrets import SecretStore
from fakes.fake_gemini import EXPECTED_IDS, KEY, FakeGeminiApi, error_body

pytestmark = pytest.mark.phase("LP5")


async def test_lists_only_text_generation_models_stable_first():
    api = FakeGeminiApi()
    models = await gemini_rest.list_models(KEY, transport=api.transport)
    assert [m.id for m in models] == EXPECTED_IDS
    by_id = {m.id: m for m in models}
    assert by_id["gemini-2.5-flash"].stage == "stable" and by_id["gemini-2.5-flash"].thinking is True
    assert by_id["gemini-2.5-pro-preview-06-05"].stage == "preview"
    assert by_id["gemini-exp-1206"].stage == "experimental"
    assert by_id["gemini-2.5-flash"].input_token_limit == 1048576
    assert all(m.capabilities == {"generate"} for m in models)   # structured output only after a probe


async def test_follows_pagination_and_sends_the_key_only_in_the_header():
    api = FakeGeminiApi()
    await gemini_rest.list_models(KEY, transport=api.transport)
    assert [r.url.params.get("pageToken") for r in api.requests] == [None, "p2"]
    assert all(r.headers["x-goog-api-key"] == KEY for r in api.requests)   # FakeGeminiApi asserts it is not in a URL


async def test_the_deny_list_is_configurable():
    api = FakeGeminiApi()
    models = await gemini_rest.list_models(KEY, transport=api.transport, exclude=("gemma", "exp"))
    ids = [m.id for m in models]
    assert "gemma-3-27b-it" not in ids and "gemini-exp-1206" not in ids
    assert "gemini-2.5-flash-image" in ids    # the defaults no longer apply


async def test_only_the_gemini_host_can_be_reached():
    transport = gemini_rest.PinnedHostTransport(httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(LlmError, match="only generativelanguage.googleapis.com"):
            await client.get("https://evil.example.com/v1beta/models")
        with pytest.raises(LlmError):
            await client.get("http://generativelanguage.googleapis.com/v1beta/models")   # not https


@pytest.mark.parametrize("model, expected", [("models/gemini-2.5-flash", "gemini-2.5-flash"), ("gemini-x", "gemini-x")])
def test_model_ids_are_normalized(model, expected):
    assert gemini_rest.normalize_model_id(model) == expected


@pytest.mark.parametrize("bad", ["../../etc", "gemini x", "a/b", "", "x" * 200])
def test_odd_model_ids_are_refused(bad):
    with pytest.raises(LlmError):
        gemini_rest.normalize_model_id(bad)


@pytest.mark.parametrize("status, body, kind, retryable", [
    (400, error_body(400, "INVALID_ARGUMENT", "API key not valid. Please pass a valid API key.",
                     [{"reason": "API_KEY_INVALID"}]), "invalid_api_key", False),
    (401, error_body(401, "UNAUTHENTICATED", "missing key"), "invalid_api_key", False),
    (403, error_body(403, "PERMISSION_DENIED", "denied"), "permission_denied", False),
    (429, error_body(429, "RESOURCE_EXHAUSTED", "You exceeded your current quota",
                     [{"violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}]),
     "quota_exhausted", False),
    (429, error_body(429, "RESOURCE_EXHAUSTED", "You exceeded your current quota",
                     [{"violations": [{"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"}]},
                      {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "17s"}]),
     "rate_limited", True),
    (503, error_body(503, "UNAVAILABLE", "overloaded"), "unavailable", True),
])
async def test_api_errors_are_classified(status, body, kind, retryable):
    with pytest.raises(LlmError) as err:
        await gemini_rest.list_models(KEY, transport=FakeGeminiApi(fail=(status, body)).transport)
    assert (err.value.kind, err.value.retryable, err.value.status_code) == (kind, retryable, status)
    if kind == "rate_limited":
        assert err.value.retry_after == 17.0


async def test_a_wrong_key_is_reported_as_invalid():
    with pytest.raises(LlmError) as err:
        await gemini_rest.list_models("AIzaSyWRONG-key-000000000000000000000000", transport=FakeGeminiApi().transport)
    assert err.value.kind == "invalid_api_key"


async def test_unknown_model_lookup():
    with pytest.raises(LlmError) as err:
        await gemini_rest.get_model(KEY, "gemini-9", transport=FakeGeminiApi().transport)
    assert err.value.kind == "model_not_found"


async def test_the_provider_caches_discovery_per_key():
    api = FakeGeminiApi()
    settings = AppSettings(llm=LlmSettings(gemini_exclude=None))
    provider = GeminiProvider(settings, secrets=SecretStore(environ={}), transport=api.transport)
    first = await provider.list_models(KEY)
    second = await provider.list_models(KEY)
    assert first == second and len(api.requests) == 2          # two pages, fetched once
    with pytest.raises(LlmError):
        await provider.list_models("AIzaSyOTHER-key-00000000000000000000000")   # a different key is not served from cache
