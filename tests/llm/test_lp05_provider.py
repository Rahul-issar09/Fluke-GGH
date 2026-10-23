"""LP5 — the Gemini provider: how the client is built, its retry policy, validation and health."""

from __future__ import annotations

import os

import pytest
from pydantic import BaseModel

from aegis.config import AppSettings, LlmSettings, ModelSettings
from aegis.llm.base import LlmError, ProviderId
from aegis.llm.limiter import TokenBucket
from aegis.llm.manager import ProviderManager
from aegis.llm.providers.gemini import GeminiProvider, GuardedRunnable, installed
from aegis.llm.providers.gemini_errors import classify_gemini
from aegis.llm.providers.ollama import OllamaProvider
from aegis.llm.registry import ProviderRegistry
from aegis.llm.secrets import ENV_KEY, SecretRegistry, SecretStore
from aegis.llm.validation import Probe
from fakes.fake_gemini import KEY, FakeGeminiApi, error_body

pytestmark = [pytest.mark.phase("LP5"), pytest.mark.skipif(not installed(), reason="the gemini extra is not installed")]


class Out(BaseModel):
    ok: bool


class Script:
    """A structured runnable that returns or raises its items in order."""

    def __init__(self, *items):
        self.items = list(items)
        self.calls = 0

    async def ainvoke(self, messages):
        self.calls += 1
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class FakeChat:
    """Stands in for ChatGoogleGenerativeAI: records its arguments, serves a scripted runnable."""

    built: list[dict] = []

    def __init__(self, runnables):
        self.runnables = runnables

    def __call__(self, **kwargs):
        FakeChat.built.append(kwargs)
        outer = self

        class _Model:
            def with_structured_output(self, schema, method=None):
                assert method == "json_schema"
                return outer.runnables.pop(0)

        return _Model()


async def no_sleep(_s):
    return None


def provider(*runnables, environ=None, api=None, **llm) -> GeminiProvider:
    FakeChat.built = []
    settings = AppSettings(model=ModelSettings(temperature=0.1), llm=LlmSettings(gemini_model="gemini-2.5-flash", **llm))
    return GeminiProvider(settings, secrets=SecretStore(environ if environ is not None else {ENV_KEY: KEY},
                                                        registry=SecretRegistry()),
                          transport=(api or FakeGeminiApi()).transport, chat_factory=FakeChat(list(runnables)),
                          limiter=TokenBucket(6000, sleep=no_sleep), sleep=no_sleep)


def api_error(code: int, status: str, message: str, details=None):
    from google.genai.errors import ClientError, ServerError

    cls = ServerError if code >= 500 else ClientError
    return cls(code, error_body(code, status, message, details))


def wrapped(code: int, status: str, message: str, details=None):
    """How errors reach AEGIS from LangChain: ChatGoogleGenerativeAIError raised from the SDK's APIError."""
    from langchain_google_genai.chat_models import ChatGoogleGenerativeAIError

    try:
        raise api_error(code, status, message, details)
    except Exception as cause:  # noqa: BLE001
        try:
            raise ChatGoogleGenerativeAIError(f"Error calling model ({status})") from cause
        except ChatGoogleGenerativeAIError as exc:
            return exc


# ---------------------------------------------------------------- how the client is built
def test_the_client_gets_an_explicit_key_no_vertex_no_sdk_retries():
    p = provider(Script(Out(ok=True)))
    p.structured(p.snapshot(), Out)
    (kwargs,) = FakeChat.built
    assert kwargs["google_api_key"].get_secret_value() == KEY
    assert kwargs["vertexai"] is False and kwargs["max_retries"] == 0
    assert (kwargs["model"], kwargs["temperature"], kwargs["max_output_tokens"]) == ("gemini-2.5-flash", 0.1, 2048)
    assert "thinking_budget" not in kwargs                     # Q-7: the model's default


def test_a_thinking_budget_is_passed_when_set():
    p = provider(Script(Out(ok=True)), gemini_thinking_budget=0)
    p.structured(p.snapshot(), Out)
    assert FakeChat.built[0]["thinking_budget"] == 0


def test_the_real_sdk_client_ignores_the_environments_keys_and_vertex_switch(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "AIzaSyUNRELATED-env-key-0000000000000000")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    settings = AppSettings(llm=LlmSettings(gemini_model="gemini-2.5-flash"))
    p = GeminiProvider(settings, secrets=SecretStore({ENV_KEY: KEY}, registry=SecretRegistry()))
    before = dict(os.environ)
    client = p.chat_model(p.snapshot())                        # the real ChatGoogleGenerativeAI, built offline
    assert client.google_api_key.get_secret_value() == KEY
    assert client._use_vertexai is False
    assert dict(os.environ) == before                          # the key never went into the environment


def test_no_key_configured_is_a_config_error():
    p = provider(environ={})
    with pytest.raises(LlmError) as err:
        p.structured(p.snapshot(), Out)
    assert err.value.kind == "config_error"


def test_no_model_configured_is_a_config_error():
    settings = AppSettings(llm=LlmSettings())
    with pytest.raises(LlmError):
        GeminiProvider(settings, secrets=SecretStore({ENV_KEY: KEY})).snapshot()


# ---------------------------------------------------------------- the error taxonomy on SDK errors
@pytest.mark.parametrize("code, status, message, details, kind", [
    (400, "INVALID_ARGUMENT", "API key not valid. Please pass a valid API key.", [{"reason": "API_KEY_INVALID"}], "invalid_api_key"),
    (403, "PERMISSION_DENIED", "Your API key was reported as leaked. Please use another API key.", None, "invalid_api_key"),
    (404, "NOT_FOUND", "models/x is not found", None, "model_not_found"),
    (429, "RESOURCE_EXHAUSTED", "quota", [{"violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel"}]}], "quota_exhausted"),
    (400, "FAILED_PRECONDITION", "User location is not supported for the API use without a billing account linked.", None, "billing_required"),
    (500, "INTERNAL", "boom", None, "unavailable"),
    (400, "INVALID_ARGUMENT", "schema too deep", None, "invalid_request"),
])
def test_sdk_errors_are_classified_through_the_langchain_wrapper(code, status, message, details, kind):
    assert classify_gemini(wrapped(code, status, message, details)).kind == kind


def test_classified_messages_never_carry_the_key():
    err = classify_gemini(api_error(400, "INVALID_ARGUMENT", f"bad request for key {KEY}"))
    assert KEY not in str(err)


# ---------------------------------------------------------------- retries
async def test_a_rate_limit_is_retried_then_succeeds():
    p = provider()
    inner = Script(api_error(429, "RESOURCE_EXHAUSTED", "slow down",
                             [{"violations": [{"quotaId": "PerMinute"}]}, {"retryDelay": "3s"}]), Out(ok=True))
    slept: list[float] = []

    async def record(s):
        slept.append(s)

    guarded = GuardedRunnable(inner, TokenBucket(6000, sleep=no_sleep), p.classify, sleep=record)
    assert await guarded.ainvoke([]) == Out(ok=True)
    assert inner.calls == 2 and 3.0 <= slept[0] <= 3.5          # Google's retry delay, plus jitter


async def test_a_spent_quota_is_not_retried_and_leaves_as_a_final_error():
    p = provider()
    inner = Script(api_error(429, "RESOURCE_EXHAUSTED", "quota", [{"violations": [{"quotaId": "PerDay"}]}]))
    guarded = GuardedRunnable(inner, TokenBucket(6000, sleep=no_sleep), p.classify, sleep=no_sleep)
    with pytest.raises(LlmError) as err:
        await guarded.ainvoke([])
    assert (err.value.kind, err.value.retryable, inner.calls) == ("quota_exhausted", False, 1)


async def test_server_errors_are_retried_twice_then_given_up():
    p = provider()
    inner = Script(*[api_error(503, "UNAVAILABLE", "busy")] * 3)
    guarded = GuardedRunnable(inner, TokenBucket(6000, sleep=no_sleep), p.classify, sleep=no_sleep)
    with pytest.raises(LlmError) as err:
        await guarded.ainvoke([])
    assert (err.value.kind, err.value.retryable, inner.calls) == ("unavailable", False, 3)


async def test_an_answer_that_does_not_parse_is_left_to_structured_call():
    p = provider()
    guarded = GuardedRunnable(Script(ValueError("not JSON")), TokenBucket(6000, sleep=no_sleep), p.classify, sleep=no_sleep)
    with pytest.raises(ValueError):
        await guarded.ainvoke([])


async def test_every_attempt_takes_from_the_rate_budget():
    taken: list[float] = []

    class Counting(TokenBucket):
        async def acquire(self):
            taken.append(1)
            return 0.0

    p = provider()
    inner = Script(api_error(503, "UNAVAILABLE", "busy"), Out(ok=True))
    await GuardedRunnable(inner, Counting(60), p.classify, sleep=no_sleep).ainvoke([])
    assert len(taken) == 2


# ---------------------------------------------------------------- validation and health
async def test_validate_proves_structured_output():
    p = provider(Script(Probe(ok=True, echo="aegis")))
    result = await p.validate("gemini-2.5-flash", KEY)
    assert result.ok and result.capabilities == {"generate", "structured_output"} and result.warnings == ()


async def test_a_preview_model_validates_with_a_warning():
    p = provider(Script(Probe(ok=True, echo="aegis")))
    result = await p.validate("models/gemini-2.5-pro-preview-06-05", KEY)
    assert result.ok and "preview" in result.warnings[0]


@pytest.mark.parametrize("model, credential, kind", [
    ("gemini-9", KEY, "model_not_found"),
    ("gemini-2.5-flash", "AIzaSyWRONG-key-000000000000000000000000", "invalid_api_key"),
    ("gemini-embedding-001", KEY, "invalid_request"),          # exists, but cannot generate text
    ("gemini-2.5-flash", "short", "invalid_api_key"),           # refused before any request
])
async def test_validate_reports_clear_failures_and_never_raises(model, credential, kind):
    result = await provider(Script(Probe(ok=True, echo="aegis"))).validate(model, credential)
    assert (result.ok, result.error_kind) == (False, kind) and result.error


async def test_a_model_that_ignores_the_schema_fails_validation():
    result = await provider(Script(ValueError("free text"))).validate("gemini-2.5-flash", KEY)
    assert (result.ok, result.error_kind) == (False, "invalid_request")


async def test_deep_validation_names_the_schemas_that_fail():
    from aegis.agent.schemas import Explanation, NextStepDecision, NextStep
    from aegis.chat.schemas import Answer

    ok_runs = [Script(Probe(ok=True, echo="aegis")),
               Script(NextStepDecision(finding_id="F-0001", next_step=NextStep.mark_sufficient, reason_evidence_ids=["E-0001"])),
               Script(Explanation(finding_id="F-0001", claims=[])),
               Script(ValueError("cannot produce FixEdit")),
               Script(Answer(text="ok"))]
    result = await provider(*ok_runs).validate("gemini-2.5-flash", KEY, deep=True)
    assert (result.ok, result.error_kind) == (False, "invalid_request") and "remediate" in result.error


async def test_health_is_a_cached_lookup():
    api = FakeGeminiApi()
    p = provider(api=api)
    first = await p.health(p.snapshot())
    second = await p.health(p.snapshot())
    assert first.reachable and first.model_present and first == second and len(api.requests) == 1


async def test_health_without_a_key_explains_itself():
    p = provider(environ={})
    h = await p.health(p.snapshot())
    assert (h.reachable, h.model_present, h.error) == (False, False, "config_error")


# ---------------------------------------------------------------- the manager remembers a validation once
def _manager(settings, tmp_path, gem) -> ProviderManager:
    registry = ProviderRegistry(settings, {ProviderId.gemini: lambda _s: gem,
                                           ProviderId.ollama: lambda s: OllamaProvider(s.model)})
    return ProviderManager(settings, tmp_path, environ={}, registry=registry)


async def test_a_validation_can_be_used_once_and_holds_the_key_in_memory_only(tmp_path):
    gem = provider(Script(Probe(ok=True, echo="aegis")))
    settings = AppSettings(data_dir=str(tmp_path))
    mgr = _manager(settings, tmp_path, gem)
    result, vid = await mgr.validate(ProviderId.gemini, "gemini-2.5-flash", KEY)
    assert result.ok and vid
    entry = mgr.validations.consume(vid)
    assert entry.model == "gemini-2.5-flash" and entry.key.get_secret_value() == KEY and KEY not in repr(entry)
    assert mgr.validations.consume(vid) is None               # single use
    assert list(tmp_path.iterdir()) == []                     # nothing written


async def test_a_failed_validation_leaves_nothing(tmp_path):
    gem = provider(Script(Probe(ok=True, echo="aegis")))
    settings = AppSettings(data_dir=str(tmp_path))
    mgr = _manager(settings, tmp_path, gem)
    result, vid = await mgr.validate(ProviderId.gemini, "gemini-9", KEY)
    assert not result.ok and vid is None


def test_validation_ids_expire():
    from aegis.llm.validation import ValidationCache

    now = [0.0]
    cache = ValidationCache(ttl_s=10, clock=lambda: now[0])
    vid = cache.put("gemini", "m", KEY, frozenset())
    now[0] = 11
    assert cache.consume(vid) is None


# ---------------------------------------------------------------- schemas (A-2), offline
@pytest.mark.parametrize("schema_path", [
    "aegis.agent.schemas:NextStepDecision", "aegis.agent.schemas:Explanation",
    "aegis.fix.draft:FixEdit", "aegis.chat.schemas:Answer",
])
def test_every_aegis_schema_binds_to_the_real_gemini_client(schema_path):
    import importlib

    module, name = schema_path.split(":")
    schema = getattr(importlib.import_module(module), name)
    settings = AppSettings(llm=LlmSettings(gemini_model="gemini-2.5-flash"))
    p = GeminiProvider(settings, secrets=SecretStore({ENV_KEY: KEY}, registry=SecretRegistry()))
    runnable = p.structured(p.snapshot(), schema)              # builds the real client and binds the schema
    assert isinstance(runnable, GuardedRunnable) and hasattr(runnable.inner, "ainvoke")
