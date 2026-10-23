"""The Google Gemini provider (LLM_PROVIDER_PHASES LP5; optional ``gemini`` extra).

Generation uses ``langchain_google_genai.ChatGoogleGenerativeAI`` with schema-constrained output
(``method="json_schema"`` → Gemini's ``response_json_schema``) — the same contract as the Ollama
provider, so nodes and chat do not know which one answers. Settings that matter for safety:

* ``google_api_key`` is always passed **explicitly**; ``GOOGLE_API_KEY`` / ``GEMINI_API_KEY`` in the
  environment are never relied on (G-5).
* ``vertexai=False`` always: the SDK's Vertex AI branch would copy the key into ``os.environ``
  (and from there into every scanner subprocess AEGIS starts); the Developer API branch does not.
  ``GOOGLE_GENAI_USE_VERTEXAI`` in the environment can therefore never switch it on.
* ``max_retries=0`` on the client: AEGIS's own policy (:class:`GuardedRunnable`) is the only one,
  so every attempt is rate-limited, counted and classified once.

Model discovery, health and validation use AEGIS's own REST client (``gemini_rest``): header auth,
pinned host, no SDK. Nothing here imports the SDK until a model is actually built.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, SecretStr

from aegis.config import AppSettings
from aegis.llm.base import LlmError, LlmSnapshot, ModelInfo, ProviderHealth, ProviderId, ValidationResult
from aegis.llm.limiter import TokenBucket
from aegis.llm.providers import gemini_rest
from aegis.llm.providers.gemini_errors import classify_gemini
from aegis.llm.secrets import REGISTRY, SecretStore, check_key_shape, fingerprint
from aegis.llm.validation import Probe, run_deep_probe, run_probe
from aegis.observability import get_logger

__all__ = ["GeminiProvider", "GuardedRunnable", "installed"]

log = get_logger("llm.gemini")

MODELS_TTL_S = 600.0
HEALTH_TTL_S = 60.0

# LP11: always this host. Passed explicitly because the SDK otherwise honours GOOGLE_GEMINI_BASE_URL,
# which would send every request — the API key header included — wherever that variable points.
API_BASE_URL = f"https://{gemini_rest.API_HOST}/"
# LP11: these switch the SDK to its test client, which writes request and response bodies (findings,
# source excerpts) to disk ("record") or answers from files instead of Gemini ("replay"). They cannot
# be overridden through LangChain, so AEGIS refuses to build a client while they are set.
UNSAFE_SDK_ENV = ("GOOGLE_GENAI_CLIENT_MODE", "GOOGLE_GENAI_REPLAYS_DIRECTORY", "GOOGLE_GENAI_REPLAY_ID")


def check_sdk_environment(environ=None) -> None:
    """Raise ``config_error`` if the environment would change where Gemini traffic goes or is kept."""
    import os

    env = os.environ if environ is None else environ
    found = [name for name in UNSAFE_SDK_ENV if (env.get(name) or "").strip()]
    if found:
        raise LlmError("config_error", f"refusing to use Gemini while {', '.join(found)} is set: it makes the Google "
                                       "SDK record or replay requests instead of sending them only to Google",
                       provider="gemini")


def installed() -> bool:
    """Is the optional SDK importable? (Checked without importing it.)"""
    import importlib.util

    return importlib.util.find_spec("langchain_google_genai") is not None


def _default_chat_factory(**kwargs: Any) -> Any:
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(**kwargs)


class GuardedRunnable:
    """Rate budget + Gemini's retry policy around a structured runnable.

    A provider failure leaves as a classified, non-retryable :class:`LlmError` (its retries are
    already spent). Anything that is not a provider failure — e.g. an answer that does not parse —
    is re-raised unchanged so ``structured_call`` can ask for a corrected answer.
    """

    RETRIES = {"rate_limited": 2, "unavailable": 2, "timeout": 1}

    def __init__(self, inner: Any, limiter: TokenBucket, classify: Callable[[BaseException], LlmError], *,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        self.inner = inner
        self.limiter = limiter
        self.classify = classify
        self._sleep = sleep

    async def ainvoke(self, messages: list[Any]) -> Any:
        attempt = 0
        while True:
            await self.limiter.acquire()
            try:
                return await self.inner.ainvoke(messages)
            except Exception as exc:  # noqa: BLE001 - classified below
                err = self.classify(exc)
                if err.kind == "unknown":
                    raise
                if err.retryable and attempt < self.RETRIES.get(err.kind, 0):
                    delay = err.retry_after if err.retry_after is not None else 2.0 * (2 ** attempt)
                    attempt += 1
                    log.warning("gemini.retry", kind=err.kind, attempt=attempt, delay_s=round(delay, 1))
                    await self._sleep(delay + random.uniform(0, 0.5))
                    continue
                raise LlmError(err.kind, str(err), provider="gemini", retryable=False,
                               status_code=err.status_code, retry_after=err.retry_after) from exc


class GeminiProvider:
    id = ProviderId.gemini
    location = "cloud"

    def __init__(self, settings: AppSettings, *, secrets: SecretStore | None = None, transport: Any = None,
                 limiter: TokenBucket | None = None, chat_factory: Callable[..., Any] | None = None,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.llm = settings.llm
        self.secrets = secrets or SecretStore()
        self._transport = transport
        self.limiter = limiter or TokenBucket(self.llm.gemini_rpm)
        self._chat_factory = chat_factory or _default_chat_factory
        self._sleep = sleep
        self._clock = clock
        self._models: dict[str, tuple[float, list[ModelInfo]]] = {}
        self._health: dict[tuple[str, str], tuple[float, ProviderHealth]] = {}

    # ------------------------------------------------------------------ keys and snapshots
    def _key(self, credential: str | None = None) -> str:
        if credential is not None:
            key = check_key_shape(credential)
            REGISTRY.register(key)
            return key
        stored = self.secrets.get()
        if stored is None:
            raise LlmError("config_error", "no Gemini API key is configured", provider="gemini")
        return stored.value.get_secret_value()

    def snapshot(self, model: str | None = None, *, generation: int = 0) -> LlmSnapshot:
        name = model or self.llm.gemini_model
        if not name:
            raise LlmError("config_error", "no Gemini model is configured", provider="gemini")
        options: dict[str, Any] = {"temperature": self.settings.model.temperature,
                                   "max_output_tokens": self.llm.gemini_max_output_tokens,
                                   "timeout_s": self.llm.timeout_s}
        if self.llm.gemini_thinking_budget is not None:
            options["thinking_budget"] = self.llm.gemini_thinking_budget
        return LlmSnapshot(self.id, gemini_rest.normalize_model_id(name), "cloud", generation, options)

    def chat_model(self, snapshot: LlmSnapshot, credential: str | None = None) -> Any:
        if snapshot.provider is not self.id:
            raise LlmError("config_error", f"snapshot is for {snapshot.provider.value}, not gemini", provider="gemini")
        check_sdk_environment()
        opts = snapshot.options
        kwargs: dict[str, Any] = {
            "model": snapshot.model,
            "google_api_key": SecretStr(self._key(credential)),
            "vertexai": False,
            "base_url": API_BASE_URL,   # never GOOGLE_GEMINI_BASE_URL (LP11)
            "temperature": min(max(float(opts.get("temperature", 0.1)), 0.0), 2.0),
            "max_output_tokens": int(opts.get("max_output_tokens", 2048)),
            "timeout": float(opts.get("timeout_s", 120.0)),
            "max_retries": 0,
        }
        if opts.get("thinking_budget") is not None:
            kwargs["thinking_budget"] = int(opts["thinking_budget"])
        return self._chat_factory(**kwargs)

    def structured(self, snapshot: LlmSnapshot, schema: type[BaseModel], credential: str | None = None) -> Any:
        inner = self.chat_model(snapshot, credential).with_structured_output(schema, method="json_schema")
        return GuardedRunnable(inner, self.limiter, self.classify, sleep=self._sleep)

    def classify(self, exc: BaseException) -> LlmError:
        return classify_gemini(exc)

    # ------------------------------------------------------------------ discovery, health, validation
    async def list_models(self, credential: str | None = None) -> list[ModelInfo]:
        key = self._key(credential)
        fp = fingerprint(key)
        cached = self._models.get(fp)
        if cached and cached[0] > self._clock():
            return cached[1]
        models = await gemini_rest.list_models(key, transport=self._transport,
                                               exclude=self.llm.gemini_exclude or gemini_rest.DEFAULT_EXCLUDE)
        self._models[fp] = (self._clock() + MODELS_TTL_S, models)
        log.info("gemini.models_listed", count=len(models), key=fp)
        return models

    async def health(self, snapshot: LlmSnapshot) -> ProviderHealth:
        """Model lookup only (no generation, no cost), cached for a minute. Never raises."""
        try:
            key = self._key()
        except LlmError as exc:
            return ProviderHealth(self.id, snapshot.model, False, False, "cloud", error=exc.kind, detail={"reason": str(exc)})
        cache_key = (fingerprint(key), snapshot.model)
        cached = self._health.get(cache_key)
        if cached and cached[0] > self._clock():
            return cached[1]
        try:
            await gemini_rest.get_model(key, snapshot.model, transport=self._transport)
            result = ProviderHealth(self.id, snapshot.model, True, True, "cloud")
        except LlmError as exc:
            reachable = exc.kind not in ("unavailable", "timeout")
            result = ProviderHealth(self.id, snapshot.model, reachable, False, "cloud", error=exc.kind,
                                    detail={"reason": str(exc)})
        self._health[cache_key] = (self._clock() + HEALTH_TTL_S, result)
        return result

    async def validate(self, model: str, credential: str | None = None, *, deep: bool = False) -> ValidationResult:
        """Look the model up, then prove schema-constrained output with a tiny probe. Never raises."""
        try:
            key = self._key(credential)
            raw = await gemini_rest.get_model(key, model, transport=self._transport)
            info = gemini_rest.to_model_info(raw, exclude=self.llm.gemini_exclude or gemini_rest.DEFAULT_EXCLUDE,
                                             min_input_tokens=0)
            if info is None:
                return ValidationResult(ok=False, error_kind="invalid_request",
                                        error=f"{model} is not a text-generation model AEGIS can use")
            snapshot = self.snapshot(info.id)
            try:
                await run_probe(self.structured(snapshot, Probe, credential=key))
            except LlmError:
                raise
            except Exception:  # noqa: BLE001 - it answered, but not in the schema
                return ValidationResult(ok=False, error_kind="invalid_request",
                                        error=f"{info.id} did not return schema-constrained JSON")
            warnings: list[str] = []
            if info.stage != "stable":
                warnings.append(f"{info.id} is a {info.stage} model: it may change or be withdrawn")
            if deep:
                failed = await run_deep_probe(lambda schema: self.structured(snapshot, schema, credential=key))
                if failed:
                    return ValidationResult(ok=False, error_kind="invalid_request",
                                            error=f"{info.id} could not produce AEGIS's {', '.join(failed)} answers")
            return ValidationResult(ok=True, capabilities=frozenset({"generate", "structured_output"}),
                                    warnings=tuple(warnings))
        except LlmError as exc:
            return ValidationResult(ok=False, error_kind=exc.kind, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - never raise from validation
            err = self.classify(exc)
            return ValidationResult(ok=False, error_kind=err.kind, error=str(err))
