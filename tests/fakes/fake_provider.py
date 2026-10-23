"""A scripted model provider for the LLM_PROVIDER_PHASES tests (LP3+).

``FakeProvider`` implements the provider contract with a :class:`~fakes.fake_llm.FakeLLM`-style
runnable, and records every snapshot it was asked to serve — so a test can prove a call went
through the manager (and which pinned model it used), never touching the network.
``manager_with`` builds a ``ProviderManager`` whose registry holds only the given fakes.
"""

from __future__ import annotations

from typing import Any

from aegis.config import AppSettings, LlmSettings, ModelSettings
from aegis.llm.base import LlmError, LlmSnapshot, ProviderHealth, ProviderId, ValidationResult
from aegis.llm.errors import classify_ollama
from aegis.llm.manager import ProviderManager
from aegis.llm.registry import ProviderRegistry
from aegis.llm.secrets import SecretRegistry, SecretStore
from fakes.fake_llm import FakeLLM


class StatusError(Exception):
    """A client error carrying an HTTP status, like the Ollama and Gemini clients raise."""

    def __init__(self, status_code: int):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class FakeProvider:
    def __init__(self, script: list[Any] | None = None, *, provider: ProviderId = ProviderId.ollama,
                 location: str = "local", runnable: Any = None):
        self.id = provider
        self.location = location
        self.runnable = runnable if runnable is not None else FakeLLM(list(script or []))
        self.used: list[LlmSnapshot] = []

    def snapshot(self, model: str | None = None, *, generation: int = 0) -> LlmSnapshot:
        return LlmSnapshot(self.id, model or "fake-model", self.location, generation, {"temperature": 0.1})

    def structured(self, snapshot: LlmSnapshot, schema: type) -> Any:
        self.used.append(snapshot)
        return self.runnable

    async def list_models(self, credential: str | None = None) -> list:
        return []

    async def health(self, snapshot: LlmSnapshot) -> ProviderHealth:
        return ProviderHealth(self.id, snapshot.model, True, True, self.location)

    async def validate(self, model: str, credential: str | None = None, *, deep: bool = False) -> ValidationResult:
        if model == "missing-model":
            return ValidationResult(ok=False, error_kind="model_not_found", error="no such model")
        return ValidationResult(ok=True, capabilities=frozenset({"generate", "structured_output"}))

    def classify(self, exc: BaseException) -> LlmError:
        if isinstance(exc, LlmError):
            return exc
        status = getattr(exc, "status_code", None)
        if status == 401:
            return LlmError("invalid_api_key", "the key was refused", provider=self.id.value, status_code=401)
        err = classify_ollama(exc)
        return LlmError(err.kind, str(err), provider=self.id.value, retryable=err.retryable, status_code=err.status_code)



class FakeGemini(FakeProvider):
    """A Gemini stand-in: one model, and refusals for any key but *key*."""

    def __init__(self, key: str):
        super().__init__(provider=ProviderId.gemini, location="cloud")
        self.key = key

    async def list_models(self, credential: str | None = None) -> list:
        from aegis.llm.base import ModelInfo

        if credential and credential != self.key:
            raise LlmError("invalid_api_key", "Gemini refused the API key (HTTP 400)", provider="gemini", status_code=400)
        return [ModelInfo(ProviderId.gemini, "gemini-2.5-flash", "Gemini 2.5 Flash", 1048576, 65536, True, "stable",
                          frozenset({"generate"}))]

    async def validate(self, model: str, credential: str | None = None, *, deep: bool = False) -> ValidationResult:
        if credential and credential != self.key:
            return ValidationResult(ok=False, error_kind="invalid_api_key", error="Gemini refused the API key")
        if model != "gemini-2.5-flash":
            return ValidationResult(ok=False, error_kind="model_not_found", error="Gemini has no such model")
        return ValidationResult(ok=True, capabilities=frozenset({"generate", "structured_output"}))


TEST_KEY = "AIzaSyTEST-fake-provider-key-0000000001"   # Google-shaped, not real


def memory_secrets(key: str | None = TEST_KEY) -> SecretStore:
    """A key store with no environment, holding *key* as this session's key if given."""
    store = SecretStore({}, registry=SecretRegistry())
    if key:
        store.put(key)
    return store


def manager_with(tmp_path, *providers: FakeProvider, model: str = "qwen2.5:7b", record_consent: bool = False,
                 allow_source_code: bool = False, secrets: SecretStore | None = None, **llm: Any) -> ProviderManager:
    """A manager over *providers* only (no real provider can be built), whose session key is
    :data:`TEST_KEY`. ``record_consent`` records a valid consent (current notice, that key)."""
    secrets = secrets or memory_secrets()
    if record_consent:
        from datetime import datetime, timezone

        from aegis.llm.config_store import ConsentRecord, LlmConfigFile, config_path, write_config
        from aegis.llm.consent import DISCLOSURE_VERSION

        stored = secrets.get()
        write_config(config_path(tmp_path), LlmConfigFile(consent=ConsentRecord(
            disclosure_version=DISCLOSURE_VERSION, accepted_at=datetime.now(timezone.utc), accepted_via="api",
            allow_source_code=allow_source_code, key_fingerprint=stored.fingerprint if stored else None)))
    settings = AppSettings(data_dir=str(tmp_path), model=ModelSettings(name=model), llm=LlmSettings(**llm))
    registry = ProviderRegistry(settings, {p.id: (lambda _s, p=p: p) for p in providers})
    return ProviderManager(settings, tmp_path, registry=registry, environ={}, secrets=secrets)
