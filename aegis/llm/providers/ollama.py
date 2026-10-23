"""The local Ollama provider (LLM_PROVIDER_PHASES LP2).

Builds the same ``ChatOllama`` client AEGIS has always used — ``format="json"``, the configured
``num_ctx`` and temperature — so moving behind the provider interface changes nothing. Model
listing and health read Ollama's ``/api/tags`` with a plain short-timeout client: Ollama is
AEGIS's own infrastructure, not a scan target (conflict C33), so this is not the scan egress guard.

``check_url`` applies the local-only model-host guard (M-7, kept for every Ollama URL under M-7′).
It is not called on construction: the default URL (``http://ollama:11434``) does not resolve
outside Docker, and refusing it here would change today's behaviour. LP4/LP6 decide where it is
enforced.
"""

from __future__ import annotations

from typing import Any

import httpx
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from aegis.config import ModelSettings
from aegis.llm.base import LlmError, LlmSnapshot, ModelInfo, ProviderHealth, ProviderId, ValidationResult
from aegis.llm.errors import classify_ollama

__all__ = ["OllamaProvider", "TAGS_TIMEOUT_S"]

TAGS_TIMEOUT_S = 2.0


class OllamaProvider:
    id = ProviderId.ollama
    location = "local"

    def __init__(self, settings: ModelSettings, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = TAGS_TIMEOUT_S):
        self.settings = settings
        self.url = settings.ollama_url
        self._transport = transport
        self._timeout = timeout

    # ------------------------------------------------------------------ snapshots and clients
    def snapshot(self, model: str | None = None, *, generation: int = 0) -> LlmSnapshot:
        """A snapshot of *model* (default: the configured one) with the configured options."""
        return LlmSnapshot(
            provider=self.id,
            model=model or self.settings.name,
            location="local",
            generation=generation,
            options={"temperature": self.settings.temperature, "num_ctx": self.settings.num_ctx},
        )

    def chat_model(self, snapshot: LlmSnapshot) -> ChatOllama:
        """The client. Constructing it opens no connection."""
        if snapshot.provider is not self.id:
            raise LlmError("config_error", f"snapshot is for {snapshot.provider.value}, not ollama", provider="ollama")
        opts = snapshot.options
        return ChatOllama(
            model=snapshot.model,
            base_url=self.url,
            temperature=opts.get("temperature", self.settings.temperature),
            num_ctx=opts.get("num_ctx", self.settings.num_ctx),
            format="json",
        )

    def structured(self, snapshot: LlmSnapshot, schema: type[BaseModel]) -> Any:
        return self.chat_model(snapshot).with_structured_output(schema, method="json_schema")

    def check_url(self) -> list[str]:
        """The local-only host guard (M-7); raises ``ModelHostRefused`` for a public address."""
        from aegis.safety.model_host import check_model_url

        return check_model_url(self.url)

    def classify(self, exc: BaseException) -> LlmError:
        return classify_ollama(exc)

    # ------------------------------------------------------------------ discovery and health
    async def _tags(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            resp = await client.get(self.url.rstrip("/") + "/api/tags")
        resp.raise_for_status()
        return [m for m in (resp.json() or {}).get("models", []) if isinstance(m, dict) and m.get("name")]

    async def list_models(self, credential: str | None = None) -> list[ModelInfo]:
        """Every pulled model; raises :class:`LlmError` when Ollama can't be reached (no credentials)."""
        try:
            tags = await self._tags()
        except (httpx.HTTPError, ValueError) as exc:
            raise self.classify(exc) from exc
        return sorted((_model_info(m) for m in tags), key=lambda m: m.id)

    async def health(self, snapshot: LlmSnapshot) -> ProviderHealth:
        """Same facts as the API's ``probe_ollama``: reachable, model pulled, which models exist."""
        detail: dict[str, Any] = {"url": self.url}
        try:
            names = {m["name"] for m in await self._tags()}
        except (httpx.HTTPError, ValueError) as exc:
            return ProviderHealth(self.id, snapshot.model, reachable=False, model_present=False, location="local",
                                  error=type(exc).__name__, detail=detail)
        detail["models"] = sorted(names)
        present = snapshot.model in names or f"{snapshot.model}:latest" in names
        return ProviderHealth(self.id, snapshot.model, reachable=True, model_present=present, location="local",
                              detail=detail)

    async def validate(self, model: str, credential: str | None = None, *, deep: bool = False) -> ValidationResult:
        health = await self.health(self.snapshot(model))
        if not health.reachable:
            return ValidationResult(ok=False, error_kind="unavailable",
                                    error=f"Ollama is not reachable at {self.url} ({health.error})")
        if not health.model_present:
            return ValidationResult(ok=False, error_kind="model_not_found",
                                    error=f"{model} is not pulled - run: ollama pull {model}")
        return ValidationResult(ok=True, capabilities=frozenset({"generate"}))


def _model_info(tag: dict) -> ModelInfo:
    details = tag.get("details") or {}
    raw_caps = tag.get("capabilities") or []  # newer Ollama versions list them; older ones don't
    caps = set()
    if "completion" in raw_caps:
        caps.add("generate")
    if "embedding" in raw_caps:
        caps.add("embedding")
    context = details.get("context_length")
    return ModelInfo(
        provider=ProviderId.ollama,
        id=tag["name"],
        display_name=tag["name"],
        input_token_limit=context if isinstance(context, int) else None,
        thinking=("thinking" in raw_caps) if raw_caps else None,
        stage="stable",
        capabilities=frozenset(caps),
    )
