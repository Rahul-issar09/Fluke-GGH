"""The provider contract every chat model behind AEGIS implements (LLM_PROVIDER_PHASES LP2).

A provider turns an :class:`LlmSnapshot` into a structured runnable — the object
:func:`aegis.agent.llm.structured_call` invokes — and can list its models and report its health.
Nothing outside ``aegis/llm/providers/`` knows which provider is behind a snapshot: nodes and the
chat service only ever ask for "a runnable for this schema".

A snapshot is an immutable value (provider, model, location, options, generation). It is pinned
per scan and per question, so a configuration change never alters a call already in flight; the
``generation`` counter lets the manager tell an old snapshot from the active one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel

__all__ = [
    "ERROR_KINDS",
    "LlmError",
    "LlmProvider",
    "LlmSnapshot",
    "Location",
    "ModelInfo",
    "ProviderHealth",
    "ProviderId",
    "ValidationResult",
]

Location = Literal["local", "cloud"]


class ProviderId(str, Enum):
    ollama = "ollama"
    gemini = "gemini"


@dataclass(frozen=True)
class ModelInfo:
    """One model a provider offers. Safe to show anywhere: it never carries a credential."""

    provider: ProviderId
    id: str
    display_name: str
    input_token_limit: int | None = None
    output_token_limit: int | None = None
    thinking: bool | None = None
    stage: Literal["stable", "preview", "experimental", "unknown"] = "unknown"
    # "generate", "embedding", and "structured_output" (only once a probe has proven it)
    capabilities: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "id": self.id,
            "display_name": self.display_name,
            "input_token_limit": self.input_token_limit,
            "output_token_limit": self.output_token_limit,
            "thinking": self.thinking,
            "stage": self.stage,
            "capabilities": sorted(self.capabilities),
        }


@dataclass(frozen=True)
class LlmSnapshot:
    """Which model answers, fixed for the duration of one scan or one question."""

    provider: ProviderId
    model: str
    location: Location
    generation: int = 0
    # sampling and provider-specific knobs (temperature, num_ctx, …) — never a secret
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def cache_key(self) -> tuple:
        return (self.provider.value, self.model, self.generation, tuple(sorted(self.options.items())))

    def to_dict(self) -> dict[str, Any]:
        """The public form, e.g. for ``Scan.config_json["llm"]`` and status output."""
        return {"provider": self.provider.value, "model": self.model, "location": self.location,
                "generation": self.generation, "options": dict(self.options)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LlmSnapshot":
        """The inverse of :meth:`to_dict` (raises ``ValueError``/``KeyError`` on a malformed record)."""
        location = data["location"]
        if location not in ("local", "cloud"):
            raise ValueError(f"unknown location {location!r}")
        return cls(provider=ProviderId(data["provider"]), model=str(data["model"]), location=location,
                   generation=int(data.get("generation", 0)), options=dict(data.get("options") or {}))


# The one error taxonomy for every provider (LLM_PROVIDER_PHASES §7.5).
ERROR_KINDS = frozenset({
    "invalid_api_key", "permission_denied", "billing_required", "model_not_found", "quota_exhausted",
    "rate_limited", "unavailable", "timeout", "invalid_request", "revoked", "provider_unavailable",
    "config_error", "unknown",
})


class LlmError(RuntimeError):
    """A provider failure, classified. ``retryable`` is decided by the provider that raised it."""

    def __init__(self, kind: str, message: str, *, provider: str | None = None, retryable: bool = False,
                 status_code: int | None = None, retry_after: float | None = None):
        if kind not in ERROR_KINDS:
            raise ValueError(f"unknown LLM error kind {kind!r}")
        super().__init__(message)
        self.kind = kind
        self.provider = provider
        self.retryable = retryable
        self.status_code = status_code
        self.retry_after = retry_after  # seconds the provider asked us to wait, when it said

    def __repr__(self) -> str:
        return f"LlmError(kind={self.kind!r}, provider={self.provider!r}, retryable={self.retryable})"


@dataclass(frozen=True)
class ProviderHealth:
    provider: ProviderId
    model: str
    reachable: bool
    model_present: bool
    location: Location
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)  # e.g. {"url": …, "models": […]} — no secrets


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    capabilities: frozenset[str] = frozenset()
    warnings: tuple[str, ...] = ()
    error_kind: str | None = None
    error: str | None = None


@runtime_checkable
class LlmProvider(Protocol):
    id: ProviderId
    location: Location

    def snapshot(self, model: str | None = None, *, generation: int = 0) -> LlmSnapshot:
        """A snapshot of *model* (default: the provider's configured model) with its options."""

    def structured(self, snapshot: LlmSnapshot, schema: type[BaseModel]) -> Any:
        """A runnable whose ``ainvoke(messages)`` returns an instance of *schema*."""

    async def list_models(self, credential: str | None = None) -> list[ModelInfo]:
        """The models this provider can use right now (with *credential* instead of the stored one)."""

    async def health(self, snapshot: LlmSnapshot) -> ProviderHealth:
        """Reachable, and is the snapshot's model available? Never raises."""

    async def validate(self, model: str, credential: str | None = None, *, deep: bool = False) -> ValidationResult:
        """Can *model* be used (with *credential*, if given)? Never raises."""

    def classify(self, exc: BaseException) -> LlmError:
        """Map a client exception to the shared taxonomy."""
