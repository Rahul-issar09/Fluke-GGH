"""Which providers this install can build, built lazily (LLM_PROVIDER_PHASES LP2).

A provider module is imported only when its provider is first used, so an offline install never
imports a cloud SDK. Ollama is always registered; Gemini when the optional ``gemini`` extra is
installed (LP5). Whether Gemini may actually be *used* is decided elsewhere (configuration,
consent, the cloud kill-switch).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from aegis.config import AppSettings
from aegis.llm.base import LlmError, LlmProvider, ProviderId

__all__ = ["DEFAULT_FACTORIES", "ProviderFactory", "ProviderRegistry"]

ProviderFactory = Callable[[AppSettings], LlmProvider]


def _ollama(settings: AppSettings) -> LlmProvider:
    from aegis.llm.providers.ollama import OllamaProvider

    return OllamaProvider(settings.model)


def default_factories(secrets: Any = None) -> dict[ProviderId, ProviderFactory]:
    """Ollama always; Gemini when the optional ``gemini`` extra is installed (checked, not imported).
    Gemini gets *secrets* — the manager's key store — so a key entered this session reaches it."""
    from aegis.llm.providers.gemini import installed

    def _gemini(settings: AppSettings) -> LlmProvider:
        from aegis.llm.providers.gemini import GeminiProvider

        return GeminiProvider(settings, secrets=secrets)

    factories: dict[ProviderId, ProviderFactory] = {ProviderId.ollama: _ollama}
    if installed():
        factories[ProviderId.gemini] = _gemini
    return factories


DEFAULT_FACTORIES: Mapping[ProviderId, ProviderFactory] = {ProviderId.ollama: _ollama}  # offline-only set


class ProviderRegistry:
    def __init__(self, settings: AppSettings, factories: Mapping[ProviderId, ProviderFactory] | None = None, *,
                 secrets: Any = None):
        self._settings = settings
        self._factories = dict(default_factories(secrets) if factories is None else factories)
        self._instances: dict[ProviderId, LlmProvider] = {}

    def available(self, provider: ProviderId) -> bool:
        return provider in self._factories

    def registered(self) -> list[ProviderId]:
        return sorted(self._factories, key=lambda p: p.value)

    def get(self, provider: ProviderId) -> LlmProvider:
        if provider not in self._instances:
            factory = self._factories.get(provider)
            if factory is None:
                raise LlmError("provider_unavailable", f"the {provider.value} provider is not available in this install",
                               provider=provider.value)
            self._instances[provider] = factory(self._settings)
        return self._instances[provider]
