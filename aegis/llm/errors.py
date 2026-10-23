"""Classify Ollama client errors into the shared taxonomy (LLM_PROVIDER_PHASES LP2, §7.5).

Retry behaviour is exactly what ``aegis/agent/llm.py`` does today: only a server-side failure
(HTTP 5xx, e.g. Ollama's model runner crashing while it loads) is retryable. "Model not found"
(404), "Ollama is down" (connection refused) and timeouts are not retried — the caller falls back
to rules and templates.
"""

from __future__ import annotations

import httpx

from aegis.llm.base import LlmError

__all__ = ["classify_ollama"]

_PROVIDER = "ollama"


def classify_ollama(exc: BaseException) -> LlmError:
    if isinstance(exc, LlmError):
        return exc
    status = getattr(exc, "status_code", None)
    name = type(exc).__name__
    if isinstance(status, int):
        if status >= 500:
            return LlmError("unavailable", f"Ollama server error (HTTP {status})", provider=_PROVIDER,
                            retryable=True, status_code=status)
        if status == 404:
            return LlmError("model_not_found", "the model is not pulled in Ollama", provider=_PROVIDER,
                            status_code=status)
        if status == 429:
            return LlmError("rate_limited", "Ollama is busy (HTTP 429)", provider=_PROVIDER, status_code=status)
        return LlmError("invalid_request", f"Ollama rejected the request (HTTP {status})", provider=_PROVIDER,
                        status_code=status)
    if isinstance(exc, httpx.TimeoutException):
        return LlmError("timeout", "Ollama did not answer in time", provider=_PROVIDER)
    if isinstance(exc, (httpx.ConnectError, ConnectionError)):
        return LlmError("unavailable", "Ollama is not reachable", provider=_PROVIDER)
    if isinstance(exc, httpx.HTTPError):
        return LlmError("unavailable", f"cannot talk to Ollama ({name})", provider=_PROVIDER)
    return LlmError("unknown", f"unexpected error from the Ollama client ({name})", provider=_PROVIDER)
