"""Classify Gemini failures into the shared taxonomy (LLM_PROVIDER_PHASES §7.5, facts G-6).

Errors reach AEGIS in three shapes: ``google.genai.errors.APIError`` (``.code`` / ``.status``),
LangChain's ``ChatGoogleGenerativeAIError`` with that error as its ``__cause__``, and AEGIS's own
:class:`GeminiHttpError` from model discovery. The classifier walks the exception chain to the
first one that carries an HTTP status.

A bad key comes back either as **401** or, from older endpoints, as **400 ``INVALID_ARGUMENT``
with reason ``API_KEY_INVALID``** — both mean ``invalid_api_key``. A 429 is a **daily quota**
(``…PerDay…``: not worth retrying today) or a **rate limit** (retry after the delay Google gives).

Messages are AEGIS's own fixed sentences plus the upstream status name, scrubbed: provider text
never travels into logs or audit records verbatim.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from aegis.llm.base import LlmError
from aegis.llm.secrets import scrub

__all__ = ["GeminiHttpError", "classify_gemini", "find_status"]

_PROVIDER = "gemini"
_RETRY_DELAY = re.compile(r"retry(?:_?delay|Delay)?\D{0,12}?(\d+(?:\.\d+)?)\s*s", re.IGNORECASE)


class GeminiHttpError(Exception):
    """An error response from the Gemini REST API (AEGIS's discovery and validation calls)."""

    def __init__(self, status_code: int, status: str = "", text: str = ""):
        super().__init__(f"HTTP {status_code} {status}".strip())
        self.code = status_code
        self.status = status
        self.text = scrub(text)[:2000]


def find_status(exc: BaseException) -> tuple[int | None, str, str]:
    """``(http_status, status_name, text)`` from the first error in the chain that has a status."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        code = getattr(current, "code", None)
        if not isinstance(code, int):
            code = getattr(current, "status_code", None)
        if not isinstance(code, int) and isinstance(current, httpx.HTTPStatusError):
            code = current.response.status_code
        if isinstance(code, int) and 100 <= code <= 599:
            status = str(getattr(current, "status", "") or "")
            text = getattr(current, "text", None)
            if not isinstance(text, str):
                details = getattr(current, "details", None)
                text = f"{getattr(current, 'message', '')} {details if details is not None else ''} {current}"
            return code, status, text
        current = current.__cause__ or current.__context__
    return None, "", ""


def _retry_after(text: str) -> float | None:
    match = _RETRY_DELAY.search(text or "")
    return min(float(match.group(1)), 120.0) if match else None


def classify_gemini(exc: BaseException) -> LlmError:
    if isinstance(exc, LlmError):
        return exc
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError)):
        return LlmError("timeout", "Gemini did not answer in time", provider=_PROVIDER, retryable=True)
    if isinstance(exc, (httpx.ConnectError, ConnectionError)):
        return LlmError("unavailable", "Gemini cannot be reached (network or DNS)", provider=_PROVIDER, retryable=True)

    code, status, text = find_status(exc)
    if code is None:
        if isinstance(exc, httpx.HTTPError):
            return LlmError("unavailable", f"cannot talk to Gemini ({type(exc).__name__})", provider=_PROVIDER,
                            retryable=True)
        return LlmError("unknown", f"unexpected error from the Gemini client ({type(exc).__name__})", provider=_PROVIDER)

    status = status.upper()
    low = text.lower()

    def err(kind: str, message: str, **kw: Any) -> LlmError:
        return LlmError(kind, scrub(f"{message} (HTTP {code}{' ' + status if status else ''})"), provider=_PROVIDER,
                        status_code=code, **kw)

    if code == 401 or "api_key_invalid" in low or "api key not valid" in low or "api key expired" in low:
        return err("invalid_api_key", "Gemini refused the API key")
    if "reported as leaked" in low:
        return err("invalid_api_key", "Google blocked this API key as leaked - create a new one in AI Studio")
    if code == 402 or (code == 400 and status == "FAILED_PRECONDITION" and "billing" in low):
        return err("billing_required", "Gemini needs billing (or prepaid credit) for this key")
    if code == 403:
        return err("permission_denied", "this API key may not use that model or the Gemini API")
    if code == 404:
        return err("model_not_found", "Gemini has no such model for this key")
    if code == 429:
        if "perday" in low or "per day" in low or "daily" in low:
            return err("quota_exhausted", "the daily Gemini quota for this key is used up")
        return err("rate_limited", "Gemini rate limit reached", retryable=True, retry_after=_retry_after(text))
    if code in (408, 504):
        return err("timeout", "Gemini did not answer in time", retryable=True)
    if code in (500, 502, 503):
        return err("unavailable", "Gemini is temporarily unavailable", retryable=True)
    if code == 499:
        return err("unavailable", "the Gemini request was cancelled")
    return err("invalid_request", "Gemini rejected the request")
