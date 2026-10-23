"""Gemini model discovery and lookup over REST (LLM_PROVIDER_PHASES §7.2, facts G-1…G-4).

AEGIS's own small client, not the SDK:

* the key travels only in the ``x-goog-api-key`` header — never in a URL, so never in a proxy log
  or an exception message;
* the transport refuses every host except ``generativelanguage.googleapis.com`` (§9.4);
* pagination and error mapping are explicit and testable with ``httpx.MockTransport``.

**No hard-coded model list.** ``list_models`` keeps what the key can use for text generation:
``generateContent`` among ``supportedGenerationMethods``, not an embedding / image / video /
audio / live / robotics family (a configurable deny-list of name tokens), and an input window of
at least 16k tokens. Stability is labelled, not hidden. The model resource says nothing about
structured output (G-3), so that capability is only added after a validation probe.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import quote

import httpx

from aegis.llm.base import LlmError, ModelInfo, ProviderId
from aegis.llm.providers.gemini_errors import GeminiHttpError, classify_gemini

__all__ = [
    "API_HOST", "BASE_URL", "DEFAULT_EXCLUDE", "MIN_INPUT_TOKENS", "PinnedHostTransport",
    "get_model", "list_models", "normalize_model_id", "to_model_info",
]

API_HOST = "generativelanguage.googleapis.com"
BASE_URL = f"https://{API_HOST}/v1beta"
MIN_INPUT_TOKENS = 16_384
MAX_PAGES = 10
TIMEOUT_S = 15.0
# name tokens of model families that do not generate text from text (§7.2 step 3)
DEFAULT_EXCLUDE = ("embedding", "embed", "aqa", "imagen", "image", "veo", "video", "tts", "audio", "live",
                   "robotics", "computer", "lyria", "music")
_MODEL_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class PinnedHostTransport(httpx.AsyncBaseTransport):
    """Only ever talks to the Gemini API host over HTTPS."""

    def __init__(self, inner: httpx.AsyncBaseTransport | None = None):
        self._inner = inner or httpx.AsyncHTTPTransport(verify=True)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != "https" or request.url.host != API_HOST:
            raise LlmError("config_error", f"refused a request to {request.url.host}: only {API_HOST} is allowed",
                           provider="gemini")
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def normalize_model_id(model: str) -> str:
    """``models/gemini-x`` → ``gemini-x``; refuses anything that is not a plain model id."""
    model = (model or "").strip()
    model = model[len("models/"):] if model.startswith("models/") else model
    if not _MODEL_ID.match(model):
        raise LlmError("invalid_request", "a model id has only letters, digits, '.', '_' and '-'", provider="gemini")
    return model


def _tokens(model_id: str) -> list[str]:
    return [t for t in re.split(r"[-_.:/]+", model_id.lower()) if t]


def _stage(model_id: str, description: str) -> str:
    toks = set(_tokens(model_id))
    if "exp" in toks or "experimental" in toks or "experimental" in description.lower():
        return "experimental"
    if "preview" in toks or "preview" in description.lower():
        return "preview"
    return "stable"


def to_model_info(raw: dict, *, exclude: Iterable[str] = DEFAULT_EXCLUDE,
                  min_input_tokens: int = MIN_INPUT_TOKENS) -> ModelInfo | None:
    """The model as AEGIS shows it, or ``None`` if it cannot generate text for AEGIS."""
    if "generateContent" not in (raw.get("supportedGenerationMethods") or []):
        return None
    model_id = str(raw.get("name") or raw.get("baseModelId") or "")
    model_id = model_id[len("models/"):] if model_id.startswith("models/") else model_id
    if not model_id or not _MODEL_ID.match(model_id):
        return None
    banned = {e.lower() for e in exclude}
    if any(tok in banned for tok in _tokens(model_id)):
        return None
    limit = raw.get("inputTokenLimit")
    if isinstance(limit, int) and limit < min_input_tokens:
        return None
    out_limit = raw.get("outputTokenLimit")
    thinking = raw.get("thinking")
    return ModelInfo(
        provider=ProviderId.gemini,
        id=model_id,
        display_name=str(raw.get("displayName") or model_id),
        input_token_limit=limit if isinstance(limit, int) else None,
        output_token_limit=out_limit if isinstance(out_limit, int) else None,
        thinking=thinking if isinstance(thinking, bool) else None,
        stage=_stage(model_id, str(raw.get("description") or "")),
        capabilities=frozenset({"generate"}),
    )


async def _get(client: httpx.AsyncClient, path: str, key: str, params: dict | None = None) -> dict:
    try:
        resp = await client.get(f"{BASE_URL}/{path}", params=params, headers={"x-goog-api-key": key})
    except LlmError:
        raise
    except httpx.HTTPError as exc:
        raise classify_gemini(exc) from None
    if resp.status_code >= 400:
        try:
            body = resp.json().get("error", {}) or {}
        except ValueError:
            body = {}
        raise classify_gemini(GeminiHttpError(resp.status_code, str(body.get("status", "")),
                                              f"{body.get('message', '')} {body.get('details', '')}")) from None
    try:
        return resp.json() or {}
    except ValueError:
        raise LlmError("unavailable", "Gemini returned something that is not JSON", provider="gemini") from None


def _client(transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=PinnedHostTransport(transport), timeout=TIMEOUT_S, follow_redirects=False)


async def list_models(key: str, *, transport: httpx.AsyncBaseTransport | None = None,
                      exclude: Iterable[str] = DEFAULT_EXCLUDE, page_size: int = 1000) -> list[ModelInfo]:
    """The text-generation models *key* can use, stable first, then by name."""
    models: list[ModelInfo] = []
    token: str | None = None
    async with _client(transport) as client:
        for _ in range(MAX_PAGES):
            params = {"pageSize": page_size, **({"pageToken": token} if token else {})}
            body = await _get(client, "models", key, params)
            for raw in body.get("models") or []:
                if isinstance(raw, dict) and (info := to_model_info(raw, exclude=exclude)) is not None:
                    models.append(info)
            token = body.get("nextPageToken")
            if not token:
                break
    order = {"stable": 0, "preview": 1, "experimental": 2, "unknown": 3}
    return sorted({m.id: m for m in models}.values(), key=lambda m: (order[m.stage], m.id))


async def get_model(key: str, model: str, *, transport: httpx.AsyncBaseTransport | None = None) -> dict:
    """The raw model resource (raises ``model_not_found`` / ``invalid_api_key`` …)."""
    model = normalize_model_id(model)
    async with _client(transport) as client:
        return await _get(client, f"models/{quote(model, safe='')}", key)
