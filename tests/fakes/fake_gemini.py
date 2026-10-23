"""A fake Gemini REST API for discovery and validation tests (LLM_PROVIDER_PHASES LP5).

Serves ``GET /v1beta/models`` (two pages) and ``GET /v1beta/models/{id}`` with model resources
shaped like Google's. It **asserts** that the key arrives in the ``x-goog-api-key`` header and never
in the URL, and records every request. Error responses use Google's error body
(``{"error": {"code", "message", "status", "details"}}``).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

KEY = "AIzaSyFAKE-test-key-0000000000000000000"   # Google-shaped, not real

MODELS: list[dict[str, Any]] = [
    {"name": "models/gemini-2.5-flash", "displayName": "Gemini 2.5 Flash", "inputTokenLimit": 1048576,
     "outputTokenLimit": 65536, "supportedGenerationMethods": ["generateContent", "countTokens"], "thinking": True,
     "temperature": 1.0, "maxTemperature": 2.0},
    {"name": "models/gemini-2.5-pro-preview-06-05", "displayName": "Gemini 2.5 Pro Preview", "inputTokenLimit": 1048576,
     "outputTokenLimit": 65536, "supportedGenerationMethods": ["generateContent"], "thinking": True},
    {"name": "models/gemini-exp-1206", "displayName": "Gemini Experimental 1206", "inputTokenLimit": 2097152,
     "supportedGenerationMethods": ["generateContent"]},
    {"name": "models/text-embedding-004", "displayName": "Text Embedding 004", "inputTokenLimit": 2048,
     "supportedGenerationMethods": ["embedContent"]},
    {"name": "models/gemini-embedding-001", "displayName": "Gemini Embedding", "inputTokenLimit": 2048,
     "supportedGenerationMethods": ["embedContent", "countTextTokens"]},
    {"name": "models/imagen-4.0-generate-001", "displayName": "Imagen 4", "supportedGenerationMethods": ["predict"]},
    # page 2
    {"name": "models/gemini-2.5-flash-image", "displayName": "Nano Banana", "inputTokenLimit": 32768,
     "supportedGenerationMethods": ["generateContent"]},
    {"name": "models/gemini-2.5-flash-preview-tts", "displayName": "Gemini TTS", "inputTokenLimit": 8192,
     "supportedGenerationMethods": ["generateContent"]},
    {"name": "models/gemini-live-2.5-flash-preview", "displayName": "Gemini Live", "inputTokenLimit": 1048576,
     "supportedGenerationMethods": ["bidiGenerateContent"]},
    {"name": "models/gemma-3-27b-it", "displayName": "Gemma 3 27B", "inputTokenLimit": 131072,
     "supportedGenerationMethods": ["generateContent", "countTokens"]},
    {"name": "models/aqa", "displayName": "Model that performs Attributed Question Answering.",
     "inputTokenLimit": 7168, "supportedGenerationMethods": ["generateAnswer"]},
    {"name": "models/gemini-1.0-tiny", "displayName": "A small-window model", "inputTokenLimit": 8192,
     "supportedGenerationMethods": ["generateContent"]},
]

EXPECTED_IDS = ["gemini-2.5-flash", "gemma-3-27b-it", "gemini-2.5-pro-preview-06-05", "gemini-exp-1206"]


def error_body(code: int, status: str, message: str, details: list | None = None) -> dict:
    return {"error": {"code": code, "message": message, "status": status, "details": details or []}}


class FakeGeminiApi:
    def __init__(self, key: str = KEY, *, fail: tuple[int, dict] | None = None, models: list[dict] | None = None):
        self.key = key
        self.fail = fail
        self.models = list(MODELS if models is None else models)
        self.requests: list[httpx.Request] = []

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.host == "generativelanguage.googleapis.com" and request.url.scheme == "https"
        assert self.key not in str(request.url), "the API key must never be in a URL"
        assert "key" not in request.url.params, "no ?key= query parameter"
        if self.fail is not None:
            return httpx.Response(self.fail[0], json=self.fail[1])
        if request.headers.get("x-goog-api-key") != self.key:
            return httpx.Response(400, json=error_body(400, "INVALID_ARGUMENT", "API key not valid. Please pass a valid API key.",
                                                        [{"reason": "API_KEY_INVALID"}]))
        path = request.url.path
        if path == "/v1beta/models":
            if request.url.params.get("pageToken") == "p2":
                return httpx.Response(200, json={"models": self.models[6:]})
            return httpx.Response(200, json={"models": self.models[:6], "nextPageToken": "p2"})
        if path.startswith("/v1beta/models/"):
            wanted = "models/" + path[len("/v1beta/models/"):]
            for m in self.models:
                if m["name"] == wanted:
                    return httpx.Response(200, json=m)
            return httpx.Response(404, json=error_body(404, "NOT_FOUND", f"{wanted} is not found for API version v1beta"))
        return httpx.Response(404, json=error_body(404, "NOT_FOUND", "no such path"))


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content) if request.content else None
