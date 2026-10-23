"""API protection (AG13.1, FASTAPI FA09.1): optional bearer token and a request-body limit.

Both are plain ASGI middleware, so they cover everything mounted on the app — the REST
routes and, later, the MCP SSE mount (``/mcp``) — not just FastAPI routes.

* **Bearer token** — when ``api.auth_token`` is set, every ``/api/*`` and ``/mcp`` request
  needs ``Authorization: Bearer <token>`` (compared in constant time); otherwise the API is
  open, the local-demo default. Swagger (``/docs``, ``/openapi.json``) stays readable.
* **Body limit** — a body larger than ``api.max_body_bytes`` is refused with 413, whether it
  announces its length or streams it.

(``ScanRequest.folder`` must stay inside ``api.allowed_source_roots`` — enforced where the scan
is created, AG02.1.)
"""

from __future__ import annotations

import hmac
import json

from aegis.observability import get_logger

__all__ = ["BearerAuthMiddleware", "BodyLimitMiddleware", "PROTECTED_PREFIXES"]

log = get_logger("api.security")

PROTECTED_PREFIXES = ("/api/", "/mcp")


async def _send_error(send, status: int, error: str, detail: str, headers: list[tuple[bytes, bytes]] = ()) -> None:
    body = json.dumps({"error": error, "detail": detail}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *headers],
    })
    await send({"type": "http.response.body", "body": body})


class BearerAuthMiddleware:
    def __init__(self, app, token: str | None):
        self.app = app
        self.token = token.encode("utf-8") if token else None

    async def __call__(self, scope, receive, send):
        if self.token is None or scope["type"] != "http" or not scope["path"].startswith(PROTECTED_PREFIXES):
            return await self.app(scope, receive, send)
        header = dict(scope.get("headers") or []).get(b"authorization", b"")
        scheme, _, given = header.partition(b" ")
        if scheme.lower() == b"bearer" and hmac.compare_digest(given.strip(), self.token):
            return await self.app(scope, receive, send)
        log.warning("api.auth_failed", method=scope["method"], path=scope["path"], reason="missing token" if not header else "wrong token")
        await _send_error(send, 401, "unauthorized", "a valid bearer token is required", [(b"www-authenticate", b"Bearer")])


class BodyLimitMiddleware:
    """Bodies are small (64 KB by default), so a body without a declared length is read in
    full first — refused with 413 as soon as it passes the limit — and then replayed."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def _refuse(self, scope, send, size: int):
        log.warning("api.body_too_large", path=scope["path"], bytes=size, limit=self.max_bytes)
        await _send_error(send, 413, "payload too large", f"request bodies are limited to {self.max_bytes} bytes")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope.get("headers") or []).get(b"content-length")
        if length is not None:
            if length.isdigit() and int(length) > self.max_bytes:
                return await self._refuse(scope, send, int(length))
            return await self.app(scope, receive, send)

        # no declared length (e.g. chunked): read it, within the limit, before the app sees it
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return await self.app(scope, receive, send)  # disconnect: let the app see it
            chunks.append(message.get("body", b""))
            size += len(chunks[-1])
            if size > self.max_bytes:
                return await self._refuse(scope, send, size)
            if not message.get("more_body"):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
