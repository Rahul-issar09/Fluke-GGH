"""FastAPI app factory and lifespan (AG13.1, FASTAPI FA00–FA01, SYSTEM_DESIGN §8.1).

``create_app()`` builds the app; the lifespan configures logging, then builds AEGIS with
:func:`aegis.services.runtime.open_runtime` — the same builder the ``aegis`` CLI uses — and keeps
the long-lived pieces on ``app.state`` (read through ``aegis.api.deps``). Shutdown cancels running
scans and closes the checkpointer and the database.

Every request gets a request ID (the caller's ``X-Request-ID`` if it is sane, else a new one),
bound into the log context so every log line of that request carries it, returned in the
response header, and logged once at the end with method, path, status and duration.
"""

from __future__ import annotations

import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI

from aegis.api.errors import install_error_handlers
from aegis.api.routers import ask, events, evidence, findings, fix, graph, health, llm, reports, scans, secure_prompt
from aegis.api.security import BearerAuthMiddleware, BodyLimitMiddleware, LocalHostGuardMiddleware
from aegis.config import AppSettings, get_app_settings
from aegis.observability import configure_logging, get_logger
# re-exported: callers and tests import these from aegis.api.main
from aegis.services.runtime import DATA_SUBDIRS, StartupError, check_model, ensure_dirs, open_runtime

__all__ = ["DATA_SUBDIRS", "StartupError", "check_model", "create_app", "ensure_dirs"]

log = get_logger("api")

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestContextMiddleware:
    """Request ID + one access-log line per request (FASTAPI FA01.2)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        given = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = given if _REQUEST_ID.match(given) else uuid.uuid4().hex[:16]
        status = 500
        started = time.monotonic()

        async def send_with_id(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", [])
                message["headers"] = [*message["headers"], (b"x-request-id", request_id.encode("latin-1"))]
            await send(message)

        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            await self.app(scope, receive, send_with_id)
        finally:
            duration = int((time.monotonic() - started) * 1000)
            level = "error" if status >= 500 else "warning" if status >= 400 else "info"
            getattr(log, level)("http.request", method=scope["method"], path=scope["path"], status=status, duration_ms=duration)
            structlog.contextvars.unbind_contextvars("request_id")


def _lifespan(settings: AppSettings, agent_overrides: dict[str, Any]):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging(settings.logging.level, settings.logging.json)
        async with open_runtime(settings, agent_overrides=agent_overrides) as rt:
            app.state.settings = rt.settings
            app.state.store = rt.store
            app.state.agent_deps = rt.agent_deps
            app.state.checkpointer = rt.checkpointer
            app.state.graph = rt.graph
            app.state.fix_graph = rt.fix_graph
            app.state.bus = rt.bus
            app.state.runner = rt.runner
            app.state.fix_service = rt.fix_service
            app.state.scan_service = rt.scan_service
            app.state.query_service = rt.query_service
            app.state.chat_service = rt.chat_service
            app.state.llm_manager = rt.llm_manager
            yield

    return lifespan


def _mount_mcp(app: FastAPI) -> None:
    try:
        from aegis.mcp import server as mcp_server

        app.mount("/mcp", mcp_server.sse_app())
        log.info("mcp.mounted", path="/mcp")
    except (ImportError, AttributeError) as exc:  # the MCP server is built in AG16
        log.warning("mcp.unavailable", reason=f"{type(exc).__name__}: the MCP server is not built yet")


def create_app(settings: AppSettings | None = None, *, agent_overrides: dict[str, Any] | None = None) -> FastAPI:
    """Build the API. ``agent_overrides`` replace ``AgentDeps`` fields (tests inject fakes)."""
    settings = settings or get_app_settings()
    app = FastAPI(
        title="AEGIS",
        version="0.1.0",
        summary="Offline, evidence-first AppSec & crypto-risk platform",
        description=(
            "Start a scan, follow its progress, read ranked findings with their evidence, "
            "approve a verified fix, and download the report. Everything runs locally."
        ),
        lifespan=_lifespan(settings, dict(agent_overrides or {})),
        openapi_tags=[
            {"name": "scans", "description": "Start a scan, follow it live, cancel it, CI gate and audit trail"},
            {"name": "findings", "description": "Ranked findings, their explanation and the evidence behind them"},
            {"name": "graph", "description": "Attack paths and the cryptography bill of materials"},
            {"name": "fix", "description": "Verify a drafted fix on a copy, then approve its commit"},
            {"name": "reports", "description": "The HTML / JSON report"},
            {"name": "ask", "description": "Questions about a scan (chat assistant, later phase)"},
            {"name": "llm", "description": "Choose the model AEGIS reasons with: offline (Ollama) or online (Gemini). "
                                           "The Gemini key is asked for every run and never saved"},
            {"name": "secure-prompt", "description": "Secure code for a plain request, explained against the OWASP Top 10 "
                                                     "(Gemini Online mode only; the code is not scanned or run)"},
            {"name": "health", "description": "What the backend can use right now"},
        ],
    )
    install_error_handlers(app)
    for module in (scans, events, findings, evidence, graph, fix, reports, ask, llm, secure_prompt, health):
        app.include_router(module.router)
    if settings.mcp_enabled:
        _mount_mcp(app)

    # outermost first at request time: request ID → host guard → auth → body limit → app
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.api.max_body_bytes)
    app.add_middleware(BearerAuthMiddleware, token=settings.api.auth_token)
    app.add_middleware(LocalHostGuardMiddleware, token=settings.api.auth_token, allowed_hosts=settings.api.allowed_hosts)
    app.add_middleware(RequestContextMiddleware)
    return app
