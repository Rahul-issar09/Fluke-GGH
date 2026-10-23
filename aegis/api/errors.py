"""Domain exceptions → HTTP responses (AG13.1, FASTAPI FA01.1).

Every error leaves as the frozen ``ErrorOut`` body: a short message, never a traceback or
internal detail. 4xx are logged at WARNING, 5xx at ERROR with the detail kept in the log.

| Exception                                      | Status |
|------------------------------------------------|--------|
| request validation / ``RequestInvalid``        | 422    |
| ``NotFound``, ``ScanNotFound``, ``QueryNotFound`` | 404 |
| ``Conflict``, ``ScanConflict``, ``IllegalTransition``, ``VerifyError`` | 409 |
| ``NotAvailable`` (built in a later phase)       | 501    |
| ``EgressBlocked``                              | 403    |
| ``FixServiceError``                            | its own code (404 / 409 / 422) |
| anything else                                  | 500, generic message |
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from aegis.api.schemas import ErrorOut
from aegis.evidence.state_machine import IllegalTransition
from aegis.fix.verifier import VerifyError
from aegis.observability import get_logger
from aegis.router import RequestInvalid
from aegis.safety.egress import EgressBlocked
from aegis.services.fix_service import FixServiceError
from aegis.services.query_service import NotAvailable, QueryNotFound
from aegis.services.scan_service import ScanConflict, ScanNotFound

__all__ = ["Conflict", "NotFound", "error_response", "install_error_handlers"]

log = get_logger("api.errors")


class NotFound(LookupError):
    """An unknown scan / finding / evidence / fix id."""

    def __init__(self, message: str, ids: list[str] | None = None):
        super().__init__(message)
        self.ids = ids


class Conflict(Exception):
    """A request that the current state does not allow (e.g. another scan is running)."""


def error_response(status: int, error: str, detail: str | None = None, ids: list[str] | None = None, headers: dict | None = None) -> JSONResponse:
    body = ErrorOut(error=error, detail=detail, ids=ids).model_dump(exclude_none=True)
    return JSONResponse(status_code=status, content=body, headers=headers)


def _client_error(request: Request, status: int, error: str, detail: str | None = None, ids: list[str] | None = None) -> JSONResponse:
    log.warning("http.client_error", method=request.method, path=request.url.path, status=status, error=error, detail=detail)
    return error_response(status, error, detail, ids)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        problems = "; ".join(f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg')}" for e in exc.errors()[:5])
        return _client_error(request, 422, "invalid request", problems)

    @app.exception_handler(RequestInvalid)
    async def _invalid(request: Request, exc: RequestInvalid):
        return _client_error(request, 422, "invalid request", str(exc))

    @app.exception_handler(NotFound)
    @app.exception_handler(QueryNotFound)
    @app.exception_handler(ScanNotFound)
    async def _not_found(request: Request, exc: Exception):
        return _client_error(request, 404, "not found", str(exc), getattr(exc, "ids", None))

    @app.exception_handler(NotAvailable)
    async def _not_available(request: Request, exc: NotAvailable):
        return _client_error(request, 501, "not available", str(exc))

    @app.exception_handler(ScanConflict)
    @app.exception_handler(Conflict)
    @app.exception_handler(IllegalTransition)
    @app.exception_handler(VerifyError)
    async def _conflict(request: Request, exc: Exception):
        return _client_error(request, 409, "conflict", str(exc))

    @app.exception_handler(EgressBlocked)
    async def _forbidden(request: Request, exc: EgressBlocked):
        return _client_error(request, 403, "forbidden", "the target is outside the scan's allowlist")

    @app.exception_handler(FixServiceError)
    async def _fix(request: Request, exc: FixServiceError):
        names = {404: "not found", 409: "conflict", 422: "invalid request"}
        return _client_error(request, exc.code, names.get(exc.code, "error"), str(exc))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        if exc.status_code >= 500:
            log.error("http.server_error", method=request.method, path=request.url.path, status=exc.status_code)
            return error_response(exc.status_code, "server error")
        names = {401: "unauthorized", 403: "forbidden", 404: "not found", 405: "method not allowed", 413: "payload too large"}
        return _client_error(request, exc.status_code, names.get(exc.status_code, "error"), exc.detail if isinstance(exc.detail, str) else None)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        # the detail stays in the log; the client only learns that something failed
        log.error("http.unhandled", method=request.method, path=request.url.path, error=f"{type(exc).__name__}: {str(exc)[:300]}", exc_info=exc)
        return error_response(500, "internal error", "the server could not complete the request; see the server log")
