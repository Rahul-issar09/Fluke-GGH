"""Errors → exit codes (CLI_PHASES.md section 6).

| Code | Meaning |
|------|---------|
| 0    | success (and a clean ``gate``) |
| 1    | the operation ran and reported failure (``gate``: blocking findings) |
| 2    | usage error (bad arguments, a refused request) · ``gate``: scan not complete |
| 3    | not found (unknown scan / finding / evidence / fix id) |
| 4    | conflict (another scan running, fix not waiting for approval) |
| 5    | unavailable (Ollama, model, scanner, API or a feature not built yet) |
| 130  | interrupted (Ctrl+C) |

Domain exceptions are recognised by their class name and module (walking the class hierarchy), so
this module imports none of the heavy AEGIS packages — ``aegis --help`` stays fast.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

import typer

__all__ = [
    "OK", "FAILED", "USAGE", "NOT_FOUND", "CONFLICT", "UNAVAILABLE", "INTERRUPTED",
    "CliError", "classify", "cli_command",
]

OK, FAILED, USAGE, NOT_FOUND, CONFLICT, UNAVAILABLE, INTERRUPTED = 0, 1, 2, 3, 4, 5, 130

F = TypeVar("F", bound=Callable[..., Any])


class CliError(Exception):
    """An error the CLI reports itself, with its exit code and an optional hint."""

    def __init__(self, message: str, code: int = FAILED, hint: str | None = None):
        super().__init__(message)
        self.code = code
        self.hint = hint


# module-qualified class names of AEGIS's own errors
_BY_CLASS: dict[str, int] = {
    "aegis.services.scan_service.ScanNotFound": NOT_FOUND,
    "aegis.services.query_service.QueryNotFound": NOT_FOUND,
    "aegis.api.errors.NotFound": NOT_FOUND,
    "aegis.services.scan_service.ScanConflict": CONFLICT,
    "aegis.api.errors.Conflict": CONFLICT,
    "aegis.evidence.state_machine.IllegalTransition": CONFLICT,
    "aegis.fix.verifier.VerifyError": CONFLICT,
    "aegis.router.RequestInvalid": USAGE,
    "aegis.router.RepoScanUnavailable": UNAVAILABLE,
    "aegis.services.query_service.NotAvailable": UNAVAILABLE,
    "aegis.services.read_services.NoAegisData": UNAVAILABLE,
    "aegis.services.runtime.StartupError": UNAVAILABLE,
    "aegis.safety.model_host.ModelHostRefused": UNAVAILABLE,
    "aegis.safety.egress.EgressBlocked": UNAVAILABLE,
    "aegis.chat.embedder.EmbeddingUnavailable": UNAVAILABLE,
    "aegis.chat.chroma_store.ChromaUnavailable": UNAVAILABLE,
    "httpx.HTTPError": UNAVAILABLE,
}
_FIX_SERVICE_ERROR = "aegis.services.fix_service.FixServiceError"
_HTTP_STATUS = {404: NOT_FOUND, 409: CONFLICT, 422: USAGE}


def _names(exc: BaseException) -> list[str]:
    return [f"{cls.__module__}.{cls.__qualname__}" for cls in type(exc).__mro__]


def classify(exc: BaseException) -> tuple[int, str, str | None]:
    """``(exit code, message, hint)`` for any exception."""
    if isinstance(exc, CliError):
        return exc.code, str(exc), exc.hint
    if isinstance(exc, KeyboardInterrupt):
        return INTERRUPTED, "interrupted", None
    names = _names(exc)
    if _FIX_SERVICE_ERROR in names:
        return _HTTP_STATUS.get(getattr(exc, "code", 409), CONFLICT), str(exc), None
    for name in names:
        if name in _BY_CLASS:
            return _BY_CLASS[name], str(exc) or type(exc).__name__, None
    return FAILED, f"unexpected error: {type(exc).__name__}: {exc}", "run again with --verbose for details"


def cli_command(fn: F) -> F:
    """Wrap a command: any error is reported on stderr and becomes the matching exit code.

    The command should take a ``typer.Context`` parameter so the error is rendered with its output
    settings (``--json``, colour, ``--quiet``)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - every failure gets a clean exit code
            if type(exc).__module__.startswith("typer"):
                raise   # Exit, Abort, usage errors: Typer handles them
            code, message, hint = classify(exc)
            from aegis.cli.context import current

            # Typer passes its internal Context class (not always the public typer.Context): match by shape
            typer_ctx = next((a for a in (*args, *kwargs.values()) if hasattr(a, "obj") and hasattr(a, "find_root")), None)
            ctx = current(typer_ctx)
            if ctx is not None:
                ctx.out.error(message, hint)
                if ctx.verbose >= 2 and code == FAILED:
                    import traceback

                    ctx.out._err("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
            else:
                typer.echo(f"error: {message}", err=True)
            raise typer.Exit(code) from None

    return wrapper  # type: ignore[return-value]
