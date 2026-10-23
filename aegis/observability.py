"""AEGIS observability — one JSON logger for the whole app, with bound context.

Implements AGENT_PHASES AG00.1. structlog is layered over the stdlib ``logging``
module via ``ProcessorFormatter`` so that:

* every AEGIS logger (``get_logger("<area>")``) emits structured JSON,
* logs from third-party libraries (langgraph, httpx, uvicorn) get the same
  treatment through the stdlib root handler,
* the context bound with :func:`bind` (``scan_id`` / ``node`` / ``tool`` /
  ``request_id``) is attached to every record,
* known secret / raw-payload fields are redacted before anything is written.

Global rule #1 (see AGENT_PHASES §0): every module logs through
``get_logger("<area>")``; there is no ``print()`` anywhere in ``aegis/``.
"""

from __future__ import annotations

import logging
from typing import Any

import structlog

from aegis.secret_scrub import scrub

__all__ = [
    "configure_logging",
    "get_logger",
    "bind",
    "clear_ctx",
    "redact",
    "reset_logging",
    "REDACTED",
]

REDACTED = "***REDACTED***"

# Substring markers: if any appears in a field name, the value is redacted.
# Kept narrow so benign names (request_id, status_code, node) are never hit.
_SECRET_MARKERS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "private_key",
)

# Exact field names that carry raw target content (HTTP bodies, source code,
# tool stderr, evidence payloads). Matched exactly so "request_id" survives
# while "request" is dropped.
_PAYLOAD_KEYS: frozenset[str] = frozenset(
    {
        "payload",
        "payload_json",
        "request",
        "response",
        "body",
        "snippet",
        "code",
        "stderr",
        "raw",
    }
)

# Idempotency guard: AG00.1 failure case — a second configure must not add a
# duplicate handler.
_configured = False


def _should_redact(key: str) -> bool:
    k = key.lower()
    if k in _PAYLOAD_KEYS:
        return True
    return any(marker in k for marker in _SECRET_MARKERS)


def redact(obj: Any) -> Any:
    """Return a copy of *obj* with secret/payload fields replaced.

    Recurses through dicts, lists and tuples. Non-container values pass
    through unchanged. Used both as a structlog processor backstop and as a
    helper callers can apply to anything before logging it.
    """
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and _should_redact(key):
                out[key] = REDACTED
            else:
                out[key] = redact(value)
        return out
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact(v) for v in obj)
    if isinstance(obj, str):
        # a known secret value (an API key) inside any text — e.g. an exception message (§9.3)
        return scrub(obj)
    return obj


def _redact_processor(_logger: Any, _method: str, event_dict: dict) -> dict:
    """structlog processor: redact the whole event dict before rendering."""
    return redact(event_dict)


def _level_to_int(level: str | int) -> int:
    if isinstance(level, int):
        return level
    return getattr(logging, str(level).upper(), logging.INFO)


def configure_logging(level: str | int = "INFO", json: bool = True, stream: Any | None = None) -> None:
    """Configure structlog + stdlib logging once for the whole process.

    :param level: log level name or int (default ``"INFO"``).
    :param json: JSON output when True, human-readable console output otherwise.
    :param stream: optional stream for the root handler (defaults to stderr);
        used by tests to capture output deterministically.

    Calling this more than once is a no-op (idempotent) so importing modules
    cannot accumulate duplicate handlers.
    """
    global _configured
    if _configured:
        return

    lvl = _level_to_int(level)

    # Shared processor chain: applied to AEGIS (structlog) records via
    # ``structlog.configure`` and to foreign (stdlib) records via the
    # ProcessorFormatter's ``foreign_pre_chain``.
    pre_chain = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_processor,
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer(colors=False)
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=pre_chain,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(lvl)

    structlog.configure(
        processors=pre_chain + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(area: str) -> Any:
    """Return the namespaced logger ``aegis.<area>``.

    Example: ``log = get_logger("workers.runtime")`` →
    ``log.info("event", scan_id=...)`` emits JSON with bound context.
    """
    return structlog.stdlib.get_logger(f"aegis.{area}")


def bind(**ctx: Any) -> None:
    """Bind context values onto the current async/thread context.

    Standard keys are ``scan_id``, ``node``, ``tool`` and ``request_id``; they
    appear on every subsequent log record until cleared.
    """
    structlog.contextvars.bind_contextvars(**ctx)


def clear_ctx() -> None:
    """Clear all bound context values."""
    structlog.contextvars.clear_contextvars()


def reset_logging() -> None:
    """Tear down logging configuration (test support).

    Clears the idempotency guard, removes root handlers, resets structlog to
    its defaults and clears bound context.
    """
    global _configured
    _configured = False
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    structlog.reset_defaults()
    clear_ctx()
