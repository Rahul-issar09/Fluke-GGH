"""AEGIS LLM layer (AG01).

AG01.1: ``make_llm`` — the single place that builds the local Ollama chat
client. Every LLM node obtains its model through this factory so the model is
configurable (``AEGIS_MODEL`` / ``AEGIS_OLLAMA_URL``, SD §5.9) and the
constrained-decoding settings (temperature 0.1, ``num_ctx`` 8192,
``format="json"``) are applied uniformly (PRD §6.1).

Later sub-phases add ``structured_call`` (AG01.2) and wire the prompt guard
(AG01.3) in this package.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any, Callable, TypeVar

from langchain_core.exceptions import OutputParserException
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from pydantic import BaseModel, ValidationError

from aegis.config import ModelSettings, get_model_settings
from aegis.observability import get_logger

__all__ = ["make_llm", "structured_call"]

T = TypeVar("T", bound=BaseModel)

log = get_logger("agent.llm")

_logged_once = False

# One quiet second chance for a server-side failure (HTTP 5xx), e.g. Ollama's model runner
# crashing while it loads. "Model not found" (404) or "Ollama is down" are not retried.
TRANSIENT_RETRY_DELAY_S = 2.0


def _transient(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and status >= 500


async def _ainvoke(structured: Any, messages: list[Any]) -> Any:
    try:
        return await structured.ainvoke(messages)
    except Exception as exc:  # noqa: BLE001 - re-raised unless it is a server-side hiccup
        if not _transient(exc):
            raise
        log.warning("llm.transient_error", status=getattr(exc, "status_code", None), error=str(exc)[:200], retry_in_s=TRANSIENT_RETRY_DELAY_S)
        await asyncio.sleep(TRANSIENT_RETRY_DELAY_S)
        return await structured.ainvoke(messages)


def make_llm(settings: ModelSettings | None = None) -> ChatOllama:
    """Build a ``ChatOllama`` client from model settings.

    Constructing the client does not open a network connection; it is only
    contacted on invocation, so this is safe to call anywhere (including under
    the offline test guard).
    """
    cfg = settings or get_model_settings()
    global _logged_once
    if not _logged_once:
        log.info(
            "llm.configured",
            model=cfg.name,
            base_url=cfg.ollama_url,
            temperature=cfg.temperature,
            num_ctx=cfg.num_ctx,
        )
        _logged_once = True
    return ChatOllama(
        model=cfg.name,
        base_url=cfg.ollama_url,
        temperature=cfg.temperature,
        num_ctx=cfg.num_ctx,
        format="json",
    )


async def structured_call(
    schema: type[T],
    system: str,
    payload: dict[str, Any],
    validate: Callable[[T], list[str]],
    *,
    llm: Any | None = None,
    settings: ModelSettings | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> tuple[T | None, str]:
    """Make a schema-constrained LLM call: validate → retry once → fallback.

    :param schema: the Pydantic model the model must produce.
    :param system: system prompt (static instruction text only).
    :param payload: the sole user-visible input — must already be built from
        whitelisted, injection-safe fields (AG01.3 prompt guard).
    :param validate: returns a list of error strings ([] means valid).
    :param llm: optional pre-built structured runnable (tests inject a fake);
        when omitted, ``make_llm(settings).with_structured_output`` is used.
    :returns: ``(result, source)`` where ``source`` is ``"llm"`` (valid first
        try), ``"llm_retry"`` (valid after one corrective retry) or
        ``"fallback"`` (``result`` is ``None``; caller applies a rule default).

    ``trace``, when given, receives one ``{"attempt", "kind", "error"}`` entry per
    rejected attempt (``kind`` is ``"unparseable"`` or ``"invalid"``) so callers can
    audit what the model said and why it was refused.

    A server-side error (HTTP 5xx, e.g. the model runner crashing while it loads) is retried
    once after a short pause; any other transport error is raised for the caller to fall back.

    A malformed/unparseable response or a failed ``validate`` both count as
    "invalid": the first invalid result triggers one corrective retry; a second
    invalid result yields ``(None, "fallback")``. The graph never crashes on a
    bad model response.
    """
    structured = (
        llm
        if llm is not None
        else make_llm(settings).with_structured_output(schema, method="json_schema")
    )
    messages: list[Any] = [
        SystemMessage(content=system),
        HumanMessage(content=json.dumps(payload, default=str)),
    ]
    for attempt in ("llm", "llm_retry"):
        try:
            out = await _ainvoke(structured, messages)
        except (ValidationError, OutputParserException, ValueError) as exc:
            log.warning("llm.unparseable", attempt=attempt, error=str(exc)[:200])
            if trace is not None:
                trace.append({"attempt": attempt, "kind": "unparseable", "error": str(exc)[:300]})
            messages.append(
                HumanMessage(
                    content=(
                        "Your previous response was not valid JSON for the schema: "
                        f"{exc}. Respond again with valid JSON only."
                    )
                )
            )
            continue
        errors = validate(out)
        if inspect.isawaitable(errors):  # a validator may need to run a tool (e.g. git apply --check)
            errors = await errors
        if not errors:
            log.info("llm.ok", attempt=attempt)
            return out, attempt
        log.warning("llm.validation_failed", attempt=attempt, errors=errors)
        if trace is not None:
            trace.append({"attempt": attempt, "kind": "invalid", "error": "; ".join(errors)[:300]})
        messages.append(
            HumanMessage(
                content=(
                    f"Invalid: {errors}. Answer again using only allowed values "
                    "from the schema."
                )
            )
        )
    log.warning("llm.fallback")
    return None, "fallback"


def _reset_log_flag() -> None:
    """Test support: allow the one-time config log to fire again."""
    global _logged_once
    _logged_once = False
