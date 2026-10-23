"""AEGIS prompt guard (AG01.3) — injection defence for every LLM call.

Guarantees that no raw evidence or target-supplied content ever reaches a
prompt (PRD FR-S6, SD §5.1). An LLM node must build its payload through
:func:`build_payload`, which:

* accepts only whitelisted, normalized fields (type / route / function /
  file:line / state / scores / evidence IDs / evidence **digests** / the
  valid next-step set),
* explicitly rejects known raw-payload field names (``payload_json``,
  ``request``, ``response``, ``body``, source ``code``/``comment`` …),
* rejects any non-inert value (objects, sets — only str/num/bool/None and
  lists/dicts of those pass),
* enforces a byte budget on the serialized payload.

Evidence **digests** are produced deterministically elsewhere
(``evidence/digest.py``, P5.6) from structured fields only; even if a digest
string happens to contain attacker-style text, it travels here as inert JSON
data in the Human message, never as instructions in the system prompt.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

__all__ = [
    "PromptGuardError",
    "build_payload",
    "to_messages",
    "PROMPT_GUARD_MAX_BYTES",
    "ALLOWED_KEYS",
]

PROMPT_GUARD_MAX_BYTES = 4000

# Normalized fields that may enter an LLM payload.
ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "finding_id",
        "type",
        "owasp",
        "title",
        "state",
        "mode",
        "route",
        "function",
        "file",
        "line",
        "where",
        "scores",
        "risk",
        "correlation",
        "severity",
        "evidence_ids",
        "evidence_digests",
        "valid_next_steps",
        # Remediation only (AG10.2). ``handler_source`` is the user's own handler code with
        # comments, docstrings and secret literals already replaced by placeholders (see
        # ``aegis.fix.draft.hide_untrusted``); ``fix_hint`` is a fixed template. Raw ``code`` /
        # ``snippet`` / ``source`` stay forbidden.
        "handler_source",
        "fix_hint",
        # Chatbot context (RAG07). ``question`` is the user's query; ``findings`` is the list of
        # retrieved findings, each a dict of validated, safe fields (``what``/``impact``/
        # ``exploit``/``fix``/``where``/``summary``) + ``evidence_digests``. These texts are the
        # kept claims + digests — already injection-safe (R-3) — never raw payloads or source.
        "question",
        "findings",
        "what",
        "impact",
        "exploit",
        "fix",
        "summary",
    }
)

# Raw-content field names that must never reach a prompt — rejected with a
# pointed message even though they are already absent from ALLOWED_KEYS.
_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "payload",
        "payload_json",
        "request",
        "response",
        "body",
        "headers",
        "cookies",
        "code",
        "snippet",
        "raw",
        "stderr",
        "source",
        "comment",
        "comments",
    }
)

_INERT_SCALARS = (str, int, float, bool, type(None))


class PromptGuardError(ValueError):
    """Raised when a payload would carry non-whitelisted or raw content."""


def _check_value(key: str, value: Any) -> None:
    if isinstance(value, bool) or isinstance(value, _INERT_SCALARS):
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_value(key, item)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise PromptGuardError(f"field '{key}' has a non-string dict key")
            _check_value(key, v)
        return
    raise PromptGuardError(
        f"field '{key}' has non-inert value type '{type(value).__name__}'"
    )


def build_payload(
    allowed_fields: dict[str, Any], *, max_bytes: int = PROMPT_GUARD_MAX_BYTES
) -> dict[str, Any]:
    """Return a safe payload dict or raise :class:`PromptGuardError`."""
    out: dict[str, Any] = {}
    for key, value in allowed_fields.items():
        if key in _FORBIDDEN_KEYS:
            raise PromptGuardError(f"forbidden raw-content field '{key}' may not enter a prompt")
        if key not in ALLOWED_KEYS:
            raise PromptGuardError(f"field '{key}' is not in the prompt whitelist")
        _check_value(key, value)
        out[key] = value

    blob = json.dumps(out, default=str)
    size = len(blob.encode("utf-8"))
    if size > max_bytes:
        raise PromptGuardError(f"payload exceeds budget ({size} > {max_bytes} bytes)")
    return out


def to_messages(
    system: str, allowed_fields: dict[str, Any], *, max_bytes: int = PROMPT_GUARD_MAX_BYTES
) -> list[Any]:
    """Build ``[SystemMessage(system), HumanMessage(<guarded payload JSON>)]``.

    The static instruction is the system message; all finding-derived data is
    confined to the Human message, so injection text in a digest can never be
    read as a system instruction.
    """
    payload = build_payload(allowed_fields, max_bytes=max_bytes)
    return [
        SystemMessage(content=system),
        HumanMessage(content=json.dumps(payload, default=str)),
    ]
