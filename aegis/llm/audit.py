"""Append-only audit of model-provider changes (LLM_PROVIDER_PHASES §9.7).

One JSON line per event in ``<data_dir>/audit/llm.jsonl`` — a file, like the MCP audit, because
the database contracts are frozen. Events: ``provider_activated``, ``provider_deactivated``,
``key_stored``, ``key_rotated``, ``key_deleted``, ``consent_granted``, ``consent_revoked``,
``validation_failed``, ``cloud_blocked_by_policy``.

Fields are ids and outcomes only: who (``ui`` / ``cli`` / ``api`` / ``env`` / ``system``), the
generation, provider, model, the key's **fingerprint** — never the key. Every string is scrubbed
before it is written, as a last line of defence. A failure to write is logged and never breaks the
change it records.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.observability import get_logger
from aegis.secret_scrub import scrub

__all__ = ["EVENTS", "LlmAudit"]

log = get_logger("llm.audit")

EVENTS = frozenset({
    "provider_activated", "provider_deactivated", "key_stored", "key_rotated", "key_deleted",
    "consent_granted", "consent_revoked", "validation_failed", "cloud_blocked_by_policy", "secure_prompt",
})
_ALLOWED_FIELDS = frozenset({"actor", "client", "generation", "provider", "model", "previous_provider",
                             "previous_model", "key_fingerprint", "previous_key_fingerprint", "key_source",
                             "disclosure_version", "allow_source_code", "reason", "kind",
                             "prompt_chars", "bullets", "outcome"})


class LlmAudit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, event: str, **fields: Any) -> None:
        if event not in EVENTS:
            raise ValueError(f"unknown audit event {event!r}")
        unknown = set(fields) - _ALLOWED_FIELDS
        if unknown:  # a field that is not in the list could be anything — refuse rather than leak it
            raise ValueError(f"audit fields not allowed: {sorted(unknown)}")
        line = {"at": datetime.now(timezone.utc).isoformat(), "event": event}
        for key, value in sorted(fields.items()):
            if value is None:
                continue
            line[key] = scrub(value) if isinstance(value, str) else value
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(line, sort_keys=True) + "\n")
        except OSError as exc:  # the audit must never break the change it records
            log.error("llm.audit_write_failed", path=str(self.path), error=type(exc).__name__)

    def read(self) -> list[dict[str, Any]]:
        try:
            return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except FileNotFoundError:
            return []
