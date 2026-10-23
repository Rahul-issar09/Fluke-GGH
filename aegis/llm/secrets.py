"""Where the Gemini API key comes from, and keeping it out of every text AEGIS writes (§9.3).

Decision Q-4 (revised 2026-10-22): **the key is asked for every run and kept in memory only — AEGIS
never saves it** (no file, no database, no OS key store). First match wins:

1. ``AEGIS_LLM__GEMINI__API_KEY`` — an environment variable the operator set (CI, a service manager);
2. ``AEGIS_LLM__GEMINI__API_KEY_FILE`` — a file holding only the key (a Docker secret);
3. the key entered in this session (``put``), held in this process's memory until it stops or the
   key is forgotten. A restart forgets it: Online mode then waits until the key is entered again.

The SDKs' own variables (``GOOGLE_API_KEY``, ``GEMINI_API_KEY``) are deliberately **not** read: an
unrelated Google key on the machine must never be used by accident.

Every key AEGIS reads or is given is registered with the process-wide :data:`REGISTRY`, whose
``scrub`` replaces known key values (and anything shaped like a Google API key) in a text — used by
the logging setup, the stores, the API and the MCP server.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr

from aegis.llm.base import LlmError
from aegis.observability import get_logger
from aegis.secret_scrub import GOOGLE_KEY_PATTERN, REGISTRY, SecretRegistry, scrub  # re-exported

__all__ = [
    "ENV_KEY", "ENV_KEY_FILE", "GOOGLE_KEY_PATTERN", "REGISTRY", "SecretRegistry", "SecretStore", "StoredKey",
    "check_key_shape", "fingerprint", "last4", "scrub",
]

log = get_logger("llm.secrets")

ENV_KEY = "AEGIS_LLM__GEMINI__API_KEY"
ENV_KEY_FILE = "AEGIS_LLM__GEMINI__API_KEY_FILE"
_SHAPE = re.compile(r"^[A-Za-z0-9_\-.]{20,200}$")


def fingerprint(key: str) -> str:
    """Tells keys apart without revealing them: ``sha256:`` and the first 16 hex digits."""
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def last4(key: str) -> str | None:
    """The key's last four characters, to recognise it (decision Q-5) — only for a long key."""
    tail = key[-4:]
    return tail if len(key) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]{4}", tail) else None


def check_key_shape(key: str) -> str:
    """The key, stripped, if it looks like an API key at all; else a usage error (no network call)."""
    key = (key or "").strip()
    if not _SHAPE.match(key):
        raise LlmError("invalid_api_key", "that does not look like an API key (20-200 letters, digits, '-', '_')",
                       provider="gemini")
    return key


@dataclass(frozen=True)
class StoredKey:
    value: SecretStr
    source: Literal["env", "file", "session"]

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.value.get_secret_value())

    @property
    def last4(self) -> str | None:
        return last4(self.value.get_secret_value())

    def describe(self) -> dict[str, Any]:
        """Safe to show anywhere."""
        return {"configured": True, "source": self.source, "fingerprint": self.fingerprint, "last4": self.last4}


class SecretStore:
    """The key in effect. One instance per process, shared by the manager and the providers."""

    def __init__(self, environ: Mapping[str, str] | None = None, *, registry: SecretRegistry = REGISTRY):
        self._environ = environ
        self._registry = registry
        self._session: str | None = None
        self._lock = threading.Lock()

    def _env(self) -> Mapping[str, str]:
        return os.environ if self._environ is None else self._environ

    def get(self) -> StoredKey | None:
        """The key in effect, or ``None``. Never raises."""
        env = self._env()
        value = (env.get(ENV_KEY) or "").strip()
        if value:
            return self._found(value, "env")
        path = (env.get(ENV_KEY_FILE) or "").strip()
        if path:
            try:
                value = Path(path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                log.error("secrets.key_file_unreadable", path=path, error=type(exc).__name__)
                value = ""
            if value:
                return self._found(value, "file")
        with self._lock:
            value = self._session
        return StoredKey(SecretStr(value), "session") if value else None

    def _found(self, value: str, source: Literal["env", "file"]) -> StoredKey:
        self._registry.register(value)
        return StoredKey(SecretStr(value), source)

    def managed_by_environment(self) -> bool:
        env = self._env()
        return bool((env.get(ENV_KEY) or "").strip() or (env.get(ENV_KEY_FILE) or "").strip())

    def put(self, key: str) -> StoredKey:
        """Use *key* for this session: memory only, never written anywhere."""
        key = check_key_shape(key)
        self._registry.register(key)
        with self._lock:
            self._session = key
        log.info("secrets.key_entered", source="session", fingerprint=fingerprint(key))
        return StoredKey(SecretStr(key), "session")

    def delete(self) -> bool:
        """Forget this session's key; ``False`` if none was entered (environment/file keys stay)."""
        with self._lock:
            had, self._session = self._session is not None, None
        if had:
            log.info("secrets.key_forgotten", source="session")
        return had
