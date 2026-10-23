"""Scrub known secret values out of any text (LLM_PROVIDER_PHASES §9.3).

The one registry of secret values the process has seen (an API key entered or read this run, a
candidate key being validated). ``scrub`` replaces them — and anything shaped like a Google API key
— in a text. It has no dependencies, so the logging setup (``aegis.observability``), the stores and
the API can all use it without import cycles.
"""

from __future__ import annotations

import re
import threading
from typing import Any

__all__ = ["GOOGLE_KEY_PATTERN", "REDACTED", "REGISTRY", "SecretRegistry", "scrub"]

REDACTED = "[REDACTED]"
# Google API keys are "AIza" + 35 characters; a little slack catches truncated or padded copies too
GOOGLE_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z_\-]{30,60}")


class SecretRegistry:
    """Known secret values, so any text can be scrubbed of them before it is logged or stored."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = threading.Lock()

    def register(self, value: str | None) -> None:
        if value and len(value) >= 8:
            with self._lock:
                self._values.add(value)

    def scrub(self, text: Any) -> str:
        out = str(text)
        for value in sorted(self._values, key=len, reverse=True):
            if value in out:
                out = out.replace(value, REDACTED)
        return GOOGLE_KEY_PATTERN.sub(REDACTED, out)


REGISTRY = SecretRegistry()


def scrub(text: Any) -> str:
    return REGISTRY.scrub(text)
