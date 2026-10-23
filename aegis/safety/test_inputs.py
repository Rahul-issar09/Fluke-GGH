"""Approved test-input library (PHASES P2.3).

Payloads come only from a fixed, reviewed library and are referenced by ID.
The agent can never supply a raw payload (FR-S3). ``{scan_id}`` is substituted
at resolve time, and ``{callback}`` with the configured callback listener
(``safety.callback_url``). That address comes from the operator's configuration,
never from the agent, and must be a bare ``http(s)://host[:port]``.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from aegis.observability import get_logger

__all__ = ["DEFAULT_CALLBACK_URL", "UnknownTestInput", "TestInputLibrary", "check_callback_url"]

log = get_logger("safety.test_inputs")

_DEFAULT_PATH = Path(__file__).with_name("test_inputs.yaml")
DEFAULT_CALLBACK_URL = "http://callback:8080"


def check_callback_url(url: str) -> str:
    """The listener's base URL, normalized; ValueError unless it is a bare ``http(s)://host[:port]``."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"callback_url must be http(s)://host[:port], got {url!r}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(f"callback_url must be a bare http(s)://host[:port], got {url!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


class UnknownTestInput(KeyError):
    """A test-input ID is not in the approved library."""


class TestInputLibrary:
    __test__ = False  # not a pytest test class despite the "Test" prefix

    def __init__(self, data: dict, callback_url: str = DEFAULT_CALLBACK_URL):
        self._data = data
        self._callback = check_callback_url(callback_url)

    @classmethod
    def load(cls, path: str | Path | None = None, *, callback_url: str = DEFAULT_CALLBACK_URL) -> "TestInputLibrary":
        p = Path(path) if path else _DEFAULT_PATH
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(data, callback_url)

    def resolve(self, input_id: str, scan_id: str) -> str:
        """Return the resolved value for *input_id*, or raise.

        Only known IDs are accepted; a raw payload string is never a valid ID.
        """
        entry = self._data.get(input_id)
        if entry is None:
            log.warning("test_inputs.unknown", input_id=input_id)
            raise UnknownTestInput(input_id)
        value = str(entry.get("value", ""))
        return value.replace("{callback}", self._callback).replace("{scan_id}", scan_id)

    def klass(self, input_id: str) -> str | None:
        entry = self._data.get(input_id)
        return entry.get("class") if entry else None
