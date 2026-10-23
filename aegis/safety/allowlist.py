"""Host allowlist (PHASES P2.1).

Only hosts explicitly allowed for a scan may be contacted. Matching is on
``host:port``; a bare-host entry matches any port of that host. No DNS
resolution (offline), so an IP and a hostname are distinct.
"""

from __future__ import annotations

from collections.abc import Iterable

from aegis.observability import get_logger

__all__ = ["Allowlist"]

log = get_logger("safety.allowlist")


def _split(entry: str) -> tuple[str, int | None]:
    entry = entry.strip().lower()
    if ":" in entry:
        host, _, port = entry.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return entry, None


class Allowlist:
    def __init__(self, entries: Iterable[str]):
        self._entries: list[tuple[str, int | None]] = [_split(e) for e in entries if e.strip()]

    def check(self, host: str | None) -> bool:
        """True if *host* (``host`` or ``host:port``) is allowed."""
        if not host:
            log.warning("allowlist.blocked", target=host, reason="empty host")
            return False
        h, p = _split(host)
        for eh, ep in self._entries:
            if h == eh and (ep is None or ep == p):
                return True
        log.warning("allowlist.blocked", target=host)
        return False
