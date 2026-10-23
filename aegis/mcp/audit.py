"""Append-only audit log of every MCP call (MCP_PHASES MCP06.1, invariant M-4).

One JSON line per tool or resource call in ``<data_dir>/audit/mcp.jsonl`` (a file, not a table:
the database contracts are frozen — conflict C37). Arguments are summarised: ids, filters and
numbers are kept; free text (the ``ask`` question) is recorded only by its length; returned
payloads are never written. A failure to write is logged and never breaks the call.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.observability import get_logger

__all__ = ["AuditLog", "summarize_args"]

log = get_logger("mcp.audit")

_FREE_TEXT = frozenset({"question"})


def summarize_args(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in sorted(args.items()):
        if value is None:
            continue
        if key in _FREE_TEXT:
            out[f"{key}_chars"] = len(str(value))
        elif isinstance(value, (bool, int, float)):
            out[key] = value
        else:
            out[key] = str(value)[:80]
    return out


class AuditLog:
    def __init__(self, path: str | Path, *, transport: str = "stdio"):
        self.path = Path(path)
        self.transport = transport
        self._lock = threading.Lock()

    def record(self, name: str, args: dict[str, Any], *, status: str, duration_ms: int, kind: str = "tool") -> None:
        line = {
            "at": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "name": name,
            "transport": self.transport,
            "status": status,
            "duration_ms": duration_ms,
            "args": summarize_args(args),
        }
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(line, sort_keys=True) + "\n")
                    fh.flush()
        except OSError as exc:  # the audit must never break the call
            log.error("mcp.audit_write_failed", path=str(self.path), error=f"{type(exc).__name__}: {exc}")
