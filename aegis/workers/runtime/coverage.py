"""Runtime coverage tracking (TNW).

A runtime scan that finds nothing is not proof the target is safe — a check may have been blocked
(login or the API description refused) or never attempted (no routes, no spec, a tool missing).
Each runtime step records what it managed to do as a scan-level ``coverage`` evidence record, and
the report turns those into a coverage section so a clean result is never mistaken for a clean bill
of health.

Status per capability:
  PASS        the check ran and established no finding
  FAILED      the check ran and established a finding (the target failed it)
  BLOCKED     the check could not run (login refused, API description 403, target unreachable)
  NOT_TESTED  the check was not attempted (nothing to test, or a tool is not installed)
"""

from __future__ import annotations

import json

__all__ = ["PASS", "FAILED", "BLOCKED", "NOT_TESTED", "CAPABILITIES", "record", "summarize", "is_limited"]

PASS, FAILED, BLOCKED, NOT_TESTED = "PASS", "FAILED", "BLOCKED", "NOT_TESTED"
_STATUSES = (PASS, FAILED, BLOCKED, NOT_TESTED)

# the runtime capabilities, in report order, with a human label
CAPABILITIES: dict[str, str] = {
    "discovery": "Route discovery",
    "authentication": "Authentication",
    "access_control": "Access control (BOLA)",
    "ssrf": "Server-side request forgery",
    "misconfig": "Misconfiguration / exposure",
    "api_conformance": "API conformance",
    "tls": "TLS posture",
}


def record(store, scan_id: str, capability: str, status: str, detail: str | None = None) -> None:
    """Write one coverage record (scan-level, not attached to a finding)."""
    assert capability in CAPABILITIES, capability
    assert status in _STATUSES, status
    store.add_evidence(
        scan_id, kind="coverage", tool="aegis.runtime",
        payload={"role": "coverage", "capability": capability, "status": status, "detail": detail},
    )


def summarize(store, scan_id: str) -> list[dict]:
    """The latest status per capability, in ``CAPABILITIES`` order. Capabilities never recorded
    (e.g. a code-only scan) are omitted."""
    latest: dict[str, dict] = {}
    for ev in store.list_evidence(scan_id, kind="coverage"):
        try:
            p = json.loads(ev.payload_json or "{}")
        except (ValueError, TypeError):
            continue
        if p.get("capability") in CAPABILITIES and p.get("status") in _STATUSES:
            latest[p["capability"]] = {"capability": p["capability"], "label": CAPABILITIES[p["capability"]],
                                       "status": p["status"], "detail": p.get("detail")}
    return [latest[c] for c in CAPABILITIES if c in latest]


def is_limited(rows: list[dict]) -> bool:
    """Whether any attempted capability was blocked or left untested — coverage is not complete."""
    return any(r["status"] in (BLOCKED, NOT_TESTED) for r in rows)
