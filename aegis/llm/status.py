"""Which model a scan used, and whether it could answer (LLM_PROVIDER_PHASES LP3, finding F-10).

When the model is down, scans still finish on rules and templates; before LP3 that was only
visible in the logs. ``scan_llm_summary`` derives a short, user-facing status from what is
already stored — the snapshot pinned in ``Scan.config_json["llm"]`` and the agent's decisions —
so the audit, the report and the CLI can say "AI unavailable: …" without any contract change.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

__all__ = ["LLM_NODES", "UNAVAILABLE_PREFIX", "scan_llm_summary"]

# the nodes that consult the model; their final (valid) decision per finding says how it went
LLM_NODES = ("investigate", "explain", "remediate")
UNAVAILABLE_PREFIX = "llm unavailable"


def scan_llm_summary(scan: Any, decisions: Iterable[Any]) -> dict[str, Any]:
    """``{provider, model, location, status, answered, unavailable, reason}``.

    ``status``: ``not_used`` (no model step ran), ``ok`` (every attempt reached the model),
    ``degraded`` (some answers fell back because the model was unavailable) or ``unavailable``
    (none reached it). Falling back because an answer was *refused* (invalid, uncited) is normal
    validation, not an outage, and does not change the status.
    """
    try:
        pinned = json.loads(getattr(scan, "config_json", None) or "{}").get("llm") or {}
    except (ValueError, AttributeError):
        pinned = {}
    finals = [d for d in decisions if d.node in LLM_NODES and d.valid]
    answered = sum(1 for d in finals if d.source in ("llm", "llm_retry"))
    outages = [d.error for d in finals if d.source == "fallback" and (d.error or "").startswith(UNAVAILABLE_PREFIX)]
    if not any(d.source in ("llm", "llm_retry", "fallback") for d in finals):
        status = "not_used"
    elif outages and not answered:
        status = "unavailable"
    elif outages:
        status = "degraded"
    else:
        status = "ok"
    return {
        "provider": pinned.get("provider"),
        "model": pinned.get("model"),
        "location": pinned.get("location"),
        "status": status,
        "answered": answered,
        "unavailable": len(outages),
        "reason": outages[0] if outages else None,
    }
