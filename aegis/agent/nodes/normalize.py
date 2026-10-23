"""normalize node (stub in AG05.1)."""
from __future__ import annotations

from aegis.observability import get_logger

log = get_logger("agent.node.normalize")


def normalize(state: dict) -> dict:
    log.info("node.enter", node="normalize", scan_id=state.get("scan_id"))
    return {"completed_stages": ["normalize"]}
