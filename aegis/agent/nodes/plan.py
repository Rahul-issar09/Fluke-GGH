"""plan node (AG05.2) — rule-based ordered stage list for the detected mode.

``next_stage`` (graph.py) then walks this list one unfinished stage at a time,
which keeps scanners sequential within the memory budget.
"""

from __future__ import annotations

from aegis.evidence.models import Mode
from aegis.observability import get_logger
from aegis.router import build_plan

log = get_logger("agent.node.plan")


def plan(state: dict) -> dict:
    scan_id = state.get("scan_id")
    log.info("node.enter", node="plan", scan_id=scan_id)
    mode = Mode(state["mode"])
    stage_plan = build_plan(mode)
    log.info("node.exit", node="plan", scan_id=scan_id, mode=mode.value, plan=stage_plan)
    return {"plan": stage_plan, "completed_stages": ["plan"]}
