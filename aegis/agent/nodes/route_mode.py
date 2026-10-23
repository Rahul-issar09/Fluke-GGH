"""route_mode node (AG05.2) — deterministic mode selection, never the LLM.

Derives the scan mode from the request inputs (url only → runtime,
folder/repo only → code, both → correlated). If the run carries no inputs, the
mode already present in state is kept.
"""

from __future__ import annotations

from aegis.agent.state import ScanInputs
from aegis.api.schemas import ScanRequest
from aegis.evidence.models import Mode
from aegis.observability import get_logger
from aegis.router import select_mode

log = get_logger("agent.node.route_mode")


def _inputs(state: dict) -> ScanInputs:
    raw = state.get("inputs")
    if isinstance(raw, ScanInputs):
        return raw
    return ScanInputs(**(raw or {}))


def route_mode(state: dict) -> dict:
    scan_id = state.get("scan_id")
    log.info("node.enter", node="route_mode", scan_id=scan_id)
    inputs = _inputs(state)

    if any((inputs.url, inputs.folder, inputs.repo)):
        mode = select_mode(
            ScanRequest(
                url=inputs.url,
                folder=inputs.folder,
                repo=inputs.repo,
                identities=inputs.identities,
            )
        )
    elif state.get("mode") is not None:
        mode = Mode(state["mode"])
        log.warning("node.route_mode.no_inputs_keeping_state_mode", scan_id=scan_id, mode=mode.value)
    else:
        raise ValueError("route_mode needs inputs (url/folder/repo) or a preset mode")

    log.info("node.exit", node="route_mode", scan_id=scan_id, mode=mode.value)
    return {"mode": mode, "completed_stages": ["route_mode"]}
