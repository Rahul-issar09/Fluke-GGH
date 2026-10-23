"""Live scan progress over SSE (AG13.2, FASTAPI FA04.1, SYSTEM_DESIGN §8.3).

``GET /api/scans/{id}/events`` replays the scan's recent events first (a late ``curl -N``
still sees earlier steps), then follows live ones, and ends after the terminal
``completed`` / ``failed`` / ``cancelled`` event. Each SSE message is ``event: progress`` with a
``ProgressEvent`` as JSON. A scan that finished before this server process started has no
in-memory history; its stream is the single terminal event taken from the scan's status.
Keep-alive comments are sent while a step is busy; a client disconnect removes the
subscription.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path
from sse_starlette.sse import EventSourceResponse

from aegis.api.deps import get_event_bus, get_scan_service
from aegis.api.schemas import ErrorOut
from aegis.observability import get_logger
from aegis.services.event_bus import TERMINAL_STATUSES, EventBus, make_event
from aegis.services.scan_service import ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])
log = get_logger("api.events")

PING_SECONDS = 15


@router.get(
    "/{scan_id}/events",
    summary="Follow a scan live (SSE)",
    description="Server-sent events: one `progress` event per finished step, then the scan's final status. "
    "Try it with `curl -N http://localhost:8000/api/scans/S-0001/events`.",
    responses={200: {"content": {"text/event-stream": {}}}, 404: {"model": ErrorOut}},
)
async def scan_events(
    scan_id: str = Path(pattern=r"^S-\d{4,}$"),
    scans: ScanService = Depends(get_scan_service),
    bus: EventBus = Depends(get_event_bus),
):
    finished = scans.is_finished(scan_id)  # raises 404 for an unknown scan
    status = scans.store.get_scan(scan_id).status.value

    async def stream():
        log.info("events.subscribed", scan_id=scan_id)
        try:
            if finished and not bus.history(scan_id):
                event = make_event(scan_id, "scan", "scan", status if status in TERMINAL_STATUSES else "completed")
                yield {"event": "progress", "data": event.model_dump_json()}
                return
            async for event in bus.stream(scan_id):
                yield {"event": "progress", "data": event.model_dump_json()}
        finally:
            log.info("events.closed", scan_id=scan_id)

    return EventSourceResponse(stream(), ping=PING_SECONDS)
