"""Per-scan progress event bus (PHASES P3.5 / AG05.4).

Fans ``ProgressEvent``s out to any number of SSE subscribers. Each scan keeps a
bounded history (ring buffer) so a subscriber that connects late — e.g. a
``curl -N`` started after the scan began, or after it finished — first replays
what it missed and then follows live events.

A scan's stream ends after its terminal event
(``stage="scan", node="scan", status in {completed, failed, cancelled}``).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from aegis.api.schemas import ProgressEvent
from aegis.observability import get_logger

__all__ = ["EventBus", "make_event", "is_terminal", "TERMINAL_STATUSES"]

log = get_logger("services.event_bus")

TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})


def make_event(scan_id: str, stage: str, node: str, status: str, ms: int | None = None) -> ProgressEvent:
    return ProgressEvent(
        scan_id=scan_id,
        stage=stage,
        node=node,
        status=status,
        ms=ms,
        at=datetime.now(timezone.utc).isoformat(),
    )


def is_terminal(event: ProgressEvent) -> bool:
    return event.stage == "scan" and event.node == "scan" and event.status in TERMINAL_STATUSES


class EventBus:
    def __init__(self, history_size: int = 500):
        self._history_size = history_size
        self._history: dict[str, deque[ProgressEvent]] = defaultdict(
            lambda: deque(maxlen=self._history_size)
        )
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)

    def publish(self, event: ProgressEvent) -> None:
        self._history[event.scan_id].append(event)
        for queue in self._subs.get(event.scan_id, []):
            queue.put_nowait(event)
        log.debug(
            "event.published",
            scan_id=event.scan_id,
            stage=event.stage,
            node=event.node,
            status=event.status,
        )

    def history(self, scan_id: str) -> list[ProgressEvent]:
        return list(self._history.get(scan_id, ()))

    def subscriber_count(self, scan_id: str) -> int:
        return len(self._subs.get(scan_id, []))

    def forget(self, scan_id: str) -> None:
        self._history.pop(scan_id, None)

    async def stream(self, scan_id: str) -> AsyncIterator[ProgressEvent]:
        """Replay history, then follow live events until the terminal event.

        Registration and the history snapshot happen with no ``await`` between
        them, so no event is lost or duplicated. The subscription is removed
        when the consumer stops (disconnect → ``aclose()``).
        """
        queue: asyncio.Queue = asyncio.Queue()
        replay = list(self._history.get(scan_id, ()))
        self._subs[scan_id].append(queue)
        try:
            for event in replay:
                yield event
                if is_terminal(event):
                    return
            while True:
                event = await queue.get()
                yield event
                if is_terminal(event):
                    return
        finally:
            subs = self._subs.get(scan_id, [])
            if queue in subs:
                subs.remove(queue)
            if not subs:
                self._subs.pop(scan_id, None)
