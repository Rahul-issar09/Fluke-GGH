"""Job runner + checkpointer (PHASES P3.5 / AG05.4).

Runs scans in the background, one at a time (semaphore = 1, hardware budget),
streams per-node progress to the :class:`EventBus`, keeps the ``Scan`` row's
status current, and supports cancel and resume.

* Progress comes from ``graph.astream(stream_mode="updates", subgraphs=True)``.
  ``subgraphs=True`` is what surfaces the steps inside a worker stage (conflict
  C24); their namespace prefix (``runtime:<id>``) gives the stage name.
* The graph is checkpointed per ``thread_id = scan_id`` (``AsyncSqliteSaver``),
  so an interrupted run can be resumed after a restart.
* A run that ends with nodes still pending (an interrupt) is reported as
  *paused*, never as completed.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from aegis.agent.deps import AgentDeps
from aegis.api.schemas import ProgressEvent
from aegis.evidence.models import ScanStatus
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.services.event_bus import EventBus, make_event

__all__ = ["CHECKPOINT_TYPES", "JobRunner", "open_checkpointer", "events_from_update"]

log = get_logger("services.job_runner")


# The only model types a checkpoint may hold (AegisState: mode, inputs, pending_actions). LangGraph
# refuses to rebuild anything else from a checkpoint — an explicit allowlist, not "any class".
CHECKPOINT_TYPES = (
    ("aegis.evidence.models", "Mode"),
    ("aegis.agent.state", "ScanInputs"),
    ("aegis.agent.schemas", "NextStepDecision"),
    ("aegis.agent.schemas", "NextStep"),
    ("aegis.agent.schemas", "Target"),
)


@asynccontextmanager
async def open_checkpointer(path: str | Path) -> AsyncIterator[AsyncSqliteSaver]:
    """Open the LangGraph SQLite checkpointer (``data/checkpoints.db``)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(p)) as conn:
        yield AsyncSqliteSaver(conn, serde=JsonPlusSerializer(allowed_msgpack_modules=list(CHECKPOINT_TYPES)))


def events_from_update(
    scan_id: str, namespace: tuple[str, ...], update: Any, ms: int
) -> list[ProgressEvent]:
    """Turn one ``astream(updates, subgraphs=True)`` item into ProgressEvents.

    Parent-level node ``n`` → stage ``n``; a step inside a worker stage arrives
    with namespace ``("runtime:<id>",)`` → stage ``runtime``.
    """
    if not isinstance(update, dict):
        return []
    stage_prefix = namespace[0].split(":", 1)[0] if namespace else None
    events: list[ProgressEvent] = []
    for node in update:
        if node.startswith("__"):  # __interrupt__ etc.
            continue
        events.append(make_event(scan_id, stage_prefix or node, node, "done", ms))
    return events


class JobRunner:
    def __init__(
        self,
        store: EvidenceStore,
        bus: EventBus | None = None,
        deps: AgentDeps | None = None,
        max_concurrent_scans: int = 1,
    ):
        self.store = store
        self.bus = bus or EventBus()
        self.deps = deps
        self._sem = asyncio.Semaphore(max_concurrent_scans)
        self.tasks: dict[str, asyncio.Task] = {}

    # --- public API ------------------------------------------------------- #
    def submit(self, scan_id: str, graph: Any, init_state: dict | None) -> asyncio.Task:
        """Start (or, with ``init_state=None``, resume) a scan in the background."""
        task = asyncio.create_task(self._run(scan_id, graph, init_state), name=f"scan-{scan_id}")
        self.tasks[scan_id] = task
        task.add_done_callback(lambda t, sid=scan_id: self._on_done(sid, t))
        log.info("job.submitted", scan_id=scan_id, resume=init_state is None)
        return task

    def resume(self, scan_id: str, graph: Any) -> asyncio.Task:
        """Continue a paused/interrupted scan from its last checkpoint."""
        return self.submit(scan_id, graph, None)

    async def wait(self, scan_id: str) -> None:
        task = self.tasks.get(scan_id)
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a queued or running scan. False if it is not active."""
        task = self.tasks.get(scan_id)
        if task is None or task.done():
            return False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return True

    async def shutdown(self) -> None:
        for scan_id in list(self.tasks):
            await self.cancel(scan_id)

    # --- internals -------------------------------------------------------- #
    def _on_done(self, scan_id: str, task: asyncio.Task) -> None:
        if self.tasks.get(scan_id) is task:
            self.tasks.pop(scan_id, None)

    def _set_status(self, scan_id: str, status: ScanStatus, **fields: Any) -> None:
        self.store.update_scan(scan_id, status=status, **fields)
        log.info("scan.status", scan_id=scan_id, status=status.value)

    def _record_failure(self, scan_id: str, reason: str) -> None:
        scan = self.store.get_scan(scan_id)
        cfg = json.loads(scan.config_json) if scan and scan.config_json else {}
        cfg["failure_reason"] = reason
        self.store.update_scan(scan_id, config_json=json.dumps(cfg))

    def _emit_scan(self, scan_id: str, status: str) -> None:
        self.bus.publish(make_event(scan_id, "scan", "scan", status, None))

    @staticmethod
    async def _is_paused(graph: Any, cfg: dict) -> bool:
        if getattr(graph, "checkpointer", None) in (None, False):
            return False
        snapshot = await graph.aget_state(cfg)
        return bool(snapshot.next)

    async def _run(self, scan_id: str, graph: Any, init_state: dict | None) -> None:
        cfg = {"configurable": {"thread_id": scan_id, "deps": self.deps}}
        try:
            async with self._sem:
                self._set_status(scan_id, ScanStatus.running, started_at=datetime.now(timezone.utc))
                self._emit_scan(scan_id, "running")

                last = time.monotonic()
                async for namespace, update in graph.astream(
                    init_state, cfg, stream_mode="updates", subgraphs=True
                ):
                    now = time.monotonic()
                    ms = int((now - last) * 1000)
                    last = now
                    for event in events_from_update(scan_id, namespace, update, ms):
                        self.bus.publish(event)

                if await self._is_paused(graph, cfg):
                    self._set_status(scan_id, ScanStatus.awaiting_approval)
                    self._emit_scan(scan_id, "paused")
                else:
                    self._set_status(
                        scan_id, ScanStatus.completed, finished_at=datetime.now(timezone.utc)
                    )
                    self._emit_scan(scan_id, "completed")
        except asyncio.CancelledError:
            self._set_status(scan_id, ScanStatus.cancelled, finished_at=datetime.now(timezone.utc))
            self._emit_scan(scan_id, "cancelled")
            raise
        except Exception as exc:  # noqa: BLE001 - any node failure fails the scan, never the server
            reason = f"{type(exc).__name__}: {str(exc)[:300]}"
            log.error("scan.failed", scan_id=scan_id, reason=reason)
            self._record_failure(scan_id, reason)
            self._set_status(scan_id, ScanStatus.failed, finished_at=datetime.now(timezone.utc))
            self._emit_scan(scan_id, "failed")
