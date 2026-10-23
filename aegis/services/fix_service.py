"""Fix service — the API's way into the fix graph (AG11.2, PHASES P12.7–P12.8).

* ``start(finding_id)`` verifies the finding's latest draft (thread ``fix_id``) and stops at
  the approval interrupt, or ends if verification failed.
* ``get(fix_id)`` reports the attempt, its diff and verify report, and whether it is waiting
  for approval (read from the checkpoint, so it survives a restart).
* ``commit(fix_id, mode)`` resumes the paused graph with ``Command(resume={"mode": mode})``.
  It is refused — and the graph stays paused — for an unknown or unavailable mode, a fix that
  is not verified, or one that is not waiting for approval.

The scan's status follows its fixes: ``awaiting_approval`` while any verified fix waits, back
to ``completed`` when none does. The scan's reports are rewritten after each step, so they show
the verification, the commit and the resolution.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langgraph.types import Command

from aegis.agent.deps import AgentDeps
from aegis.agent.fix_graph import APPROVAL_MODES
from aegis.evidence.models import ScanStatus
from aegis.fix.committer import unavailable_reason
from aegis.observability import get_logger
from aegis.services.report_service import write_reports

__all__ = ["FixService", "FixServiceError"]

log = get_logger("services.fix")


class FixServiceError(Exception):
    """A fix request that cannot be carried out. ``code`` maps to an HTTP status in the API."""

    def __init__(self, message: str, code: int = 409):
        super().__init__(message)
        self.code = code


class FixService:
    def __init__(self, deps: AgentDeps, graph: Any):
        """*graph* is ``build_fix_graph(checkpointer)`` — it must be checkpointed to pause."""
        if getattr(graph, "checkpointer", None) in (None, False):
            raise ValueError("the fix graph needs a checkpointer to wait for approval")
        self.deps = deps
        self.store = deps.store
        self.graph = graph
        self.tasks: dict[str, asyncio.Task] = {}  # fix_id → background verification

    def _config(self, fix_id: str) -> dict:
        return {"configurable": {"thread_id": fix_id, "deps": self.deps}}

    async def _waiting(self, fix_id: str) -> dict | None:
        """The approval request the graph is paused on, or ``None``."""
        snapshot = await self.graph.aget_state(self._config(fix_id))
        if "await_approval" not in (snapshot.next or ()):
            return None
        for task in snapshot.tasks:
            for pending in getattr(task, "interrupts", ()) or ():
                return pending.value
        return {}

    def _attempt(self, fix_id: str):
        attempt = self.store.get_fix_attempt(fix_id)
        if attempt is None:
            raise FixServiceError(f"unknown fix {fix_id}", code=404)
        return attempt

    def _sync_scan_status(self, scan_id: str) -> None:
        waiting = any(
            a.status == "verified"
            for f in self.store.list_findings(scan_id)
            for a in self.store.list_fix_attempts(f.id)
        )
        scan = self.store.get_scan(scan_id)
        if waiting and scan.status != ScanStatus.awaiting_approval:
            self.store.update_scan(scan_id, status=ScanStatus.awaiting_approval)
            log.info("scan.status", scan_id=scan_id, status="awaiting_approval")
        elif not waiting and scan.status == ScanStatus.awaiting_approval:
            self.store.update_scan(scan_id, status=ScanStatus.completed)
            log.info("scan.status", scan_id=scan_id, status="completed")

    def _refresh_report(self, scan_id: str) -> None:
        """Rewrite the scan's reports so they tell the fix's story too (never fails the request)."""
        try:
            write_reports(self.store, scan_id, self.deps.data_dir)
        except Exception as exc:  # noqa: BLE001 - the fix itself is already recorded
            log.warning("report.refresh_failed", scan_id=scan_id, error=f"{type(exc).__name__}: {str(exc)[:200]}")

    def _fresh_draft(self, finding_id: str):
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise FixServiceError(f"unknown finding {finding_id}", code=404)
        attempt = self.store.latest_fix_attempt(finding_id)
        if attempt is None or attempt.status != "drafted":
            state = attempt.status if attempt else "none"
            raise FixServiceError(f"{finding_id} has no fresh fix draft to verify (latest: {state})")
        return finding, attempt

    def submit(self, finding_id: str) -> str:
        """Check there is a fresh draft, then verify it in the background; return its fix id."""
        _finding, attempt = self._fresh_draft(finding_id)
        if attempt.id in self.tasks and not self.tasks[attempt.id].done():
            raise FixServiceError(f"{attempt.id} is already being verified")

        async def run() -> None:
            try:
                await self.start(finding_id)
            except Exception as exc:  # noqa: BLE001 - recorded in the log; the attempt keeps its status
                log.error("fix.background_failed", fix_id=attempt.id, error=f"{type(exc).__name__}: {str(exc)[:300]}")

        task = asyncio.get_running_loop().create_task(run(), name=f"fix-{attempt.id}")
        self.tasks[attempt.id] = task
        log.info("fix.submitted", fix_id=attempt.id, finding_id=finding_id)
        return attempt.id

    async def wait(self, fix_id: str) -> None:
        task = self.tasks.get(fix_id)
        if task is not None:
            await asyncio.shield(task)

    async def shutdown(self) -> None:
        for task in list(self.tasks.values()):
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)

    async def start(self, finding_id: str) -> dict:
        finding, attempt = self._fresh_draft(finding_id)
        log.info("fix.start", fix_id=attempt.id, finding_id=finding_id)
        init = {
            "fix_id": attempt.id,
            "finding_id": finding_id,
            "workspace_path": None,
            "diff": None,
            "verify_report": None,
            "approved": False,
            "commit_mode": None,
            "errors": [],
        }
        await self.graph.ainvoke(init, self._config(attempt.id))
        self._sync_scan_status(finding.scan_id)
        self._refresh_report(finding.scan_id)
        return await self.get(attempt.id)

    async def get(self, fix_id: str) -> dict:
        attempt = self._attempt(fix_id)
        stored = json.loads(attempt.verify_report_json or "{}")
        waiting = await self._waiting(fix_id)
        verifying = fix_id in self.tasks and not self.tasks[fix_id].done() and attempt.status == "drafted"
        status = "awaiting_approval" if waiting is not None else "verifying" if verifying else attempt.status
        return {
            "fix_id": fix_id,
            "finding_id": attempt.finding_id,
            "status": status,
            "diff": attempt.diff,
            "verify_report": stored.get("verify"),
            "draft": stored.get("draft"),
            "resolution": stored.get("resolution"),
            "commit_mode": attempt.commit_mode,
            "approval": waiting,
        }

    async def commit(self, fix_id: str, mode: str) -> dict:
        attempt = self._attempt(fix_id)
        reason = unavailable_reason(mode)
        if reason is not None or mode not in APPROVAL_MODES:
            # pr is a real mode that is not enabled yet (C6): a conflict, not a malformed request
            raise FixServiceError(reason or f"{mode} cannot be approved", code=409 if mode == "pr" else 422)
        if attempt.status != "verified":
            raise FixServiceError(f"{fix_id} is {attempt.status}: only a verified fix can be committed")
        if await self._waiting(fix_id) is None:
            raise FixServiceError(f"{fix_id} is not waiting for approval")

        log.info("fix.commit_requested", fix_id=fix_id, mode=mode)
        await self.graph.ainvoke(Command(resume={"mode": mode}), self._config(fix_id))
        finding = self.store.get_finding(attempt.finding_id)
        self._sync_scan_status(finding.scan_id)
        self._refresh_report(finding.scan_id)
        return await self.get(fix_id)
