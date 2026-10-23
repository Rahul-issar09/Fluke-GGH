"""ScanService (PHASES P1.5 create_scan slice; AG04 close-out).

Creates the ``Scan`` row and the ordered stage plan from a request. Source
cloning and execution happen later (prepare node / JobRunner, AG05).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from aegis.agent.state import ScanInputs
from aegis.api.schemas import GateOut, ScanOut, ScanRequest
from aegis.evidence.links import visible_findings
from aegis.evidence.models import FindingState, ScanStatus
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.router import build_plan, select_mode, validate_request

__all__ = ["ScanConflict", "ScanNotFound", "ScanService", "create_scan", "get_audit"]

log = get_logger("services.scan_service")


def create_scan(
    store: EvidenceStore,
    request: ScanRequest,
    *,
    allowed_source_roots: Iterable[str] | None = None,
    git_hosts: Iterable[str] | None = None,
) -> str:
    """Validate the request, choose the mode, build the plan, persist the Scan.

    Returns the new ``scan_id``. Raises :class:`aegis.router.RequestInvalid`
    on a bad request.
    """
    validate_request(request, allowed_source_roots=allowed_source_roots, git_hosts=git_hosts)
    mode = select_mode(request)
    plan = build_plan(mode)
    config = {
        "plan": plan,
        "url": request.url,
        "folder": request.folder,
        "repo": request.repo,
        "identities": request.identities,
        "options": request.options,
    }
    scan = store.add_scan(
        mode=mode.value,
        status=ScanStatus.queued,
        target_url=request.url,
        source_path=request.folder,
        repo_url=request.repo,
        config_json=json.dumps(config),
    )
    log.info("scan_service.created", scan_id=scan.id, mode=mode.value, plan=plan)
    return scan.id


def _loads(raw: str | None):
    try:
        return json.loads(raw or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}


def get_audit(store: EvidenceStore, scan_id: str) -> dict:
    """Everything the system did and decided during a scan (PHASES P11.4).

    Tool calls (what ran, against which host, how long, whether it was blocked), the
    agent's decisions in order (rule / llm / llm_retry / fallback, including rejected
    LLM attempts) and every finding state transition. Arguments, payloads and evidence
    content never appear here — IDs, hashes and outcomes only.
    """
    findings = store.list_findings(scan_id)
    return {
        "scan_id": scan_id,
        "tool_calls": [
            {
                "tool": c.tool,
                "target_host": c.target_host,
                "args_hash": c.args_hash,
                "duration_ms": c.duration_ms,
                "exit_code": c.exit_code,
                "blocked_reason": c.blocked_reason,
                "at": c.at.isoformat() if c.at else None,
            }
            for c in store.list_tool_calls(scan_id)
        ],
        "decisions": [
            {
                "id": d.id,
                "node": d.node,
                "finding_id": d.finding_id,
                "source": d.source,
                "valid": d.valid,
                "error": d.error,
                "input": _loads(d.input_summary_json),
                "output": _loads(d.output_json),
                "at": d.at.isoformat() if d.at else None,
            }
            for d in store.list_decisions(scan_id)
        ],
        "transitions": [
            {
                "finding_id": t.finding_id,
                "from": t.from_state,
                "to": t.to_state,
                "actor": t.actor,
                "reason": t.reason,
                "evidence_ids": _loads(t.evidence_ids),
                "at": t.at.isoformat() if t.at else None,
            }
            for t in store.list_transitions([f.id for f in findings])
        ],
    }


# --------------------------------------------------------------------------------------------- #
# ScanService — what the API (and later MCP) call (AG13.2, FASTAPI FA02.1 / FA03 / FA11)
# --------------------------------------------------------------------------------------------- #
class ScanNotFound(LookupError):
    pass


class ScanConflict(RuntimeError):
    """Another scan is still running (one scan at a time — hardware budget, A-4)."""


_TERMINAL = {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}


class ScanService:
    def __init__(self, store: EvidenceStore, runner: Any, graph: Any, settings: Any):
        self.store = store
        self.runner = runner
        self.graph = graph
        self.settings = settings

    def _scan(self, scan_id: str):
        scan = self.store.get_scan(scan_id)
        if scan is None:
            raise ScanNotFound(f"unknown scan {scan_id}")
        return scan

    def _active(self) -> list[str]:
        return [sid for sid, task in self.runner.tasks.items() if not task.done()]

    def start(self, request: ScanRequest) -> str:
        """Validate, persist and submit a scan; it runs in the background."""
        active = self._active()
        if active:
            raise ScanConflict(f"scan {active[0]} is still running; one scan runs at a time")
        scan_id = create_scan(
            self.store,
            request,
            allowed_source_roots=self.settings.api.allowed_source_roots,
            git_hosts=getattr(self.settings, "git_hosts", None),
        )
        init = {
            "scan_id": scan_id,
            "inputs": ScanInputs(url=request.url, folder=request.folder, repo=request.repo, identities=request.identities),
            "plan": [],
            "completed_stages": [],
            "open_findings": [],
            "pending_actions": [],
            "iterations": 0,
            "max_iterations": 3,
            "errors": [],
        }
        self.runner.submit(scan_id, self.graph, init)
        log.info("scan.started", scan_id=scan_id)
        return scan_id

    async def get(self, scan_id: str) -> ScanOut:
        scan = self._scan(scan_id)
        config = json.loads(scan.config_json or "{}")
        snapshot = await self.graph.aget_state({"configurable": {"thread_id": scan_id}})
        values = snapshot.values or {}
        counts: dict[str, int] = {"findings": 0, "evidence": len(self.store.list_evidence(scan_id))}
        for f in visible_findings(self.store, scan_id):
            counts["findings"] += 1
            state = getattr(f.state, "value", f.state)
            counts[state] = counts.get(state, 0) + 1
        return ScanOut(
            id=scan.id,
            mode=getattr(scan.mode, "value", scan.mode),
            status=getattr(scan.status, "value", scan.status),
            stages=list(values.get("plan") or config.get("plan") or []),
            completed_stages=list(values.get("completed_stages") or []),
            counts=counts,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        )

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a running scan. Cancelling a finished one is a no-op (idempotent)."""
        self._scan(scan_id)
        cancelled = await self.runner.cancel(scan_id)
        log.info("scan.cancel", scan_id=scan_id, was_running=cancelled)
        return cancelled

    def gate(self, scan_id: str, severity_threshold: float | None = None) -> GateOut:
        """CI verdict: 0 clean · 1 blocking findings · 2 the scan did not complete."""
        scan = self._scan(scan_id)
        if scan.status not in (ScanStatus.completed, ScanStatus.awaiting_approval):
            log.info("gate.error", scan_id=scan_id, status=scan.status.value)
            return GateOut(passed=False, exit_code=2, blocking_findings=[])
        gate = self.settings.gate
        threshold = gate.severity_threshold if severity_threshold is None else severity_threshold
        blocking = [
            f.id
            for f in visible_findings(self.store, scan_id)
            if f.state != FindingState.resolved and f.owasp in gate.block_owasp and f.risk >= threshold
        ]
        blocking.sort(key=lambda fid: -self.store.get_finding(fid).risk)
        verdict = GateOut(passed=not blocking, exit_code=1 if blocking else 0, blocking_findings=blocking)
        log.info("gate.verdict", scan_id=scan_id, exit_code=verdict.exit_code, blocking=blocking, threshold=threshold)
        return verdict

    def audit(self, scan_id: str) -> dict:
        self._scan(scan_id)
        return get_audit(self.store, scan_id)

    def recent(self, limit: int = 50) -> list[dict]:
        """A short line per recent scan, newest first (for a scan picker)."""
        out = []
        for scan in self.store.list_scans(limit):
            findings = visible_findings(self.store, scan.id)
            out.append({
                "id": scan.id,
                "mode": getattr(scan.mode, "value", scan.mode),
                "status": getattr(scan.status, "value", scan.status),
                "target_url": scan.target_url,
                "source": scan.source_path,
                "findings": len(findings),
                "top_risk": max((f.risk for f in findings if f.state != FindingState.resolved), default=0.0),
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            })
        return out

    def is_finished(self, scan_id: str) -> bool:
        return self._scan(scan_id).status in _TERMINAL
