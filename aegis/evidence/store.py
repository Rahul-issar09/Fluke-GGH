"""EvidenceStore repository (PHASES P5.2).

All reads/writes go through one class. It never changes ``Finding.state`` —
that is the state machine's job (``update_finding_fields`` refuses ``state``).
It exposes a ``session()`` context manager that the state machine uses to make
the single authorized state assignment.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlmodel import Session, select

from aegis.evidence.ids import next_id
from aegis.evidence.models import (
    AgentDecision,
    StateTransition,
    Claim,
    Evidence,
    Finding,
    FindingState,
    FixAttempt,
    Scan,
    ToolCallLog,
)
from aegis.observability import get_logger
from aegis.secret_scrub import scrub

__all__ = ["EvidenceStore"]

log = get_logger("evidence.store")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceStore:
    def __init__(self, engine):
        self._engine = engine

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = Session(self._engine, expire_on_commit=False)
        try:
            yield s
        finally:
            s.close()

    # --- scans ------------------------------------------------------------ #
    def add_scan(self, mode: str, **fields: Any) -> Scan:
        with self.session() as s:
            scan = Scan(id=next_id(s, "S"), mode=mode, **fields)
            s.add(scan)
            s.commit()
            log.info("store.add_scan", scan_id=scan.id, mode=mode)
            return scan

    def list_scans(self, limit: int = 50) -> list[Scan]:
        """The most recent scans first."""
        with self.session() as s:
            return list(s.exec(select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit)))

    def get_scan(self, scan_id: str) -> Scan | None:
        with self.session() as s:
            return s.get(Scan, scan_id)

    def update_scan(self, scan_id: str, **fields: Any) -> Scan | None:
        with self.session() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                return None
            for k, v in fields.items():
                setattr(scan, k, v)
            s.add(scan)
            s.commit()
            return scan

    # --- findings --------------------------------------------------------- #
    def add_finding(self, scan_id: str, type: str, **fields: Any) -> Finding:
        with self.session() as s:
            finding = Finding(id=next_id(s, "F"), scan_id=scan_id, type=type, **fields)
            s.add(finding)
            s.commit()
            log.info("store.add_finding", finding_id=finding.id, type=type, scan_id=scan_id)
            return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        with self.session() as s:
            return s.get(Finding, finding_id)

    def find_by_fingerprint(self, scan_id: str, fingerprint: str) -> Finding | None:
        with self.session() as s:
            stmt = select(Finding).where(
                Finding.scan_id == scan_id, Finding.fingerprint == fingerprint
            )
            return s.exec(stmt).first()

    def update_finding_fields(self, finding_id: str, **fields: Any) -> Finding | None:
        if "state" in fields:
            raise ValueError("Finding.state can only change via StateMachine.transition()")
        with self.session() as s:
            finding = s.get(Finding, finding_id)
            if finding is None:
                return None
            for k, v in fields.items():
                setattr(finding, k, v)
            finding.updated_at = _utcnow()
            s.add(finding)
            s.commit()
            return finding

    def list_findings(
        self,
        scan_id: str | None = None,
        *,
        severity_min: float | None = None,
        owasp: str | None = None,
        state: str | None = None,
        mode: str | None = None,
        type: str | None = None,
        sort: str = "risk",
    ) -> list[Finding]:
        with self.session() as s:
            stmt = select(Finding)
            if scan_id is not None:
                stmt = stmt.where(Finding.scan_id == scan_id)
            if severity_min is not None:
                stmt = stmt.where(Finding.severity >= severity_min)
            if owasp is not None:
                stmt = stmt.where(Finding.owasp == owasp)
            if state is not None:
                stmt = stmt.where(Finding.state == FindingState(state))
            if mode is not None:
                stmt = stmt.where(Finding.mode == mode)
            if type is not None:
                stmt = stmt.where(Finding.type == type)
            results = list(s.exec(stmt))
            reverse = sort in ("risk", "severity")
            key = (lambda f: getattr(f, sort, 0.0) or 0.0) if sort else (lambda f: f.id)
            results.sort(key=key, reverse=reverse)
            return results

    # --- evidence --------------------------------------------------------- #
    def add_evidence(
        self,
        scan_id: str,
        kind: str,
        tool: str,
        payload: dict | list | None = None,
        *,
        finding_id: str | None = None,
        tool_version: str = "",
        db_date: str | None = None,
    ) -> Evidence:
        with self.session() as s:
            ev = Evidence(
                id=next_id(s, "E"),
                scan_id=scan_id,
                finding_id=finding_id,
                kind=kind,
                tool=tool,
                tool_version=tool_version,
                db_date=db_date,
                payload_json=json.dumps(payload or {}, default=str),
            )
            s.add(ev)
            s.commit()
            log.info("store.add_evidence", evidence_id=ev.id, kind=kind, finding_id=finding_id)
            return ev

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        with self.session() as s:
            return s.get(Evidence, evidence_id)

    def list_evidence(self, scan_id: str, kind: str | None = None) -> list[Evidence]:
        """All evidence of a scan (finding-attached or scan-level), oldest first."""
        with self.session() as s:
            stmt = select(Evidence).where(Evidence.scan_id == scan_id)
            if kind is not None:
                stmt = stmt.where(Evidence.kind == kind)
            return sorted(s.exec(stmt), key=lambda e: e.id)

    def evidence_for(self, finding_id: str) -> list[Evidence]:
        with self.session() as s:
            return list(s.exec(select(Evidence).where(Evidence.finding_id == finding_id)))

    def evidence_exists(self, ids: list[str], finding_id: str | None = None) -> list[str]:
        """Return the subset of *ids* that do not exist (or, when ``finding_id``
        is given, that do not belong to that finding)."""
        missing: list[str] = []
        with self.session() as s:
            for eid in ids:
                ev = s.get(Evidence, eid)
                if ev is None or (finding_id is not None and ev.finding_id not in (None, finding_id)):
                    missing.append(eid)
        return missing

    def attach_evidence(self, evidence_id: str, finding_id: str) -> None:
        with self.session() as s:
            ev = s.get(Evidence, evidence_id)
            if ev is not None:
                ev.finding_id = finding_id
                s.add(ev)
                s.commit()

    # --- claims / decisions / fixes --------------------------------------- #
    def add_claim(
        self, finding_id: str, field: str, text: str, evidence_ids: list[str], kept: bool
    ) -> Claim:
        with self.session() as s:
            claim = Claim(
                finding_id=finding_id,
                field=field,
                text=text,
                evidence_ids_json=json.dumps(evidence_ids),
                kept=kept,
            )
            s.add(claim)
            s.commit()
            return claim

    def replace_claims(self, finding_id: str, claims: list[tuple[str, str, list[str], bool]]) -> None:
        """Replace a finding's validated claim set (``(field, text, evidence_ids, kept)`` rows).

        One validated set per finding: re-running validation never piles up duplicates.
        """
        with self.session() as s:
            for old in s.exec(select(Claim).where(Claim.finding_id == finding_id)):
                s.delete(old)
            for field, text, evidence_ids, kept in claims:
                s.add(
                    Claim(
                        finding_id=finding_id,
                        field=field,
                        text=text,
                        evidence_ids_json=json.dumps(evidence_ids),
                        kept=kept,
                    )
                )
            s.commit()

    def list_claims(self, finding_id: str, kept: bool | None = None) -> list[Claim]:
        with self.session() as s:
            stmt = select(Claim).where(Claim.finding_id == finding_id)
            if kept is not None:
                stmt = stmt.where(Claim.kept == kept)
            return sorted(s.exec(stmt), key=lambda c: c.id or 0)

    def add_decision(
        self,
        scan_id: str,
        node: str,
        source: str,
        *,
        finding_id: str | None = None,
        input_summary: dict | None = None,
        output: dict | None = None,
        valid: bool = True,
        error: str | None = None,
    ) -> AgentDecision:
        with self.session() as s:
            dec = AgentDecision(
                id=next_id(s, "D"),
                scan_id=scan_id,
                finding_id=finding_id,
                node=node,
                # scrubbed: a provider error must never store a secret (LLM_PROVIDER_PHASES §9.3)
                input_summary_json=scrub(json.dumps(input_summary or {}, default=str)),
                output_json=scrub(json.dumps(output or {}, default=str)),
                source=source,
                valid=valid,
                error=scrub(error) if error is not None else None,
            )
            s.add(dec)
            s.commit()
            return dec

    def list_decisions(self, scan_id: str, finding_id: str | None = None) -> list[AgentDecision]:
        """Recorded agent decisions for a scan (optionally one finding), oldest first."""
        with self.session() as s:
            stmt = select(AgentDecision).where(AgentDecision.scan_id == scan_id)
            if finding_id is not None:
                stmt = stmt.where(AgentDecision.finding_id == finding_id)
            return sorted(s.exec(stmt), key=lambda d: d.id)

    def list_fix_attempts(self, finding_id: str) -> list[FixAttempt]:
        with self.session() as s:
            rows = s.exec(select(FixAttempt).where(FixAttempt.finding_id == finding_id))
            return sorted(rows, key=lambda r: r.id)

    def latest_fix_attempt(self, finding_id: str) -> FixAttempt | None:
        attempts = self.list_fix_attempts(finding_id)
        return attempts[-1] if attempts else None

    def list_tool_calls(self, scan_id: str) -> list[ToolCallLog]:
        with self.session() as s:
            rows = s.exec(select(ToolCallLog).where(ToolCallLog.scan_id == scan_id))
            return sorted(rows, key=lambda r: r.id or 0)

    def list_transitions(self, finding_ids: list[str]) -> list[StateTransition]:
        if not finding_ids:
            return []
        with self.session() as s:
            rows = s.exec(select(StateTransition).where(StateTransition.finding_id.in_(finding_ids)))
            return sorted(rows, key=lambda r: r.id or 0)

    def add_fix_attempt(
        self,
        finding_id: str,
        diff: str,
        *,
        workspace_path: str | None = None,
        status: str = "drafted",
        verify_report: dict | None = None,
        commit_mode: str | None = None,
    ) -> FixAttempt:
        with self.session() as s:
            fix = FixAttempt(
                id=next_id(s, "X"),
                finding_id=finding_id,
                diff=diff,
                workspace_path=workspace_path,
                status=status,
                verify_report_json=json.dumps(verify_report or {}, default=str),
                commit_mode=commit_mode,
            )
            s.add(fix)
            s.commit()
            return fix

    def get_fix_attempt(self, fix_id: str) -> FixAttempt | None:
        with self.session() as s:
            return s.get(FixAttempt, fix_id)

    _FIX_FIELDS = frozenset({"workspace_path", "status", "verify_report", "commit_mode"})

    def update_fix_attempt(self, fix_id: str, **fields: Any) -> FixAttempt | None:
        """Update a fix attempt's progress. Its diff and finding are fixed at creation."""
        unknown = set(fields) - self._FIX_FIELDS
        if unknown:
            raise ValueError(f"fix attempt fields cannot be changed: {sorted(unknown)}")
        with self.session() as s:
            fix = s.get(FixAttempt, fix_id)
            if fix is None:
                return None
            for k, v in fields.items():
                if k == "verify_report":
                    fix.verify_report_json = json.dumps(v, default=str)
                else:
                    setattr(fix, k, v)
            s.add(fix)
            s.commit()
            return fix

    # --- audit (AG03 deferrals wired here) -------------------------------- #
    def add_tool_call_log(self, entry: dict) -> None:
        with self.session() as s:
            s.add(
                ToolCallLog(
                    scan_id=entry.get("scan_id", ""),
                    tool=entry.get("tool", ""),
                    target_host=entry.get("target_host"),
                    args_hash=entry.get("args_hash", ""),
                    duration_ms=entry.get("duration_ms"),
                    exit_code=entry.get("exit_code"),
                    blocked_reason=entry.get("blocked_reason"),
                )
            )
            s.commit()

    def add_tool_error(self, scan_id: str, tool: str, reason: str) -> Evidence:
        """A failed tool becomes evidence, not a crash (P4.2)."""
        return self.add_evidence(
            scan_id, kind="tool_error", tool=tool, payload={"reason": reason}
        )
