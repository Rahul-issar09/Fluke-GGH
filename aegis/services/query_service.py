"""QueryService — the read-only view of results (AG13.2, FASTAPI FA02.1 / FA05 / FA06).

Shared by the REST API and (AG16) the MCP server. It has **no write methods**: nothing here
can create, change or delete a scan, finding or evidence record (MCP M-1).

Findings are the de-duplicated ones (merged duplicates folded into their primary), ranked:
open findings by risk, highest first, then resolved ones. Details are built by the same code
as the reports, so the API and the report never disagree.
"""

from __future__ import annotations

from pathlib import Path

from aegis.api.schemas import EvidenceOut, FindingDetail, FindingOut, ScanOut
from aegis.evidence.links import visible_findings
from aegis.evidence.models import FindingState, ScanStatus
from aegis.evidence.store import EvidenceStore
from aegis.graph.security_graph import graph_path
from aegis.observability import get_logger
from aegis.reports.json_report import evidence_out, finding_detail, load_graph

__all__ = ["QueryService", "QueryNotFound", "NotAvailable"]

log = get_logger("services.query")


class QueryNotFound(LookupError):
    def __init__(self, message: str, ids: list[str] | None = None):
        super().__init__(message)
        self.ids = ids


class NotAvailable(RuntimeError):
    """The data exists in the design but is not produced yet (e.g. the CBOM before AG15)."""


def _value(v):
    return getattr(v, "value", v)


class QueryService:
    def __init__(self, store: EvidenceStore, data_dir: str | Path):
        self._store = store
        self._data_dir = Path(data_dir)

    def _scan(self, scan_id: str):
        scan = self._store.get_scan(scan_id)
        if scan is None:
            raise QueryNotFound(f"unknown scan {scan_id}", [scan_id])
        return scan

    def list_findings(
        self,
        scan_id: str,
        *,
        severity_min: float | None = None,
        owasp: str | None = None,
        state: str | None = None,
        mode: str | None = None,
        sort: str = "risk",
    ) -> list[FindingOut]:
        self._scan(scan_id)
        findings = visible_findings(self._store, scan_id)
        if severity_min is not None:
            findings = [f for f in findings if f.severity >= severity_min]
        if owasp:
            findings = [f for f in findings if f.owasp == owasp]
        if state:
            findings = [f for f in findings if _value(f.state) == state]
        if mode:
            findings = [f for f in findings if _value(f.mode) == mode]
        if sort == "risk":
            open_ = sorted((f for f in findings if f.state != FindingState.resolved), key=lambda f: (-f.risk, -f.severity, f.id))
            done = sorted((f for f in findings if f.state == FindingState.resolved), key=lambda f: f.id)
            findings = [*open_, *done]
        else:
            findings = sorted(findings, key=lambda f: f.id)
        return [
            FindingOut(
                id=f.id, type=f.type, owasp=f.owasp, title=f.title, severity=f.severity, state=_value(f.state),
                mode=_value(f.mode), route=f.route, function=f.function, file=f.file, line=f.line,
                risk=f.risk, correlation_score=f.correlation_score,
            )
            for f in findings
        ]

    def get_finding(self, finding_id: str) -> FindingDetail:
        finding = self._store.get_finding(finding_id)
        if finding is None:
            raise QueryNotFound(f"unknown finding {finding_id}", [finding_id])
        scan = self._store.get_scan(finding.scan_id)
        return FindingDetail.model_validate(finding_detail(self._store, finding, scan.source_path if scan else None))

    def get_evidence(self, evidence_id: str) -> EvidenceOut:
        """The raw evidence record — the operator surface (MCP applies its own redaction)."""
        ev = self._store.get_evidence(evidence_id)
        if ev is None:
            raise QueryNotFound(f"unknown evidence {evidence_id}", [evidence_id])
        return evidence_out(ev, redacted=False)

    def get_graph(self, scan_id: str) -> dict:
        """Cytoscape-style ``{nodes, edges}`` plus the attack paths. Correlation scores ride on edges."""
        scan = self._scan(scan_id)
        if not graph_path(self._data_dir, scan_id).is_file() and scan.status in (ScanStatus.queued, ScanStatus.running):
            raise QueryNotFound(f"the security graph of {scan_id} is not built yet (the scan is {scan.status.value})", [scan_id])
        graph = load_graph(self._store, scan_id, self._data_dir)
        return {"scan_id": scan_id, **graph.to_api(), "attack_paths": graph.attack_paths()}

    def get_attack_paths(self, scan_id: str) -> list[list[str]]:
        """The attack-path chains of the scan's security graph (MCP ``get_attack_paths``)."""
        return [list(path) for path in self.get_graph(scan_id).get("attack_paths") or []]

    def latest_scan_id(self) -> str | None:
        """The most recently created scan, or ``None`` when there are no scans yet."""
        scans = self._store.list_scans(limit=1)
        return scans[0].id if scans else None

    def scan_status(self, scan_id: str) -> ScanOut:
        """A scan's status read from the store alone (MCP ``scan_status``).

        Unlike ``ScanService.get`` this does not open the scan graph's checkpoint, so
        ``completed_stages`` is left empty; ``stages`` is the scan's recorded plan.
        """
        import json

        scan = self._scan(scan_id)
        try:
            config = json.loads(scan.config_json or "{}")
        except (ValueError, TypeError):
            config = {}
        counts: dict[str, int] = {"findings": 0, "evidence": len(self._store.list_evidence(scan_id))}
        for f in visible_findings(self._store, scan_id):
            counts["findings"] += 1
            state = _value(f.state)
            counts[state] = counts.get(state, 0) + 1
        return ScanOut(
            id=scan.id,
            mode=_value(scan.mode),
            status=_value(scan.status),
            stages=list(config.get("plan") or []),
            completed_stages=[],
            counts=counts,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        )

    def get_cbom(self, scan_id: str) -> dict:
        """The scan's CycloneDX 1.6 cryptography bill of materials (written by the crypto stage)."""
        import json

        from aegis.workers.crypto.cbom import cbom_path

        scan = self._scan(scan_id)
        path = cbom_path(self._data_dir, scan_id)
        if not path.is_file():
            why = "the scan is still running" if scan.status in (ScanStatus.queued, ScanStatus.running) else "this scan had no crypto stage (code or correlated scans have one)"
            raise QueryNotFound(f"no CBOM for {scan_id}: {why}", [scan_id])
        return json.loads(path.read_text(encoding="utf-8"))
