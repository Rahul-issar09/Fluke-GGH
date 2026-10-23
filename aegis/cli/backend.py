"""The one interface every command talks to (CLI_PHASES.md CLI03, section 4A).

Commands and the ``ui`` layer never import AEGIS's services directly — only this module. That keeps
local mode (this machine) and remote mode (``--api URL``, phase CLI12) interchangeable: both
implement :class:`Backend`, and a test proves the two give identical results.

Methods are added phase by phase (findings in CLI04, scans in CLI06, …). Heavy modules are imported
inside the methods, so starting the CLI stays fast.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from aegis.config import AppSettings

__all__ = ["Backend", "LocalBackend"]


class Backend(ABC):
    mode: str = "abstract"

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Where this backend gets its data from (for ``version`` and error messages)."""

    # ---- read (CLI04): results of scans that already ran; the shapes are the REST API's
    @abstractmethod
    def latest_scan_id(self) -> str | None:
        """The most recently created scan, or ``None`` when there are no scans."""

    @abstractmethod
    def list_scans(self, limit: int = 20) -> list[dict]:
        """Recent scans, newest first (``GET /api/scans``)."""

    @abstractmethod
    def scan_status(self, scan_id: str) -> Any:
        """``ScanOut`` (``GET /api/scans/{id}``)."""

    @abstractmethod
    def scan_audit(self, scan_id: str) -> dict:
        """Tool calls, decisions, transitions (``GET /api/scans/{id}/audit``)."""

    @abstractmethod
    def list_findings(self, scan_id: str, **filters: Any) -> list[Any]:
        """``list[FindingOut]`` (``GET /api/findings``)."""

    @abstractmethod
    def get_finding(self, finding_id: str) -> Any:
        """``FindingDetail`` (``GET /api/findings/{id}``)."""

    @abstractmethod
    def get_evidence(self, evidence_id: str, *, raw: bool = False) -> Any:
        """A digest (``EvidenceDigestOut``) by default; ``raw`` → ``EvidenceOut`` with credentials redacted."""

    @abstractmethod
    def get_graph(self, scan_id: str) -> dict:
        """Nodes, edges and attack paths (``GET /api/graph``)."""

    @abstractmethod
    def get_cbom(self, scan_id: str) -> dict:
        """CycloneDX 1.6 CBOM (``GET /api/cbom``)."""

    # ---- reports and the CI gate (CLI05)
    @abstractmethod
    def get_report(self, scan_id: str, fmt: str) -> dict[str, Any]:
        """``{"content": bytes, "media_type", "filename", "path"}`` (``GET /api/reports``). ``path`` is the
        stored report file when this backend can see it (local), else ``None``."""

    @abstractmethod
    def gate(self, scan_id: str, threshold: float | None = None) -> Any:
        """``GateOut`` (``GET /api/scans/{id}/gate``): 0 clean · 1 blocking findings · 2 scan not complete."""

    def resolve_scan(self, scan_id: str | None) -> str:
        """*scan_id*, or the latest scan when it is omitted."""
        if scan_id:
            return scan_id
        latest = self.latest_scan_id()
        if latest is None:
            from aegis.cli.errors import NOT_FOUND, CliError

            raise CliError("there are no scans yet", NOT_FOUND, hint="run a scan first (aegis scan run - phase CLI06)")
        return latest

    def close(self) -> None:
        """Release anything opened."""

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class LocalBackend(Backend):
    """AEGIS on this machine, built in-process from the same services the REST API uses."""

    mode = "local"

    def __init__(self, settings: AppSettings):
        self.settings = settings
        self._read = None

    def describe(self) -> dict[str, Any]:
        from pathlib import Path

        return {"mode": self.mode, "data_dir": str(Path(self.settings.data_dir).resolve())}

    def read_services(self):
        """Read-only services (store opened read-only): for commands that only look at results."""
        if self._read is None:
            from aegis.services.read_services import build_read_services

            self._read = build_read_services(self.settings)
        return self._read

    def _scans(self):
        """The scan service's read-only parts (history, audit) over the read-only store."""
        from aegis.services.scan_service import ScanService

        return ScanService(self.read_services().store, runner=None, graph=None, settings=self.settings)

    # ---- read (CLI04)
    def latest_scan_id(self) -> str | None:
        return self.read_services().query.latest_scan_id()

    def list_scans(self, limit: int = 20) -> list[dict]:
        return self._scans().recent(limit)

    def scan_status(self, scan_id: str) -> Any:
        return self.read_services().query.scan_status(scan_id)

    def scan_audit(self, scan_id: str) -> dict:
        return self._scans().audit(scan_id)

    def list_findings(self, scan_id: str, **filters: Any) -> list[Any]:
        return self.read_services().query.list_findings(scan_id, **filters)

    def get_finding(self, finding_id: str) -> Any:
        return self.read_services().query.get_finding(finding_id)

    def get_evidence(self, evidence_id: str, *, raw: bool = False) -> Any:
        from aegis.mcp.redaction import project_evidence
        from aegis.services.query_service import QueryNotFound

        ev = self.read_services().store.get_evidence(evidence_id)
        if ev is None:
            raise QueryNotFound(f"unknown evidence {evidence_id}", [evidence_id])
        return project_evidence(ev, expose_raw=raw)     # digest, or payload with credentials redacted

    def get_graph(self, scan_id: str) -> dict:
        return self.read_services().query.get_graph(scan_id)

    def get_cbom(self, scan_id: str) -> dict:
        return self.read_services().query.get_cbom(scan_id)

    # ---- reports and the CI gate (CLI05)
    def get_report(self, scan_id: str, fmt: str) -> dict[str, Any]:
        """The same rules as ``GET /api/reports``: the stored file if there is one; otherwise built on
        demand for a finished scan; a running scan has no report yet; SARIF is not built yet."""
        from aegis.api.errors import Conflict
        from aegis.evidence.models import ScanStatus
        from aegis.services.query_service import NotAvailable
        from aegis.services.report_service import FORMATS, build_report, report_paths

        services = self.read_services()
        scan = services.store.get_scan(scan_id)
        if scan is None:
            from aegis.services.scan_service import ScanNotFound

            raise ScanNotFound(f"unknown scan {scan_id}")
        if fmt == "cbom":
            from aegis.workers.crypto.cbom import cbom_path

            path = cbom_path(services.data_dir, scan_id)
            if not path.is_file():
                raise Conflict(f"{scan_id} has no CBOM: it is written by the crypto stage of a code or correlated scan")
            return {"content": path.read_bytes(), "media_type": "application/vnd.cyclonedx+json",
                    "filename": f"aegis-{scan_id}.cbom.json", "path": str(path)}
        if fmt not in FORMATS:
            raise NotAvailable(f"the {fmt} report is not built yet")
        path = report_paths(services.data_dir, scan_id)[fmt]
        finished = scan.status in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.awaiting_approval)
        if path.is_file():
            content, stored = path.read_bytes(), str(path)
        elif finished:
            content, stored = build_report(services.store, scan_id, fmt, data_dir=services.data_dir).encode("utf-8"), None
        else:
            raise Conflict(f"{scan_id} has not finished; its report is written when it does")
        return {"content": content, "media_type": FORMATS[fmt], "filename": f"aegis-{scan_id}.{fmt}", "path": stored}

    def gate(self, scan_id: str, threshold: float | None = None) -> Any:
        return self._scans().gate(scan_id, threshold)

    @asynccontextmanager
    async def runtime(self) -> AsyncIterator[Any]:
        """The full AEGIS runtime (scans, fixes, chat), shared with the API (``open_runtime``)."""
        from aegis.services.runtime import open_runtime

        async with open_runtime(self.settings) as rt:
            yield rt

    def close(self) -> None:
        if self._read is not None:
            self._read.store._engine.dispose()
            self._read = None
