"""Report service (AG12.1, PHASES P13.6–P13.7).

Writes ``<data_dir>/reports/<scan_id>/report.json`` and ``report.html`` (at ``finalize``, and
again whenever a fix changes a finding's story), and builds a report on demand for the API.
Files are written to a temporary name and renamed, so a reader never sees half a report.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.reports.html import render_html
from aegis.reports.json_report import build_json_report

__all__ = ["FORMATS", "build_report", "report_paths", "write_reports"]

log = get_logger("services.report")

FORMATS = {"json": "application/json", "html": "text/html; charset=utf-8"}
_SCAN_ID = re.compile(r"^S-\d{4,}$")


def report_paths(data_dir: str | Path, scan_id: str) -> dict[str, Path]:
    if not _SCAN_ID.match(scan_id):
        raise ValueError(f"not a scan id: {scan_id!r}")
    folder = Path(data_dir) / "reports" / scan_id
    return {"json": folder / "report.json", "html": folder / "report.html"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))
    os.replace(tmp, path)


def build_report(store: EvidenceStore, scan_id: str, fmt: str, *, data_dir: str | Path | None = None) -> str:
    """The report as text in *fmt* (``json`` or ``html``)."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown report format {fmt!r}; choose one of {', '.join(FORMATS)}")
    report = build_json_report(store, scan_id, data_dir=data_dir)
    if fmt == "json":
        return json.dumps(report, indent=2, ensure_ascii=False)
    return render_html(report)


def write_reports(store: EvidenceStore, scan_id: str, data_dir: str | Path) -> dict[str, Path]:
    paths = report_paths(data_dir, scan_id)
    report = build_json_report(store, scan_id, data_dir=data_dir)
    _write(paths["json"], json.dumps(report, indent=2, ensure_ascii=False))
    _write(paths["html"], render_html(report))
    log.info("report.written", scan_id=scan_id, json=str(paths["json"]), html=str(paths["html"]))
    return paths
