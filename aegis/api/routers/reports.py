"""Report export (AG13.2, FASTAPI FA12.1).

Serves the report written at ``finalize`` (and rewritten after each fix step); if the file is
missing for a finished scan it is built on demand. ``sarif`` and ``cbom`` are not built yet and
answer 501.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from aegis.api.deps import get_scan_service, get_settings, get_store
from aegis.api.errors import Conflict
from aegis.api.schemas import ErrorOut
from aegis.config import AppSettings
from aegis.evidence.store import EvidenceStore
from aegis.services.query_service import NotAvailable
from aegis.services.report_service import FORMATS, build_report, report_paths
from aegis.services.scan_service import ScanService

router = APIRouter(prefix="/api", tags=["reports"])


@router.get(
    "/reports",
    summary="Download a scan's report",
    description="`html` — one self-contained file that opens offline. `json` — the same facts as data. "
    "`cbom` — the CycloneDX 1.6 cryptography bill of materials. `sarif` arrives in a later phase (501 until then).",
    response_class=Response,
    responses={
        200: {"content": {"text/html": {}, "application/json": {}}},
        404: {"model": ErrorOut},
        409: {"model": ErrorOut, "description": "The scan has not finished"},
        501: {"model": ErrorOut},
    },
)
def get_report(
    scan_id: str = Query(pattern=r"^S-\d{4,}$", examples=["S-0001"]),
    format: Literal["html", "json", "sarif", "cbom"] = "html",
    scans: ScanService = Depends(get_scan_service),
    store: EvidenceStore = Depends(get_store),
    settings: AppSettings = Depends(get_settings),
) -> Response:
    finished = scans.is_finished(scan_id) or store.get_scan(scan_id).status.value == "awaiting_approval"
    if format == "cbom":  # written by the crypto stage
        from aegis.workers.crypto.cbom import cbom_path

        path = cbom_path(settings.data_dir, scan_id)
        if not path.is_file():
            raise Conflict(f"{scan_id} has no CBOM: it is written by the crypto stage of a code or correlated scan")
        return Response(path.read_bytes(), media_type="application/vnd.cyclonedx+json",
                        headers={"Content-Disposition": f'attachment; filename="aegis-{scan_id}.cbom.json"'})
    if format not in FORMATS:
        raise NotAvailable(f"the {format} report is not built yet")
    path = report_paths(settings.data_dir, scan_id)[format]
    if path.is_file():
        content = path.read_bytes()
    elif finished:
        content = build_report(store, scan_id, format, data_dir=settings.data_dir).encode("utf-8")
    else:
        raise Conflict(f"{scan_id} has not finished; its report is written when it does")
    disposition = "inline" if format == "html" else "attachment"
    return Response(
        content,
        media_type=FORMATS[format],
        headers={"Content-Disposition": f'{disposition}; filename="aegis-{scan_id}.{format}"'},
    )
