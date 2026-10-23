"""Scans: start / status / cancel / CI gate / audit (AG13.2, FASTAPI FA03 + FA11)."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, Response

from aegis.api.deps import get_scan_service
from aegis.api.schemas import ErrorOut, GateOut, ScanOut, ScanRequest
from aegis.services.scan_service import ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])

SCAN_ID = Path(pattern=r"^S-\d{4,}$", description="Scan id, e.g. S-0001", examples=["S-0001"])
_ERRORS = {404: {"model": ErrorOut, "description": "Unknown scan"}}

EXAMPLES = {
    "mode1_code": {
        "summary": "Mode 1 — code only",
        "description": "Scan a mounted source folder (must be inside api.allowed_source_roots).",
        "value": {"folder": "/scan/demo-app"},
    },
    "mode2_runtime": {
        "summary": "Mode 2 — running app only",
        "description": "Test a running app as two identities (owner A and attacker B).",
        "value": {"url": "http://demo-app:5000", "identities": "/scan/demo-app/identities.yml"},
    },
    "mode3_correlated": {
        "summary": "Mode 3 — code + running app (correlated)",
        "description": "Both: runtime proof is linked to the exact handler in the code.",
        "value": {"url": "http://demo-app:5000", "folder": "/scan/demo-app", "identities": "/scan/demo-app/identities.yml"},
    },
}


@router.post(
    "",
    status_code=202,
    summary="Start a scan",
    description="Validates the request, picks the mode deterministically and starts the scan in the background. "
    "One scan runs at a time. Follow it with `GET /api/scans/{id}/events`.",
    responses={409: {"model": ErrorOut, "description": "Another scan is running"}, 422: {"model": ErrorOut}},
)
async def start_scan(
    request: ScanRequest = Body(openapi_examples=EXAMPLES),
    scans: ScanService = Depends(get_scan_service),
) -> dict:
    return {"scan_id": scans.start(request)}


@router.get("", summary="Recent scans", description="Newest first: id, mode, status, target, how many findings and the top open risk.")
def list_scans(limit: int = Query(50, ge=1, le=500), scans: ScanService = Depends(get_scan_service)) -> list[dict]:
    return scans.recent(limit)


@router.get("/{scan_id}", summary="Scan status and progress", response_model=ScanOut, responses=_ERRORS)
async def get_scan(scan_id: str = SCAN_ID, scans: ScanService = Depends(get_scan_service)) -> ScanOut:
    return await scans.get(scan_id)


@router.post(
    "/{scan_id}/cancel",
    status_code=204,
    summary="Cancel a scan",
    description="Stops a running scan. Cancelling a scan that already finished changes nothing.",
    responses=_ERRORS,
)
async def cancel_scan(scan_id: str = SCAN_ID, scans: ScanService = Depends(get_scan_service)) -> Response:
    await scans.cancel(scan_id)
    return Response(status_code=204)


@router.get(
    "/{scan_id}/gate",
    summary="CI gate verdict",
    description="`exit_code` 0 = clean, 1 = open findings in a blocking OWASP category at or above the risk threshold, "
    "2 = the scan did not complete. Resolved findings never block.",
    response_model=GateOut,
    responses=_ERRORS,
)
def gate(
    scan_id: str = SCAN_ID,
    severity_threshold: float | None = Query(None, ge=0.0, le=1.0, description="Override gate.severity_threshold"),
    scans: ScanService = Depends(get_scan_service),
) -> GateOut:
    return scans.gate(scan_id, severity_threshold)


@router.get(
    "/{scan_id}/audit",
    summary="What ran and what was decided",
    description="Tool calls (through the safety layer), agent decisions (rule / llm / retry / fallback, "
    "including rejected model answers) and every finding state transition. IDs and outcomes only.",
    responses=_ERRORS,
)
def audit(scan_id: str = SCAN_ID, scans: ScanService = Depends(get_scan_service)) -> dict:
    return scans.audit(scan_id)
