"""Findings: ranked list and five-part detail (AG13.2, FASTAPI FA05.1). Read-only."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Path, Query

from aegis.api.deps import get_query_service
from aegis.api.schemas import ErrorOut, FindingDetail, FindingOut
from aegis.services.query_service import QueryService

router = APIRouter(prefix="/api/findings", tags=["findings"])

FINDING_ID = Path(pattern=r"^F-\d{4,}$", description="Finding id, e.g. F-0012", examples=["F-0012"])


@router.get(
    "",
    summary="Ranked findings of a scan",
    description="Open findings by risk (highest first), then resolved ones. Merged duplicates are folded into "
    "their primary finding.",
    response_model=list[FindingOut],
    responses={404: {"model": ErrorOut, "description": "Unknown scan"}},
)
def list_findings(
    scan_id: str = Query(pattern=r"^S-\d{4,}$", examples=["S-0001"]),
    severity_min: float | None = Query(None, ge=0.0, le=1.0),
    owasp: str | None = Query(None, pattern=r"^A\d{2}$", examples=["A01"]),
    state: Literal["candidate", "corroborated", "confirmed", "resolved"] | None = None,
    mode: Literal["code", "runtime", "correlated"] | None = None,
    sort: Literal["risk", "id"] = "risk",
    query: QueryService = Depends(get_query_service),
) -> list[FindingOut]:
    return query.list_findings(scan_id, severity_min=severity_min, owasp=owasp, state=state, mode=mode, sort=sort)


@router.get(
    "/{finding_id}",
    summary="One finding, explained",
    description="What / where / impact / exploit / fix, the validated claims with the evidence each cites, "
    "every risk factor, and the finding's evidence ids.",
    response_model=FindingDetail,
    responses={404: {"model": ErrorOut}},
)
def get_finding(finding_id: str = FINDING_ID, query: QueryService = Depends(get_query_service)) -> FindingDetail:
    return query.get_finding(finding_id)
