"""Evidence records (AG13.2, FASTAPI FA05.1). Read-only; the raw payload is returned here —
this is the operator's own surface (the MCP server applies its own redaction, AG16)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path

from aegis.api.deps import get_query_service
from aegis.api.schemas import ErrorOut, EvidenceOut
from aegis.services.query_service import QueryService

router = APIRouter(prefix="/api/evidence", tags=["findings"])


@router.get(
    "/{evidence_id}",
    summary="One evidence record",
    description="The raw proof behind a claim: the HTTP exchange, code location, data flow, out-of-band hit …",
    response_model=EvidenceOut,
    responses={404: {"model": ErrorOut}},
)
def get_evidence(
    evidence_id: str = Path(pattern=r"^E-\d{4,}$", examples=["E-0041"]),
    query: QueryService = Depends(get_query_service),
) -> EvidenceOut:
    return query.get_evidence(evidence_id)
