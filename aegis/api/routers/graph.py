"""Security graph and CBOM (AG13.2, FASTAPI FA06.1). Read-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from aegis.api.deps import get_query_service
from aegis.api.schemas import ErrorOut
from aegis.services.query_service import QueryService

router = APIRouter(prefix="/api", tags=["graph"])

SCAN_ID = Query(pattern=r"^S-\d{4,}$", examples=["S-0001"])


@router.get(
    "/graph",
    summary="Attack-path graph",
    description="Cytoscape-style `{nodes, edges}`: endpoints, handler functions, sinks and findings. "
    "`HANDLED_BY` edges carry the correlation score and its signals. `attack_paths` lists the chains.",
    responses={404: {"model": ErrorOut, "description": "Unknown scan, or its graph is not built yet"}},
)
def get_graph(scan_id: str = SCAN_ID, query: QueryService = Depends(get_query_service)) -> dict:
    return query.get_graph(scan_id)


@router.get(
    "/cbom",
    summary="Cryptography bill of materials (CycloneDX 1.6)",
    description="Every cryptographic asset the scan found (algorithm, key size, TLS settings and live endpoints), "
    "with `aegis:classical_risk` and `aegis:quantum_risk` verdicts. Written by the crypto stage of code / correlated scans.",
    responses={404: {"model": ErrorOut, "description": "Unknown scan, or no CBOM for it"}},
)
def get_cbom(scan_id: str = SCAN_ID, query: QueryService = Depends(get_query_service)) -> dict:
    return query.get_cbom(scan_id)
