"""Fixes: verify a drafted fix, read it, approve its commit (AG13.2, FASTAPI FA08.1).

``POST /api/findings/{id}/fix`` starts verifying the finding's latest draft in the background
(copy → apply → static / tests / runtime checks) and returns at once; ``GET /api/fixes/{id}``
shows ``verifying``, then ``awaiting_approval`` (with the request to approve) or ``failed``
(with the reason). ``POST /api/fixes/{id}/commit`` is the human approval: ``patch`` writes a
``.diff``; ``apply`` writes the verified files into the scanned folder (refused on a read-only
mount, C14); ``pr`` is not enabled yet (C6) and answers 409.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path

from aegis.api.deps import get_fix_service
from aegis.api.schemas import CommitRequest, ErrorOut, FixOut
from aegis.services.fix_service import FixService

router = APIRouter(prefix="/api", tags=["fix"])

FIX_ID = Path(pattern=r"^X-\d{4,}$", description="Fix id, e.g. X-0003", examples=["X-0003"])


def fix_out(view: dict) -> FixOut:
    """The service view as the frozen ``FixOut``; approval, draft and resolution ride in ``verify_report``."""
    report = dict(view.get("verify_report") or {})
    report.update(
        {
            "draft": view.get("draft"),
            "approval": view.get("approval"),
            "resolution": view.get("resolution"),
            "commit_mode": view.get("commit_mode"),
        }
    )
    return FixOut(fix_id=view["fix_id"], finding_id=view["finding_id"], status=view["status"], diff=view["diff"], verify_report=report)


@router.post(
    "/findings/{finding_id}/fix",
    status_code=202,
    summary="Verify the drafted fix",
    description="Starts verifying the finding's latest fix draft on a copy of the code. Nothing of yours changes. "
    "Poll `GET /api/fixes/{fix_id}` until it is `awaiting_approval` or `failed`.",
    responses={404: {"model": ErrorOut}, 409: {"model": ErrorOut, "description": "No fresh draft, or already verifying"}},
)
async def start_fix(
    finding_id: str = Path(pattern=r"^F-\d{4,}$", examples=["F-0012"]),
    fixes: FixService = Depends(get_fix_service),
) -> dict:
    return {"fix_id": fixes.submit(finding_id)}


@router.get(
    "/fixes/{fix_id}",
    summary="A fix: diff, verification, approval request",
    response_model=FixOut,
    responses={404: {"model": ErrorOut}},
)
async def get_fix(fix_id: str = FIX_ID, fixes: FixService = Depends(get_fix_service)) -> FixOut:
    return fix_out(await fixes.get(fix_id))


@router.post(
    "/fixes/{fix_id}/commit",
    summary="Approve and commit a verified fix",
    description="The human approval. `patch` → a `.diff` file; `apply` → the verified files are written into the "
    "scanned folder; then the finding is resolved with the verification's retest evidence.",
    response_model=FixOut,
    responses={404: {"model": ErrorOut}, 409: {"model": ErrorOut, "description": "Not verified, not waiting, or pr mode"}},
)
async def commit_fix(
    fix_id: str = FIX_ID,
    body: CommitRequest = Body(openapi_examples={"apply": {"value": {"mode": "apply"}}, "patch": {"value": {"mode": "patch"}}}),
    fixes: FixService = Depends(get_fix_service),
) -> FixOut:
    return fix_out(await fixes.commit(fix_id, body.mode))
