"""URL fetch — INTENTIONALLY VULNERABLE (planted SSRF)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException, Request

from ..auth import current_user

router = APIRouter()


@router.get("/api/fetch")
async def fetch(url: str, request: Request):
    current_user(request)
    # PLANTED WEAKNESS (SSRF): the server fetches any URL the caller supplies.
    try:
        resp = await request.app.state.http.get(url)
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="upstream fetch failed")
    return {"status": resp.status_code, "length": len(resp.content)}
