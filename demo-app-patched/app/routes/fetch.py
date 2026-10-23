"""URL fetch — patched: only allowlisted upstream hosts may be fetched."""
from __future__ import annotations

from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request

from ..auth import current_user

router = APIRouter()

ALLOWED_FETCH_HOSTS = {"images.example.internal"}


@router.get("/api/fetch")
async def fetch(url: str, request: Request):
    current_user(request)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        raise HTTPException(status_code=400, detail="url not allowed")  # FIX: allowlist
    try:
        resp = await request.app.state.http.get(url)
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="upstream fetch failed")
    return {"status": resp.status_code, "length": len(resp.content)}
