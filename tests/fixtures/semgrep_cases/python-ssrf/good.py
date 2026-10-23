from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

ALLOWED_HOSTS = {"images.example.internal"}


@router.get("/fetch")
async def fetch(url: str, request: Request):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="url not allowed")
    resp = await request.app.state.http.get(url)
    return resp.status_code


@router.get("/status")
def status():
    return requests.get("https://status.example.internal/health", timeout=5).status_code


@router.get("/settings")
def settings(key: str, request: Request):
    # dict.get is not a network call
    return request.app.state.settings.get(key)
