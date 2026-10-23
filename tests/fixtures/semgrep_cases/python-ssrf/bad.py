import httpx
import requests
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/fetch")
async def fetch(url: str, request: Request):
    resp = await request.app.state.http.get(url)  # ruleid: python-ssrf
    return resp.status_code


@router.get("/preview")
def preview(link: str):
    return requests.get(link, timeout=5).text  # ruleid: python-ssrf


@router.get("/proxy")
def proxy(target: str):
    with httpx.Client() as client:
        return client.get(target).text  # ruleid: python-ssrf
