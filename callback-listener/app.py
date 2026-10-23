"""AEGIS callback listener (PHASES P6.7) — out-of-band hit recorder.

A tiny service on the scan network. When the target server fetches a URL we
supplied (the approved test input ``SSRF-CB-001`` →
``http://callback:8080/hit/<scan_id>``), the request lands here and is counted.
AEGIS then asks ``GET /hits/<scan_id>`` whether a hit arrived; an out-of-band
hit is the proof of server-side request forgery.

It records only the *fact* of a hit: method, time and (when available) the
caller address. Never request bodies or headers. Memory is bounded.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_TOKENS = 1000
_MAX_HITS_PER_TOKEN = 100


def create_app() -> FastAPI:
    app = FastAPI(title="AEGIS callback listener")
    hits: dict[str, list[dict]] = {}
    app.state.hits = hits

    def _check(token: str) -> str:
        if not _TOKEN.match(token):
            raise HTTPException(status_code=400, detail="invalid token")
        return token

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.api_route("/hit/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    async def hit(token: str, request: Request):
        _check(token)
        if token not in hits and len(hits) >= _MAX_TOKENS:
            raise HTTPException(status_code=429, detail="too many tokens")
        entries = hits.setdefault(token, [])
        if len(entries) < _MAX_HITS_PER_TOKEN:
            entries.append(
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "method": request.method,
                    "from": request.client.host if request.client else None,
                }
            )
        return {"ok": True}

    @app.get("/hits/{token}")
    def get_hits(token: str):
        _check(token)
        entries = hits.get(token, [])
        return {"token": token, "count": len(entries), "hits": entries}

    return app


app = create_app()
