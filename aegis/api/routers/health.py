"""``GET /api/health`` (AG13.1, FASTAPI FA10.1).

Reports what the backend can use right now — never a 500 for a missing piece:

* ``ollama`` — reachable, and whether the configured model is pulled. The probe uses a plain
  infrastructure client with a short timeout, not the scan egress guard (conflict C33): Ollama
  is part of AEGIS, not a scan target.
* ``tools`` — each scanner binary found (and where); a missing one is ``false``.
* ``database`` — the evidence store answers.
* ``db_snapshot_dates`` — the offline vulnerability-database dates scans would use.
* ``repo_scans`` — whether repo URLs can be scanned, and from which git hosts.

``status`` is ``ok`` when the database answers; everything else degrades features, not the
service (a scan without Ollama still runs on rules and templates).
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends
from sqlmodel import select

from aegis.agent.nodes.prepare import snapshot_db_dates
from aegis.api.deps import get_settings, get_store
from aegis.config import AppSettings
from aegis.evidence.models import Scan
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.workers.executor import find_binary

router = APIRouter(prefix="/api", tags=["health"])
log = get_logger("api.health")

TOOLS = ("git", "semgrep", "gitleaks", "nuclei", "katana", "schemathesis", "trivy", "osv-scanner", "syft", "trufflehog", "sslyze")
_OLLAMA_TIMEOUT = 2.0


async def probe_ollama(url: str, model: str) -> dict:
    out = {"url": url, "model": model, "reachable": False, "model_present": False}
    try:
        async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
            resp = await client.get(url.rstrip("/") + "/api/tags")
        resp.raise_for_status()
        names = {m.get("name") for m in (resp.json() or {}).get("models", []) if isinstance(m, dict)}
        out["reachable"] = True
        out["model_present"] = model in names or f"{model}:latest" in names
        out["models"] = sorted(n for n in names if n)
    except (httpx.HTTPError, ValueError) as exc:
        out["error"] = type(exc).__name__
    return out


def _database(store: EvidenceStore) -> bool:
    try:
        with store.session() as s:
            s.exec(select(Scan).limit(1)).all()
        return True
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        log.error("health.database_failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
        return False


def _playwright() -> dict:
    """The browser-login tool: the Python package in this interpreter, plus a staged Chromium."""
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        return {"found": False}
    browsers = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or Path(__file__).resolve().parents[3] / ".tools" / "ms-playwright")
    if not browsers.is_dir() or not any(browsers.glob("chromium*")):
        return {"found": False, "detail": "package installed, Chromium not staged"}
    return {"found": True, "path": str(browsers)}


@router.get("/health", summary="What the backend can use right now")
async def health(settings: AppSettings = Depends(get_settings), store: EvidenceStore = Depends(get_store)) -> dict:
    database = _database(store)
    ollama = await probe_ollama(settings.model.ollama_url, settings.model.name)
    tools = {}
    for name in TOOLS:
        path = find_binary(name)
        tools[name] = {"found": path is not None, **({"path": path} if path else {})}
    tools["playwright"] = _playwright()
    body = {
        "status": "ok" if database else "degraded",
        "database": database,
        "ollama": ollama,
        "tools": tools,
        "db_snapshot_dates": snapshot_db_dates(settings.offline_db_dir),
        # repo scans (TNW-1): on when at least one git host is configured
        "repo_scans": {"enabled": bool(settings.git_hosts), "git_hosts": list(settings.git_hosts)},
    }
    log.info("health.checked", database=database, ollama=ollama["reachable"], tools_found=sum(t["found"] for t in tools.values()))
    return body
