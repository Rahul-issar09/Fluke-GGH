"""Runtime step — out-of-band SSRF check (PHASES P6.7, optional).

For each route that takes a URL-like query parameter, ask the target to fetch
the **approved** callback URL (test input ``SSRF-CB-001`` →
``http://callback:8080/hit/<scan_id>``) and then ask the self-hosted listener
whether that URL was requested. A hit that arrives out-of-band is proof the
server made the request.

Safety properties:
* the probe value is resolved from the approved library by ID — the worker
  never composes a payload and never targets any host other than our listener;
* only side-effect-free ``GET`` routes with no path parameters and no other
  required parameters are probed;
* routes/parameters are probed **one at a time**, so a hit is attributed to the
  probe that caused it (the library URL carries only the scan id);
* the listener is queried through the same egress-guarded client, so it must be
  on the scan's allowlist like any other host.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlencode, urlparse

import httpx

from aegis.evidence.adapters.ssrf import SsrfAdapter
from aegis.evidence.normalizer import confirm_with_proof, ingest
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.safety.egress import EgressBlocked
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.runtime.context import Route, RuntimeStageError, Session, request_as

log = get_logger("workers.runtime.ssrf")

TEST_INPUT_ID = "SSRF-CB-001"
_URL_HINTS = (
    "url", "uri", "link", "href", "src", "target", "dest", "destination",
    "redirect", "callback", "webhook", "fetch", "proxy", "feed", "image", "next",
)
_POLL_INTERVAL_S = 0.1


def looks_like_url_param(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _URL_HINTS)


def find_ssrf_candidates(routes: list[Route]) -> list[tuple[Route, str]]:
    """Safe-to-probe (route, parameter) pairs.

    ``GET`` only, no path parameters, and the URL-like parameter must be the
    only required one (we can't invent values for others).
    """
    found: list[tuple[Route, str]] = []
    for route in routes:
        if route.method != "GET" or route.params:
            continue
        for param in route.query_params:
            if not looks_like_url_param(param):
                continue
            if set(route.required_query) - {param}:
                continue
            found.append((route, param))
    return found


def listener_base(callback_url: str) -> str:
    parsed = urlparse(callback_url)
    return f"{parsed.scheme}://{parsed.netloc}"


async def _hit_count(client: httpx.AsyncClient, base: str, token: str) -> int:
    try:
        resp = await client.get(f"{base}/hits/{token}")
    except EgressBlocked as exc:
        raise RuntimeStageError(f"callback listener is not on the allowlist: {exc}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeStageError(f"callback listener unreachable ({type(exc).__name__})") from exc
    if resp.status_code != 200:
        raise RuntimeStageError(f"callback listener returned HTTP {resp.status_code}")
    try:
        return int(resp.json()["count"])
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeStageError("callback listener returned an unexpected response") from exc


async def check_ssrf(
    client: httpx.AsyncClient,
    base_url: str,
    candidates: list[tuple[Route, str]],
    session: Session,
    library: TestInputLibrary,
    scan_id: str,
    *,
    wait_s: float = 5.0,
) -> list[dict]:
    probe_value = library.resolve(TEST_INPUT_ID, scan_id)
    base = listener_base(probe_value)
    results: list[dict] = []
    for route, param in candidates:
        before = await _hit_count(client, base, scan_id)
        path = f"{route.path}?{urlencode({param: probe_value})}"
        reply = await request_as(client, base_url, session, "GET", path)

        deadline = time.monotonic() + wait_s
        after = before
        while True:
            after = await _hit_count(client, base, scan_id)
            if after > before or time.monotonic() >= deadline:
                break
            await asyncio.sleep(_POLL_INTERVAL_S)

        vulnerable = after > before
        results.append(
            {
                "route": route.template,
                "path": route.path,
                "param": param,
                "test_input_id": TEST_INPUT_ID,
                "probe_status": reply.status,
                "hits": after - before,
                "vulnerable": vulnerable,
            }
        )
        log.info(
            "ssrf.checked",
            route=route.template,
            param=param,
            probe_status=reply.status,
            hits=after - before,
            vulnerable=vulnerable,
        )
    return results


def record_ssrf_findings(
    store: EvidenceStore, scan_id: str, mode: str | None, results: list[dict]
) -> list[str]:
    """Persist confirmed out-of-band hits as findings; return their IDs."""
    finding_ids = ingest(store, scan_id, SsrfAdapter(mode=mode).parse(results, scan_id))
    confirm_with_proof(
        store,
        finding_ids,
        {"oob_hit"},
        actor="worker",
        reason="out-of-band callback received from the target server",
    )
    return finding_ids
