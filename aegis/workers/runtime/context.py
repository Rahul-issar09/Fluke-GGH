"""Shared types + HTTP helper for the runtime worker (Worker 1, AG06.1).

Worker modules never import the agent/graph layer (layering): they expose plain
async functions and raise :class:`RuntimeStageError`; the graph-side step
adapters (``agent/nodes/runtime_subgraph.py``) translate that into a stage
abort.

All HTTP goes through an egress-guarded ``httpx.AsyncClient``
(``safety.egress.make_client``): non-allowlisted hosts are blocked and requests
are rate limited. Login sessions live in memory only.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Any

import httpx

__all__ = [
    "RuntimeStageError",
    "Route",
    "Session",
    "Reply",
    "ObjectRoute",
    "RuntimeContext",
    "auth_headers",
    "request_as",
    "target_host",
]

_PARAM = re.compile(r"\{([^}/]+)\}")


class RuntimeStageError(Exception):
    """A runtime-worker step cannot continue (unreachable target, login failed, …)."""


@dataclass(frozen=True)
class Route:
    method: str
    path: str  # OpenAPI template, e.g. /api/accounts/{id}
    query_params: tuple[str, ...] = ()  # declared query parameter names
    required_query: tuple[str, ...] = ()  # the subset the API marks required

    @property
    def params(self) -> tuple[str, ...]:
        return tuple(_PARAM.findall(self.path))

    @property
    def template(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Session:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Reply:
    status: int
    json: Any
    text: str
    timing_ms: int


@dataclass
class ObjectRoute:
    """A GET-by-id route plus the object IDs the owner identity can legitimately see."""

    route: Route
    list_path: str
    owner_ids: list[Any]


@dataclass
class RuntimeContext:
    scan_id: str
    base_url: str
    client: httpx.AsyncClient
    identities_path: str | None = None
    spec_path: str | None = None  # where the OpenAPI document was found
    routes: list[Route] = field(default_factory=list)
    sessions: dict[str, Session] = field(default_factory=dict)
    model: list[ObjectRoute] = field(default_factory=list)


def verify_tls(scan_cfg: dict) -> bool:
    """The scan's ``options.verify_tls`` (default true): false accepts a self-signed certificate."""
    return (scan_cfg.get("options") or {}).get("verify_tls", True) is not False


def target_host(url: str) -> str:
    """``host:port`` for a URL (scheme default port when none is given)."""
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname}:{port}"


def auth_headers(session: Session | None) -> dict[str, str]:
    """HTTP headers that carry *session*'s credentials (cookie and/or bearer token)."""
    if session is None:
        return {}
    headers = dict(session.headers)
    if session.cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    return headers


async def request_as(
    client: httpx.AsyncClient,
    base_url: str,
    session: Session | None,
    method: str,
    path: str,
) -> Reply:
    """Send one request as *session* and return status/JSON/timing.

    The client's cookie jar is cleared first and the identity's credentials are
    sent explicitly, so one identity's session can never leak into another's
    request.
    """
    client.cookies.clear()
    started = time.monotonic()
    resp = await client.request(method, base_url.rstrip("/") + path, headers=auth_headers(session))
    client.cookies.clear()
    timing = int((time.monotonic() - started) * 1000)
    try:
        body = resp.json()
    except ValueError:
        body = None
    return Reply(status=resp.status_code, json=body, text=resp.text, timing_ms=timing)
