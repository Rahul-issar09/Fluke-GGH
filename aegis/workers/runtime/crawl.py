"""Runtime step — crawl for routes when the target publishes no OpenAPI document (TNW-4, PHASES P6.2).

Katana runs through the SafetyController (allowlist, policy, rate limit, audit) as the logged-in
test identity A, so pages behind the login are found too. It follows links and the endpoints
named in the app's JavaScript, stays on the target host, never submits forms and skips URLs that
look like they change state (log out, delete, remove).

Each crawled URL becomes a :class:`Route` like the ones read from an OpenAPI document: numeric /
UUID path segments become ``{id}`` (``/api/accounts/1`` → ``/api/accounts/{id}``) and the query
parameter names seen are kept, so the access-control and SSRF checks can use them.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from aegis.graph.route_normalize import normalize_path
from aegis.observability import get_logger
from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.runtime.context import Route, target_host

__all__ = ["run_katana", "routes_from_crawl", "STATIC_EXTENSIONS"]

log = get_logger("workers.runtime.crawl")

STATIC_EXTENSIONS = (
    "js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
    "woff", "woff2", "ttf", "eot", "pdf", "zip", "txt", "xml",
)
_SKIP_STATUS = (404, 405, 410)


async def run_katana(
    controller: SafetyController,
    scan_id: str,
    base_url: str,
    *,
    rate_limit: float = 5,
    headers: dict[str, str] | None = None,
) -> ToolResult:
    args: dict = {"url": base_url, "rate_limit": max(1, min(100, int(rate_limit)))}
    if headers:
        args["headers"] = headers
    return await controller.run(ToolCall(tool="katana", scan_id=scan_id, target_host=target_host(base_url), args=args))


def _template(path: str) -> str:
    """``/api/accounts/1`` → ``/api/accounts/{id}``; a second parameter becomes ``{id2}``, …"""
    out, n = [], 0
    for segment in normalize_path(path).split("/")[1:]:
        if segment == "{param}":
            n += 1
            segment = "{id}" if n == 1 else f"{{id{n}}}"
        out.append(segment)
    return "/" + "/".join(out)


def routes_from_crawl(rows, base_url: str) -> list[Route]:
    """The routes behind Katana's ``-jsonl`` rows that are on the target itself."""
    want = target_host(base_url)
    found: dict[tuple[str, str], set[str]] = {}
    for row in rows if isinstance(rows, list) else []:
        request = row.get("request") if isinstance(row, dict) else None
        if not isinstance(request, dict) or not request.get("endpoint"):
            continue
        url = urlparse(str(request["endpoint"]))
        if url.scheme not in ("http", "https") or target_host(url.geturl()) != want:
            continue
        status = (row.get("response") or {}).get("status_code")
        if status in _SKIP_STATUS:
            continue
        last = url.path.rsplit("/", 1)[-1]
        if "." in last and last.rsplit(".", 1)[-1].lower() in STATIC_EXTENSIONS:
            continue
        key = (str(request.get("method") or "GET").upper(), _template(url.path or "/"))
        found.setdefault(key, set()).update(parse_qs(url.query, keep_blank_values=True))
    routes = [
        Route(method=method, path=path, query_params=tuple(sorted(query)), required_query=tuple(sorted(query)))
        for (method, path), query in found.items()
    ]
    routes.sort(key=lambda r: (r.path, r.method))
    log.info("crawl.routes", routes=[r.template for r in routes])
    return routes
