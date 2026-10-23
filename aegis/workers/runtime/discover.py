"""Runtime step 2 — discover routes (PHASES P6.2).

Reads the target's OpenAPI document (/openapi.json, then /swagger.json). The
Katana crawl fallback goes through SafetyController and is added with the other
subprocess tools; without a spec the stage simply has no routes to model.
"""

from __future__ import annotations

import httpx

from aegis.observability import get_logger
from aegis.safety.egress import EgressBlocked
from aegis.workers.runtime.context import Route, RuntimeStageError

log = get_logger("workers.runtime.discover")

_SPEC_PATHS = ("/openapi.json", "/swagger.json")
_METHODS = ("get", "post", "put", "patch", "delete")


def _query_params(item: dict, operation: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(all, required) query parameter names from path-level + operation-level params."""
    names: list[str] = []
    required: list[str] = []
    for param in [*(item.get("parameters") or []), *(operation.get("parameters") or [])]:
        if isinstance(param, dict) and param.get("in") == "query" and param.get("name"):
            if param["name"] not in names:
                names.append(param["name"])
            if param.get("required") and param["name"] not in required:
                required.append(param["name"])
    return tuple(names), tuple(required)


def routes_from_openapi(spec: dict) -> list[Route]:
    routes: list[Route] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            operation = item.get(method)
            if isinstance(operation, dict):
                query, required = _query_params(item, operation)
                routes.append(
                    Route(method=method.upper(), path=path, query_params=query, required_query=required)
                )
    return sorted(routes, key=lambda r: (r.path, r.method))


async def discover_routes(client: httpx.AsyncClient, base_url: str) -> tuple[list[Route], dict]:
    """Return ``(routes, evidence_payload)``."""
    last_status: int | None = None
    for spec_path in _SPEC_PATHS:
        try:
            resp = await client.get(base_url.rstrip("/") + spec_path)
        except EgressBlocked as exc:
            raise RuntimeStageError(f"target host is not on the allowlist: {exc}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeStageError(
                f"target unreachable during discovery ({type(exc).__name__})"
            ) from exc
        last_status = resp.status_code
        if resp.status_code != 200:
            continue
        try:
            spec = resp.json()
        except ValueError:
            continue
        if isinstance(spec, dict) and "paths" in spec:
            routes = routes_from_openapi(spec)
            log.info("discover.openapi", spec=spec_path, routes=len(routes))
            return routes, {
                "method": "GET",
                "route": spec_path,
                "status": 200,
                "routes_found": len(routes),
                "routes": [r.template for r in routes],
            }
    log.warning("discover.no_openapi", status=last_status)
    return [], {
        "method": "GET",
        "route": _SPEC_PATHS[0],
        "status": last_status,
        "routes_found": 0,
        "routes": [],
    }
