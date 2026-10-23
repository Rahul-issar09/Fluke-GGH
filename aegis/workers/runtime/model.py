"""Runtime step 4 — build the request model (PHASES P6.4).

Finds object routes (``GET /x/{id}`` with a sibling list route ``GET /x``) and
asks the *owner* identity's list endpoint which object IDs it legitimately has,
so the differential check replays only real, owned objects.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from aegis.observability import get_logger
from aegis.workers.runtime.context import ObjectRoute, Route, Session, request_as

log = get_logger("workers.runtime.model")

_OBJECT_PATH = re.compile(r"^(?P<parent>.*)/\{(?P<param>[^/}]+)\}$")


def _ids_from(body: Any) -> list[Any]:
    items = body
    if isinstance(body, dict):
        items = body.get("items") or body.get("data") or body.get("results")
    if not isinstance(items, list):
        return []
    return [it["id"] for it in items if isinstance(it, dict) and "id" in it]


async def build_model(
    client: httpx.AsyncClient,
    base_url: str,
    routes: list[Route],
    sessions: dict[str, Session],
    owner: str = "A",
) -> list[ObjectRoute]:
    gets = {r.path: r for r in routes if r.method == "GET"}
    model: list[ObjectRoute] = []
    for path, route in sorted(gets.items()):
        match = _OBJECT_PATH.match(path)
        if not match or len(route.params) != 1:
            continue
        list_path = match.group("parent") or "/"
        if list_path not in gets or gets[list_path].params:
            log.info("model.no_list_route", route=route.template)
            continue
        reply = await request_as(client, base_url, sessions[owner], "GET", list_path)
        ids = _ids_from(reply.json) if reply.status < 400 else []
        if not ids:
            log.info("model.no_owned_objects", route=route.template, status=reply.status)
            continue
        model.append(ObjectRoute(route=route, list_path=list_path, owner_ids=ids))
        log.info("model.object_route", route=route.template, owner=owner, objects=len(ids))
    return model
