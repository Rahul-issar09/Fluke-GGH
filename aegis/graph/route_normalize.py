"""Route normalization (PHASES P9.1) — pure, deterministic.

Makes a route written in source (``/api/accounts/<int:id>``, ``/api/accounts/{id}``)
comparable to one observed at runtime (``/api/accounts/12/``): every parameter
segment becomes ``{param}``, the method is upper-cased, the query string and a
trailing slash are dropped.

A segment is a parameter when it is a framework placeholder (``{id}`` FastAPI/Spring,
``<int:id>`` Flask/Django, ``:id`` Express), a number, or a UUID. Everything else is a literal and is kept
exactly — ``/v1`` is not a parameter.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

__all__ = ["normalize_path", "normalize_route", "split_route"]

_PARAM = "{param}"
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_WHOLE_PLACEHOLDER = re.compile(r"^(?:\{[^{}]+\}|<[^<>]+>|:[A-Za-z_][A-Za-z0-9_]*\??)$")
_PLACEHOLDER = re.compile(r"\{[^{}]+\}|<[^<>]+>")


def _normalize_segment(segment: str) -> str:
    if _WHOLE_PLACEHOLDER.match(segment) or segment.isdigit() or _UUID.match(segment):
        return _PARAM
    # placeholder embedded in a literal, e.g. /files/{name}.{ext}
    return _PLACEHOLDER.sub(_PARAM, segment)


def normalize_path(path: str) -> str:
    """Normalize the path part of a route (no method)."""
    if "://" in path:  # a full URL from runtime discovery
        path = urlparse(path).path
    path = path.split("#", 1)[0].split("?", 1)[0]
    segments = [s for s in path.split("/") if s]  # also collapses // and trailing /
    return "/" + "/".join(_normalize_segment(s) for s in segments)


def normalize_route(method: str, path: str) -> str:
    """``normalize_route("get", "/api/accounts/12/") == "GET /api/accounts/{param}"``."""
    return f"{method.strip().upper()} {normalize_path(path)}"


def split_route(route: str) -> tuple[str, str] | None:
    """Split a finding's ``"GET /api/accounts/{id}"`` into ``(method, path)``."""
    parts = route.strip().split(None, 1)
    if len(parts) != 2 or not parts[0].isalpha():
        return None
    return parts[0].upper(), parts[1]
