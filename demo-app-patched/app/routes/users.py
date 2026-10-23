"""User search — patched: parameterized query."""
from __future__ import annotations

from fastapi import APIRouter, Request

from ..auth import current_user

router = APIRouter()


@router.get("/api/users/search")
def search_users(name: str, request: Request):
    current_user(request)
    rows = request.app.state.db.execute(
        "SELECT id, username FROM users WHERE username LIKE ?", (f"%{name}%",)
    ).fetchall()
    return [{"id": r["id"], "username": r["username"]} for r in rows]
