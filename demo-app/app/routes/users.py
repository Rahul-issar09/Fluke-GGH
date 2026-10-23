"""User search — INTENTIONALLY VULNERABLE (planted SQL built by string concatenation)."""
from __future__ import annotations

from fastapi import APIRouter, Request

from ..auth import current_user

router = APIRouter()


@router.get("/api/users/search")
def search_users(name: str, request: Request):
    current_user(request)
    # PLANTED WEAKNESS: user input concatenated into the SQL text.
    query = "SELECT id, username FROM users WHERE username LIKE '%" + name + "%'"
    rows = request.app.state.db.execute(query).fetchall()
    return [{"id": r["id"], "username": r["username"]} for r in rows]
