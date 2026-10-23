"""Demo authentication — INTENTIONALLY VULNERABLE (planted weak password hashing)."""
from __future__ import annotations

import hashlib
import secrets

from fastapi import HTTPException, Request


def hash_password(password: str) -> str:
    # PLANTED WEAKNESS: MD5 is not a password hash (weak crypto finding).
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def new_session_token() -> str:
    return secrets.token_hex(16)


def current_user(request: Request):
    """Return the logged-in user row, or raise 401."""
    token = request.cookies.get("session")
    user_id = request.app.state.sessions.get(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return request.app.state.db.execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def login_user_id(db, username: str, password: str):
    """The user id for these credentials, or None (used by the browser login form)."""
    row = db.execute(
        "SELECT id FROM users WHERE username = ? AND password_hash = ?", (username, hash_password(password))
    ).fetchone()
    return row["id"] if row else None
