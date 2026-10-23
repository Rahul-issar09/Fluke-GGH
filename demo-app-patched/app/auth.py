"""Demo authentication — patched: salted scrypt instead of MD5."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request


def new_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=bytes.fromhex(salt), n=2**14, r=8, p=1
    ).hex()


def verify_password(password: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), expected)


def new_session_token() -> str:
    return secrets.token_hex(16)


def current_user(request: Request):
    token = request.cookies.get("session")
    user_id = request.app.state.sessions.get(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return request.app.state.db.execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def login_user_id(db, username: str, password: str):
    """The user id for these credentials, or None (used by the browser login form)."""
    row = db.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,)).fetchone()
    return row["id"] if row and verify_password(password, row["salt"], row["password_hash"]) else None
