"""AEGIS demo target — INTENTIONALLY VULNERABLE. Test fixture only; never deploy."""
from __future__ import annotations

import sqlite3

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from . import auth, web
from .routes import accounts, fetch, users

_USERS = [(1, "alice", "alice-demo-pass"), (2, "bob", "bob-demo-pass")]
_ACCOUNTS = [(1, 1, "ACC-1001", 1200.50), (2, 2, "ACC-2002", 87.25)]


def _seed(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    db.execute(
        "CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner_id INTEGER, "
        "account_number TEXT, balance REAL)"
    )
    for uid, name, pw in _USERS:
        db.execute("INSERT INTO users VALUES (?, ?, ?)", (uid, name, auth.hash_password(pw)))
    db.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?)", _ACCOUNTS)
    db.commit()


def create_app(http_client: httpx.AsyncClient | None = None) -> FastAPI:
    app = FastAPI(title="AEGIS demo target (intentionally vulnerable)")
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    _seed(db)
    app.state.db = db
    app.state.sessions = {}
    app.state.http = http_client or httpx.AsyncClient(timeout=5.0)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/login")
    async def login(request: Request):
        body = await request.json()
        row = request.app.state.db.execute(
            "SELECT id FROM users WHERE username = ? AND password_hash = ?",
            (body.get("username"), auth.hash_password(str(body.get("password", "")))),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = auth.new_session_token()
        request.app.state.sessions[token] = row["id"]
        response = JSONResponse({"ok": True})
        response.set_cookie("session", token, httponly=True)
        return response

    app.include_router(accounts.router)
    app.include_router(users.router)
    app.include_router(fetch.router)
    web.install(app)
    return app


app = create_app()
