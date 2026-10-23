"""Demo web pages (TNW-4): a home page that links to the API, and a browser login form.

* ``GET /`` and ``GET /static/app.js`` — what a crawler sees when the app publishes no OpenAPI
  document (start the app with ``DEMO_OPENAPI=0``): links to the account pages, and a script
  that calls the search and fetch endpoints.
* ``GET /login-form`` / ``POST /login-form`` — a login a plain HTTP client cannot do: a CSRF
  token (cookie + hidden field, both must match) and, for bob, a TOTP code (RFC 6238, 30 s).
  It sets the same ``session`` cookie as ``POST /login``.
"""
from __future__ import annotations

import base64
import os
import hashlib
import hmac
import secrets
import struct
import time
from pathlib import Path
from html import escape
from urllib.parse import parse_qs

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import auth

router = APIRouter(include_in_schema=False)

# demo-only TOTP seeds (base32): bob signs in with a one-time code as well
_TWO_FACTOR = {"bob": "JBSWY3DPEHPK3PXP"}

_HOME = """<!doctype html>
<html><head><title>Demo bank</title><script src="/static/app.js"></script></head>
<body>
<h1>Demo bank</h1>
<p><a href="/ui/">Open the app</a> &middot; <a href="/login-form">Sign in</a></p>
<ul>
  <li><a href="/api/accounts">My accounts</a></li>
  <li><a href="/api/accounts/1">Account 1</a></li>
</ul>
</body></html>
"""

_SCRIPT = """// demo bank front end
const API = {
  search: "/api/users/search?name=demo",
  preview: "/api/fetch?url=link",
};
async function searchUsers(name) {
  return (await fetch(API.search.replace("demo", encodeURIComponent(name)))).json();
}
async function previewLink(link) {
  return (await fetch(API.preview.replace("link", encodeURIComponent(link)))).json();
}
"""

_FORM = """<!doctype html>
<html><head><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
{error}
<form method="post" action="/login-form">
  <input type="hidden" name="csrf" value="{csrf}">
  <label>User <input id="username" name="username" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password"></label>
  <label>Code (if you use two-factor) <input id="code" name="code" inputmode="numeric"></label>
  <button type="submit">Sign in</button>
</form>
</body></html>
"""


def install(app: FastAPI) -> None:
    """Add the demo pages and, when it is present, the static browser frontend at ``/ui``.

    With ``DEMO_OPENAPI=0`` the app also stops publishing its API description
    (``/openapi.json``, ``/docs``, ``/redoc``) — the case a crawler is for."""
    app.include_router(router)
    if os.environ.get("DEMO_OPENAPI", "1") == "0":
        hidden = {app.openapi_url, app.docs_url, app.redoc_url, app.swagger_ui_oauth2_redirect_url}
        app.router.routes = [r for r in app.router.routes if getattr(r, "path", None) not in hidden]
    # the frontend lives next to the app package (demo-app/frontend); a patched-build copy ships
    # only app/, so the mount is skipped there. Served from the same origin, so no CORS is needed.
    ui = Path(__file__).resolve().parent.parent / "frontend"
    if ui.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/ui", StaticFiles(directory=str(ui), html=True), name="ui")


def totp(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(code).zfill(digits)


def _code_ok(secret: str, code: str) -> bool:
    now = time.time()
    return any(hmac.compare_digest(totp(secret, now + drift), code) for drift in (-30, 0, 30))


@router.get("/", response_class=HTMLResponse)
def home():
    return _HOME


@router.get("/static/app.js")
def script():
    return Response(_SCRIPT, media_type="application/javascript")


def _form(csrf: str, error: str = "", status: int = 200) -> HTMLResponse:
    response = HTMLResponse(_FORM.format(csrf=csrf, error=f"<p role='alert'>{escape(error)}</p>" if error else ""), status_code=status)
    response.set_cookie("csrf", csrf, httponly=True, samesite="strict")
    return response


@router.get("/login-form", response_class=HTMLResponse)
def login_form():
    return _form(secrets.token_hex(16))


@router.post("/login-form")
async def login_form_submit(request: Request):
    # parsed by hand: an application/x-www-form-urlencoded body (no python-multipart dependency)
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode("utf-8", "replace")).items()}
    sent, expected = str(form.get("csrf", "")), request.cookies.get("csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        return _form(secrets.token_hex(16), "Your form expired, please try again.", 403)
    username = str(form.get("username", ""))
    user_id = auth.login_user_id(request.app.state.db, username, str(form.get("password", "")))
    secret = _TWO_FACTOR.get(username)
    if user_id is None or (secret and not _code_ok(secret, str(form.get("code", "")).strip())):
        return _form(secrets.token_hex(16), "Wrong user name, password or code.", 401)
    token = auth.new_session_token()
    request.app.state.sessions[token] = user_id
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("session", token, httponly=True)
    response.delete_cookie("csrf")
    return response
