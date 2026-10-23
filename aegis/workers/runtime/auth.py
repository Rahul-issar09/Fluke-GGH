"""Runtime step 3 — authenticate the test identities (PHASES P6.3).

Plain HTTP login (JSON or form) for each pre-provisioned identity; the session
(cookie and/or bearer token) is kept **in memory only** — never written to the
store, never logged, never shown to the LLM. A login that needs a real browser
(a CSRF token in the form, a TOTP code, a script-driven page) uses
``login.type: browser``: :func:`browser_authenticate` runs the fixed Playwright
flow through the SafetyController (TNW-4).

Credentials come from the identities file and are never put in error messages.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

import httpx
import yaml

from aegis.observability import get_logger
from aegis.safety.egress import EgressBlocked
from aegis.safety.models import ToolCall
from aegis.workers.runtime.context import RuntimeStageError, Session, target_host

log = get_logger("workers.runtime.auth")

_TOKEN_KEYS = ("access_token", "token")


@dataclass
class IdentitiesConfig:
    login_url: str
    method: str
    body: str  # json | form
    fields: dict[str, str]
    identities: dict[str, dict[str, str]]
    type: str = "http"  # http | browser


def load_identities(path: str | None) -> IdentitiesConfig:
    if not path or not pathlib.Path(path).is_file():
        raise RuntimeStageError("identities file not found")
    try:
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuntimeStageError("identities file is not valid YAML") from exc

    login = data.get("login") or {}
    identities = data.get("identities") or {}
    if "A" not in identities or "B" not in identities:
        raise RuntimeStageError("identities file must define identities A and B")
    if not login.get("url"):
        raise RuntimeStageError("identities file is missing login.url")
    kind = str(login.get("type", "http")).lower()
    if kind not in ("http", "browser"):
        raise RuntimeStageError("login.type must be 'http' or 'browser'")
    if kind == "browser":
        fields = login.get("fields") or {}
        if not (fields.get("username") and fields.get("password") and login.get("submit")):
            raise RuntimeStageError("a browser login needs fields.username, fields.password and submit (CSS selectors)")
        return IdentitiesConfig(
            login_url=str(login["url"]), method="GET", body="browser", fields=dict(fields),
            identities={k: dict(v) for k, v in identities.items()}, type="browser",
        )
    fields = login.get("fields") or {"username": "username", "password": "password"}
    body = str(login.get("body", "json")).lower()
    if body not in ("json", "form"):
        raise RuntimeStageError("login.body must be 'json' or 'form'")
    return IdentitiesConfig(
        login_url=str(login["url"]),
        method=str(login.get("method", "POST")).upper(),
        body=body,
        fields=dict(fields),
        identities={k: dict(v) for k, v in identities.items()},
    )


async def browser_authenticate(
    controller,
    scan_id: str,
    base_url: str,
    cfg: IdentitiesConfig,
    identities_path: str,
    allow: list[str],
    *,
    verify_tls: bool = True,
) -> dict[str, Session]:
    """Log identities A and B in through a headless browser (the ``playwright`` tool)."""
    login_url = _login_target(base_url, cfg.login_url)
    sessions: dict[str, Session] = {}
    for label in ("A", "B"):
        result = await controller.run(ToolCall(
            tool="playwright", scan_id=scan_id, target_host=target_host(login_url),
            args={"login_url": login_url, "identity": label, "identities": identities_path,
                  "allow": list(allow), "verify_tls": verify_tls},
        ))
        if result.blocked_reason and result.blocked_reason.startswith("tool not installed"):
            raise RuntimeStageError("this target needs a browser login, but Playwright is not installed (see TOOL_NOT_WORKING.md TNW-4)")
        if not result.ok or not isinstance(result.output, dict):
            reason = result.blocked_reason or (result.stderr_tail or "").strip() or "no session"
            raise RuntimeStageError(f"browser login failed for identity '{label}': {reason[-300:]}")
        session = Session(cookies=dict(result.output.get("cookies") or {}), headers=dict(result.output.get("headers") or {}))
        if not session.cookies and not session.headers:
            raise RuntimeStageError(f"browser login for identity '{label}' produced no session")
        sessions[label] = session
        log.info("auth.ok", identity=label, via="browser", has_cookie=bool(session.cookies), has_token=bool(session.headers))
    return sessions


def _login_target(base_url: str, login_url: str) -> str:
    return login_url if "://" in login_url else base_url.rstrip("/") + "/" + login_url.lstrip("/")


async def authenticate(
    client: httpx.AsyncClient, base_url: str, cfg: IdentitiesConfig
) -> dict[str, Session]:
    sessions: dict[str, Session] = {}
    target = _login_target(base_url, cfg.login_url)
    for label in ("A", "B"):
        creds = cfg.identities[label]
        payload = {
            cfg.fields.get("username", "username"): creds.get("username", ""),
            cfg.fields.get("password", "password"): creds.get("password", ""),
        }
        client.cookies.clear()
        try:
            if cfg.body == "form":
                resp = await client.request(cfg.method, target, data=payload)
            else:
                resp = await client.request(cfg.method, target, json=payload)
        except EgressBlocked as exc:
            raise RuntimeStageError(f"login host is not on the allowlist: {exc}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeStageError(
                f"login request failed for identity '{label}' ({type(exc).__name__})"
            ) from exc

        if resp.status_code >= 400:
            raise RuntimeStageError(f"login failed for identity '{label}' (HTTP {resp.status_code})")

        session = Session(cookies=dict(resp.cookies.items()))
        try:
            body = resp.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            for key in _TOKEN_KEYS:
                if isinstance(body.get(key), str):
                    session.headers["Authorization"] = f"Bearer {body[key]}"
                    break
        client.cookies.clear()  # the shared jar must never carry one identity into another request

        if not session.cookies and not session.headers:
            raise RuntimeStageError(f"login for identity '{label}' produced no session")
        sessions[label] = session
        log.info(
            "auth.ok",
            identity=label,
            has_cookie=bool(session.cookies),
            has_token=bool(session.headers),
        )
    return sessions
