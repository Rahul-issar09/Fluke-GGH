"""Browser login for one test identity (TNW-4) — run by the SafetyController as the ``playwright`` tool.

    python -m aegis.workers.runtime.browser_login --login-url URL --identities FILE --identity A
                                                  --allow host:port[,host:port…] [--insecure]

A fixed flow, never a script from the scan: open the login page in headless Chromium, fill the
user name and password (and a TOTP code when the identity has ``totp_secret``) into the selectors
the identities file names, submit, and wait for the session cookie it names. Prints
``{"cookies": {...}, "headers": {...}}`` for the target host on success; on failure prints a reason
to stderr (never a credential) and exits 2.

The browser can only reach the hosts in ``--allow`` (the scan's allowlist): every other request —
an analytics script, an off-list redirect — is aborted. Nothing is downloaded and no service
worker runs. Credentials are read from the identities file here, so they never appear in the
tool call's arguments.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.parse import urlparse

import yaml

from aegis.safety.allowlist import Allowlist
from aegis.workers.runtime.totp import totp

_DEFAULT_PORTS = {"https": 443, "http": 80}
_TIMEOUT_MS = 20_000


class LoginFailed(Exception):
    """The login did not produce a session (the message is safe to show)."""


def _host_port(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in _DEFAULT_PORTS or not parsed.hostname:
        return None
    return f"{parsed.hostname}:{parsed.port or _DEFAULT_PORTS[parsed.scheme]}"


def browser_config(path: str, identity: str) -> tuple[dict, dict]:
    """``(login, credentials)`` from the identities file, checked for what the flow needs."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    login = data.get("login") or {}
    creds = (data.get("identities") or {}).get(identity)
    fields = login.get("fields") or {}
    if login.get("type") != "browser" or not fields.get("username") or not fields.get("password") or not login.get("submit"):
        raise LoginFailed("the identities file has no complete browser login (type, fields.username/password, submit)")
    if not isinstance(creds, dict):
        raise LoginFailed(f"the identities file has no identity '{identity}'")
    return login, creds


def login(login_url: str, identities: str, identity: str, allow: list[str], *, insecure: bool = False) -> dict:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    cfg, creds = browser_config(identities, identity)
    fields = cfg["fields"]
    success = cfg.get("success") or {}
    cookie_name = success.get("cookie")
    token_key = success.get("local_storage")
    allowlist = Allowlist(allow)
    target = _host_port(login_url)
    blocked: list[str] = []

    def guard(route):
        url = route.request.url
        host = _host_port(url)
        if url.startswith(("data:", "blob:", "about:")) or (host and allowlist.check(host)):
            route.continue_()
        else:
            blocked.append(host or url.split(":", 1)[0])
            route.abort("blockedbyclient")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            context = browser.new_context(ignore_https_errors=insecure, accept_downloads=False, service_workers="block")
            context.set_default_timeout(_TIMEOUT_MS)
            context.route("**/*", guard)
            page = context.new_page()
            try:
                page.goto(login_url, wait_until="domcontentloaded")
                page.fill(fields["username"], str(creds.get("username", "")))
                page.fill(fields["password"], str(creds.get("password", "")))
                if fields.get("totp") and creds.get("totp_secret"):
                    page.fill(fields["totp"], totp(str(creds["totp_secret"])))
                page.click(cfg["submit"])
                try:
                    page.wait_for_load_state("networkidle", timeout=_TIMEOUT_MS)
                except PlaywrightError:
                    pass  # a page that keeps polling never goes idle; the cookie check below decides
            except PlaywrightError as exc:
                first = str(exc).splitlines()[0][:160] if str(exc) else type(exc).__name__
                raise LoginFailed(f"the login page could not be used ({first})") from None

            deadline = time.monotonic() + 10
            while True:
                cookies = {c["name"]: c["value"] for c in context.cookies(login_url)}
                if not cookie_name or cookie_name in cookies or time.monotonic() > deadline:
                    break
                page.wait_for_timeout(250)
            headers: dict[str, str] = {}
            if token_key:
                value = page.evaluate("key => window.localStorage.getItem(key)", token_key)
                if isinstance(value, str) and value:
                    headers["Authorization"] = f"Bearer {value}"
        finally:
            browser.close()

    if cookie_name and cookie_name not in cookies:
        reason = f"no '{cookie_name}' cookie after submitting the form (wrong credentials or code, or a changed page?)"
        if blocked:
            reason += f"; blocked hosts not on the allowlist: {', '.join(sorted(set(blocked)))}"
        raise LoginFailed(reason)
    if token_key and not headers:
        raise LoginFailed(f"no '{token_key}' token in the page's local storage after login")
    if not cookies and not headers:
        raise LoginFailed("the login produced no session")
    return {"cookies": cookies, "headers": headers, "target": target}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="browser_login")
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--identities", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--allow", required=True)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args(argv)
    try:
        session = login(args.login_url, args.identities, args.identity, [a for a in args.allow.split(",") if a], insecure=args.insecure)
    except LoginFailed as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    except Exception as exc:  # noqa: BLE001 - the browser failed to start, etc.: say what, never the inputs
        sys.stderr.write(f"the browser login could not run ({type(exc).__name__})\n")
        return 2
    sys.stdout.write(json.dumps(session))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
