"""TNW-4 — Katana (routes for apps without an OpenAPI document) and Playwright (browser logins).

* Katana: the policy and the fixed command line (same host only, no form submission, no
  log-out/delete URLs, no raw requests in the output); crawled URLs become routes
  (``/api/accounts/1`` → ``/api/accounts/{id}``, query parameter names kept),
* Playwright: the policy (credentials never in the arguments, the browser limited to the scan's
  allowlist), the identities file's ``login.type: browser``, TOTP codes,
* the runtime stage: with no OpenAPI document the crawl's routes feed the access-control and SSRF
  checks, and a browser login provides the two sessions — over the in-process demo network, with
  Katana's real recorded output and a stand-in for the browser,
* ``-m tools``: real Katana and real Playwright (headless Chromium) against the demo app served
  without its OpenAPI document, signing in through its CSRF + TOTP login form.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import httpx
import pytest

import aegis.agent.nodes.runtime_subgraph  # noqa: F401 - registers the runtime steps
from _graph_helpers import make_run
from aegis.agent.nodes.worker_stage import run_steps
from aegis.evidence.models import Mode
from aegis.safety.models import ToolCall, ToolResult
from aegis.safety.policies import PolicyError, required_target, validate_args
from aegis.workers import executor
from aegis.workers.runtime.auth import load_identities
from aegis.workers.runtime.browser_login import LoginFailed, browser_config
from aegis.workers.runtime.context import RuntimeStageError
from aegis.workers.runtime.crawl import routes_from_crawl
from aegis.workers.runtime.totp import totp
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("TNW-4")

KATANA_RECORDED = ROOT / "tests" / "fixtures" / "tools" / "katana_demo.jsonl"
BROWSER_IDENTITIES = ROOT / "demo-app" / "identities-browser.yml"
CRAWLED = ["GET /", "GET /api/accounts", "GET /api/accounts/{id}", "GET /api/fetch", "GET /api/users/search", "GET /login-form"]


def katana_rows(host: str) -> list[dict]:
    text = KATANA_RECORDED.read_text(encoding="utf-8").replace("{HOST}", host)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# --------------------------------------------------------------------------------------------- #
# Katana
# --------------------------------------------------------------------------------------------- #
def test_the_katana_policy():
    ok = validate_args("katana", {"url": "https://example.com", "headers": {"Cookie": "session=x"}})
    assert (ok["depth"], ok["rate_limit"], ok["crawl_seconds"]) == (3, 5, 60)
    for args, why in [
        ({"url": "file:///etc/passwd"}, "http"),
        ({"url": "http://x", "depth": 9}, "depth"),
        ({"url": "http://x", "rate_limit": 0}, "rate_limit"),
        ({"url": "http://x", "crawl_seconds": 5000}, "crawl_seconds"),
        ({"url": "http://x", "headers": {"X-Forwarded-For": "1.2.3.4"}}, "header not allowed"),
        ({"url": "http://x", "automatic_form_fill": True}, "Extra inputs"),
    ]:
        with pytest.raises(PolicyError, match=why):
            validate_args("katana", args)


def test_the_katana_command_line():
    spec = executor.BUILDERS["katana"]({"url": "http://demo-app:5000", "depth": 3, "rate_limit": 5, "crawl_seconds": 60,
                                         "headers": {"Cookie": "session=abc"}})
    argv = spec.argv
    assert argv[0] == "katana" and argv[argv.index("-u") + 1] == "http://demo-app:5000"
    for flag in ("-jc", "-duf", "-or", "-duc", "-j"):
        assert flag in argv
    assert "-aff" not in argv and "-automatic-form-fill" not in argv and "-ob" not in argv  # bodies are needed for -jc
    assert argv[argv.index("-fs") + 1] == "fqdn" and "log-?out" in argv[argv.index("-cos") + 1]
    assert argv[argv.index("-H") + 1] == "Cookie: session=abc" and argv[argv.index("-rl") + 1] == "5"
    assert argv[argv.index("-kf") + 1] == "all" and spec.parse == "jsonl" and spec.timeout == 120
    assert "-kf" not in executor.BUILDERS["katana"]({"url": "http://x", "depth": 2}).argv  # Katana needs depth 3


def test_crawled_urls_become_routes():
    routes = routes_from_crawl(katana_rows("demo-app:5000"), "http://demo-app:5000")
    assert [r.template for r in routes] == CRAWLED
    by = {r.path: r for r in routes}
    assert by["/api/fetch"].query_params == ("url",) and by["/api/users/search"].query_params == ("name",)
    assert by["/api/accounts/{id}"].params == ("id",)


def test_off_host_static_and_missing_urls_are_dropped():
    rows = [
        {"request": {"method": "GET", "endpoint": "http://demo-app:5000/orders/7/items/3"}, "response": {"status_code": 200}},
        {"request": {"method": "GET", "endpoint": "http://cdn.example.com/x"}, "response": {"status_code": 200}},
        {"request": {"method": "GET", "endpoint": "http://demo-app:5000/static/app.js"}, "response": {"status_code": 200}},
        {"request": {"method": "GET", "endpoint": "http://demo-app:5000/gone"}, "response": {"status_code": 404}},
        {"request": {"method": "GET", "endpoint": "https://demo-app:5000/tls"}, "response": {"status_code": 200}},  # port 5000, other scheme
        "not a row",
    ]
    assert [r.path for r in routes_from_crawl(rows, "http://demo-app:5000")] == ["/orders/{id}/items/{id2}", "/tls"]


# --------------------------------------------------------------------------------------------- #
# Playwright
# --------------------------------------------------------------------------------------------- #
def test_the_playwright_policy():
    base = {"login_url": "http://demo-app:5000/login-form", "identity": "A", "identities": str(BROWSER_IDENTITIES), "allow": ["demo-app:5000"]}
    assert validate_args("playwright", base)["verify_tls"] is True
    assert required_target("playwright", base) == "demo-app:5000"
    assert required_target("playwright", {**base, "login_url": "https://sso.example.com/login"}) == "sso.example.com:443"
    for change, why in [
        ({"login_url": "javascript:alert(1)"}, "http"),
        ({"identity": "C"}, "A or B"),
        ({"identities": str(ROOT / "missing.yml")}, "existing file"),
        ({"allow": []}, "allowlist"),
        ({"password": "x"}, "Extra inputs"),  # credentials are read from the file, never passed
    ]:
        with pytest.raises(PolicyError, match=why):
            validate_args("playwright", {**base, **change})


def test_the_playwright_command_line(monkeypatch):
    args = {"login_url": "https://demo-app:5443/login-form", "identity": "B", "identities": str(BROWSER_IDENTITIES),
            "allow": ["demo-app:5443", "callback:8080"], "verify_tls": False}
    argv = executor.BUILDERS["playwright"](args).argv
    assert argv[:3] == [sys.executable, "-m", "aegis.workers.runtime.browser_login"]
    assert argv[argv.index("--allow") + 1] == "demo-app:5443,callback:8080" and argv[-1] == "--insecure"
    assert "bob" not in " ".join(argv) and "bob-demo-pass" not in " ".join(argv)
    import importlib.util

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert executor.find_binary(executor.BUILDERS["playwright"](args).argv[0]) is None  # → "tool not installed"


def test_totp_matches_rfc_6238():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # the RFC's 20-byte SHA-1 seed
    assert [totp(secret, t, digits=8) for t in (59, 1111111109, 1234567890)] == ["94287082", "07081804", "89005924"]


def test_browser_identities(tmp_path):
    cfg = load_identities(str(BROWSER_IDENTITIES))
    assert (cfg.type, cfg.login_url, cfg.fields["totp"]) == ("browser", "/login-form", "#code")
    login, creds = browser_config(str(BROWSER_IDENTITIES), "B")
    assert login["success"] == {"cookie": "session"} and creds["totp_secret"]
    broken = tmp_path / "ids.yml"
    broken.write_text("login: {type: browser, url: /x, fields: {username: '#u'}}\nidentities: {A: {}, B: {}}\n", encoding="utf-8")
    with pytest.raises(RuntimeStageError, match="needs fields.username, fields.password and submit"):
        load_identities(str(broken))
    with pytest.raises(LoginFailed, match="no complete browser login"):
        browser_config(str(broken), "A")


# --------------------------------------------------------------------------------------------- #
# the runtime stage, in-process: no OpenAPI document, a browser login
# --------------------------------------------------------------------------------------------- #
def spec_less_run(store, tmp_path, monkeypatch, *, browser: bool, katana: bool = True):
    monkeypatch.setenv("DEMO_OPENAPI", "0")
    calls: list[ToolCall] = []
    world: dict = {}

    async def fake(call, args, inputs):
        calls.append(call)
        if call.tool == "katana" and katana:
            return ToolResult(ok=True, tool="katana", exit_code=0, output=katana_rows("demo-app:5000"))
        if call.tool == "playwright":  # stands in for the browser: logs the identity in for real
            creds = {"A": ("alice", "alice-demo-pass"), "B": ("bob", "bob-demo-pass")}[args["identity"]]
            async with httpx.AsyncClient(transport=world["transport"], base_url="http://demo-app:5000") as client:
                resp = await client.post("/login", json={"username": creds[0], "password": creds[1]})
            return ToolResult(ok=True, tool="playwright", exit_code=0, output={"cookies": dict(resp.cookies.items()), "headers": {}})
        return ToolResult(ok=False, tool=call.tool, blocked_reason=f"tool not installed: {call.tool}")

    identities = str(BROWSER_IDENTITIES) if browser else None
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fake, identities=identities)
    world["transport"] = config["configurable"]["deps"].http_transport
    return scan_id, state, config, calls


async def test_without_openapi_the_crawl_finds_the_routes_and_the_bugs(store, tmp_path, monkeypatch):
    scan_id, state, config, calls = spec_less_run(store, tmp_path, monkeypatch, browser=False)
    steps = ["validate_target", "discover_routes", "authenticate", "crawl", "build_request_model", "check_bola", "check_ssrf"]
    out = await run_steps("runtime", steps, state, config)
    assert out.get("errors", []) == [], out
    (katana,) = [c for c in calls if c.tool == "katana"]
    assert katana.target_host == "demo-app:5000" and katana.args["headers"]["Cookie"].startswith("session=")  # crawled logged in
    found = {(f.type, f.route, getattr(f.state, "value", f.state)) for f in store.list_findings(scan_id)}
    assert ("broken_access_control", "GET /api/accounts/{id}", "confirmed") in found
    assert ("ssrf", "GET /api/fetch", "confirmed") in found
    (ev,) = [e for e in store.list_evidence(scan_id, kind="http_exchange") if e.tool == "katana"]
    assert json.loads(ev.payload_json)["routes"] == CRAWLED


async def test_with_openapi_there_is_no_crawl(store, tmp_path):
    calls = []

    async def fake(call, args, inputs):
        calls.append(call)
        return ToolResult(ok=False, tool=call.tool, blocked_reason=f"tool not installed: {call.tool}")

    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fake)
    out = await run_steps("runtime", ["validate_target", "discover_routes", "authenticate", "crawl"], state, config)
    assert out.get("errors", []) == [] and not [c for c in calls if c.tool == "katana"]


async def test_without_openapi_or_katana_the_stage_has_no_routes_but_goes_on(store, tmp_path, monkeypatch):
    scan_id, state, config, calls = spec_less_run(store, tmp_path, monkeypatch, browser=False, katana=False)
    out = await run_steps("runtime", ["validate_target", "discover_routes", "authenticate", "crawl", "build_request_model", "check_bola"], state, config)
    assert out.get("errors", []) == [] and store.list_findings(scan_id) == []


async def test_a_browser_login_provides_both_sessions(store, tmp_path, monkeypatch):
    scan_id, state, config, calls = spec_less_run(store, tmp_path, monkeypatch, browser=True)
    steps = ["validate_target", "discover_routes", "authenticate", "crawl", "build_request_model", "check_bola"]
    out = await run_steps("runtime", steps, state, config)
    assert out.get("errors", []) == [], out
    logins = [c for c in calls if c.tool == "playwright"]
    assert [c.args["identity"] for c in logins] == ["A", "B"]
    assert all(c.target_host == "demo-app:5000" and c.args["login_url"] == "http://demo-app:5000/login-form" for c in logins)
    assert "demo-app:5000" in logins[0].args["allow"] and "password" not in json.dumps(logins[0].args)
    assert any(f.type == "broken_access_control" for f in store.list_findings(scan_id))
    audited = [r for r in store.list_tool_calls(scan_id) if r.tool == "playwright"]
    assert len(audited) == 2 and all(r.blocked_reason is None for r in audited)


async def test_a_browser_login_without_playwright_stops_the_stage_with_a_reason(store, tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_OPENAPI", "0")
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, identities=str(BROWSER_IDENTITIES))  # no tools at all
    out = await run_steps("runtime", ["validate_target", "discover_routes", "authenticate", "crawl"], state, config)
    assert out["aborted"] and any("Playwright is not installed" in e for e in out["errors"])


# --------------------------------------------------------------------------------------------- #
# real Katana + real Playwright (opt-in: -m tools)
# --------------------------------------------------------------------------------------------- #
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.tools
@pytest.mark.parametrize("login", ["http", "browser"])
async def test_real_crawl_and_browser_login_on_a_spec_less_demo(store, tmp_path, monkeypatch, login):
    import importlib.util

    monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [str(ROOT / ".tools" / "katana"), os.environ.get("AEGIS_TOOL_DIRS")])))
    if executor.find_binary("katana") is None:
        pytest.skip("katana is not installed (see TOOL_NOT_WORKING.md TNW-4)")
    if login == "browser" and importlib.util.find_spec("playwright") is None:
        pytest.skip("playwright is not installed")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--factory", "app.main:create_app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT / "demo-app", env={**os.environ, "DEMO_OPENAPI": "0"},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:  # noqa: BLE001 - still starting
                time.sleep(0.25)
        url, target = f"http://127.0.0.1:{port}", f"127.0.0.1:{port}"
        identities = str(BROWSER_IDENTITIES if login == "browser" else ROOT / "demo-app" / "identities.yml")
        scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=executor.execute_tool, http_transport=None,
                                          default_allowlist=(target,), identities=identities, rate_limit_rps=50.0)
        store.update_scan(scan_id, target_url=url)
        steps = ["validate_target", "discover_routes", "authenticate", "crawl", "build_request_model", "check_bola"]
        out = await run_steps("runtime", steps, state, config)
        assert out.get("errors", []) == [], out
        bola = [f for f in store.list_findings(scan_id) if f.type == "broken_access_control"]
        assert bola and getattr(bola[0].state, "value", bola[0].state) == "confirmed"
        calls = {c.tool: c for c in store.list_tool_calls(scan_id)}
        assert calls["katana"].exit_code == 0
        if login == "browser":
            assert len([c for c in store.list_tool_calls(scan_id) if c.tool == "playwright" and c.exit_code == 0]) == 2
    finally:
        proc.terminate()
