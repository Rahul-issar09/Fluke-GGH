"""AG06.2 — real scanner binaries (opt-in: ``pytest -m tools``).

Runs the real ``schemathesis`` CLI through SafetyController + the production
executor against a live demo server on loopback, then feeds its real JUnit
report to the adapter. This is what proves the command line, exit-code handling,
report parsing and determinism against the actual tool — the unit tests use a
recorded report.

Nuclei is not covered here: it is a Go binary with no pip install, so its
command line and adapter are tested against documented flags and a sample of
its documented JSONL format only (see ``executor.py``).
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.request

import httpx
import pytest

from aegis.evidence.adapters.schemathesis import SchemathesisAdapter
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.executor import execute_tool, find_binary
from aegis.workers.runtime.context import Session
from aegis.workers.runtime.schemathesis import run_schemathesis
from fakes.demo_apps import ROOT

pytestmark = [pytest.mark.phase("AG06"), pytest.mark.tools, pytest.mark.slow]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_demo():
    pytest.importorskip("uvicorn")
    if find_binary("schemathesis") is None:
        pytest.skip("schemathesis is not installed")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", str(ROOT / "demo-app"),
         "--port", str(port), "--log-level", "warning"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            pytest.fail("demo server did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _controller(base: str) -> SafetyController:
    host = base.split("//", 1)[1]
    return SafetyController(
        Allowlist([host]), TestInputLibrary.load(), RateLimiter(1000, 1000), executor=execute_tool
    )


async def _login(base: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{base}/login", json={"username": "alice", "password": "alice-demo-pass"})
        return resp.cookies["session"]


async def test_real_schemathesis_runs_read_only_and_is_deterministic(live_demo):
    base = live_demo
    token = await _login(base)
    controller = _controller(base)
    session = Session(cookies={"session": token})

    runs = []
    for _ in range(2):
        res = await run_schemathesis(controller, "S-0001", base, f"{base}/openapi.json", session)
        assert res.ok, f"schemathesis failed: {res.stderr_tail or res.blocked_reason}"
        assert res.exit_code in (0, 1) and "junit_xml" in res.output
        drafts = SchemathesisAdapter().parse(res.output, "S-0001")
        runs.append(sorted((d.route, d.title, e[0].payload["status"]) for d, e in drafts))

    assert runs[0] == runs[1]  # same seed + deterministic generation -> same findings (NFR-3)
    assert any(route == "GET /api/accounts/{id}" for route, _, _ in runs[0])
    assert token not in repr(runs)  # the session never reaches the findings


async def test_real_schemathesis_unauthenticated_sees_the_auth_wall(live_demo):
    base = live_demo
    res = await run_schemathesis(_controller(base), "S-0001", base, f"{base}/openapi.json", None)
    assert res.ok
    routes = {d.route for d, _ in SchemathesisAdapter().parse(res.output, "S-0001")}
    assert {"GET /api/accounts", "GET /api/accounts/{id}"} <= routes  # undocumented 401s


async def test_real_schemathesis_blocked_off_allowlist(live_demo):
    base = live_demo
    controller = SafetyController(
        Allowlist(["not-the-target:1"]), TestInputLibrary.load(), RateLimiter(1000, 1000), executor=execute_tool
    )
    res = await run_schemathesis(controller, "S-0001", base, f"{base}/openapi.json", None)
    assert res.ok is False and "not allowlisted" in res.blocked_reason
