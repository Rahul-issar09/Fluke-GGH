"""AG03 — safety layer: allowlist, policies, test inputs, rate limiter,
egress guard, ToolRunner, heavy-stage semaphore, SafetyController."""

from __future__ import annotations

import asyncio
import sys

import httpx
import pytest

from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.egress import EgressBlocked, make_client
from aegis.safety.policies import PolicyError, validate_args
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary, UnknownTestInput
from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.base import heavy_stage, run_tool

pytestmark = pytest.mark.phase("AG03")


# --- P2.1 allowlist -------------------------------------------------------- #
def test_allowlist_allows_exact_hostport():
    al = Allowlist(["demo-app:5000", "callback:8080"])
    assert al.check("demo-app:5000") is True
    assert al.check("callback:8080") is True


def test_allowlist_blocks_port_mismatch_and_unknown():
    al = Allowlist(["demo-app:5000"])
    assert al.check("demo-app:5001") is False  # port mismatch
    assert al.check("evil.com") is False
    assert al.check("127.0.0.1:5000") is False  # IP != hostname
    assert al.check(None) is False


def test_allowlist_bare_host_matches_any_port():
    al = Allowlist(["demo-app"])
    assert al.check("demo-app:9999") is True
    assert al.check("demo-app") is True


# --- P2.2 policies --------------------------------------------------------- #
def test_policy_accepts_known_args():
    out = validate_args("semgrep", {"path": "/scan", "config": "rules/semgrep"})
    assert out["path"] == "/scan"


def test_policy_rejects_unknown_arg():
    with pytest.raises(PolicyError):
        validate_args("semgrep", {"path": "/scan", "evil": "x"})


def test_policy_rejects_wrong_type():
    with pytest.raises(PolicyError):
        validate_args("semgrep", {"path": 123})


def test_policy_unknown_tool():
    with pytest.raises(PolicyError):
        validate_args("nope", {})


# --- P2.3 test inputs ------------------------------------------------------ #
def test_test_input_resolve_and_substitute():
    lib = TestInputLibrary.load()
    val = lib.resolve("SSRF-CB-001", "S-0001")
    assert "S-0001" in val and "{scan_id}" not in val


def test_test_input_unknown_rejected():
    lib = TestInputLibrary.load()
    with pytest.raises(UnknownTestInput):
        lib.resolve("NOT-A-REAL-ID", "S-0001")


# --- P2.4 rate limiter ----------------------------------------------------- #
async def test_rate_limiter_burst_then_throttle():
    clock = {"t": 0.0}
    slept: list[float] = []

    def time_fn():
        return clock["t"]

    async def sleep_fn(d):
        slept.append(d)
        clock["t"] += d

    rl = RateLimiter(rps=5, burst=10, time_fn=time_fn, sleep_fn=sleep_fn)
    for _ in range(30):
        await rl.acquire("demo-app:5000")
    # 10 free (burst), then 20 throttled at 0.2s each ≈ 4.0s total
    assert len(slept) == 20
    assert abs(sum(slept) - 4.0) < 1e-6


# --- P2.5 egress guard ----------------------------------------------------- #
async def test_egress_allows_allowlisted_host():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    al = Allowlist(["demo-app:5000"])
    async with make_client(al, inner=httpx.MockTransport(handler)) as client:
        resp = await client.get("http://demo-app:5000/health")
        assert resp.status_code == 200


async def test_egress_blocks_non_allowlisted_host():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200)

    al = Allowlist(["demo-app:5000"])
    async with make_client(al, inner=httpx.MockTransport(handler)) as client:
        with pytest.raises(EgressBlocked):
            await client.get("http://evil.com/")


# --- P4.1 ToolRunner ------------------------------------------------------- #
async def test_tool_runner_parses_json():
    argv = [sys.executable, "-c", "import json;print(json.dumps({'a':1}))"]
    res = await run_tool("semgrep", argv, parse="json", timeout=10)
    assert res.ok and res.output == {"a": 1} and res.exit_code == 0


async def test_tool_runner_parses_jsonl():
    argv = [sys.executable, "-c", "print('{\"a\":1}');print('{\"b\":2}')"]
    res = await run_tool("gitleaks", argv, parse="jsonl", timeout=10)
    assert res.ok and res.output == [{"a": 1}, {"b": 2}]


async def test_tool_runner_timeout_kills():
    argv = [sys.executable, "-c", "import time;time.sleep(5)"]
    res = await run_tool("slow", argv, parse="text", timeout=0.5)
    assert res.ok is False and res.stderr_tail == "timeout"


async def test_tool_runner_nonzero_exit_not_ok():
    argv = [sys.executable, "-c", "import sys;sys.exit(3)"]
    res = await run_tool("x", argv, parse="text", timeout=10)
    assert res.ok is False and res.exit_code == 3


# --- P4.2 heavy-stage semaphore -------------------------------------------- #
async def test_heavy_stage_serializes():
    order: list[str] = []

    async def worker(name: str):
        async with heavy_stage(name):
            order.append(f"{name}-in")
            await asyncio.sleep(0.01)
            order.append(f"{name}-out")

    await asyncio.gather(worker("a"), worker("b"))
    # one must fully finish before the other enters
    assert order in (
        ["a-in", "a-out", "b-in", "b-out"],
        ["b-in", "b-out", "a-in", "a-out"],
    )


# --- P2.6 SafetyController ------------------------------------------------- #
def _controller(executor, audit=None):
    return SafetyController(
        Allowlist(["demo-app:5000", "callback:8080"]),
        TestInputLibrary.load(),
        RateLimiter(rps=1000, burst=1000),
        executor=executor,
        audit_sink=audit,
    )


async def test_controller_blocks_offscope_host_before_executing():
    calls: list = []

    async def exe(call, args, inputs):
        calls.append(call)
        return ToolResult(ok=True, tool=call.tool)

    ctrl = _controller(exe)
    res = await ctrl.run(ToolCall(tool="httpx", scan_id="S-1", target_host="evil.com", args={"url": "http://evil.com"}))
    assert res.ok is False and "not allowlisted" in res.blocked_reason
    assert calls == []  # executor never reached


async def test_controller_blocks_bad_policy():
    async def exe(call, args, inputs):  # pragma: no cover
        return ToolResult(ok=True, tool=call.tool)

    ctrl = _controller(exe)
    res = await ctrl.run(ToolCall(tool="semgrep", scan_id="S-1", args={"evil": 1}))
    assert res.ok is False and res.blocked_reason.startswith("policy:")


async def test_controller_blocks_unknown_test_input():
    async def exe(call, args, inputs):  # pragma: no cover
        return ToolResult(ok=True, tool=call.tool)

    ctrl = _controller(exe)
    res = await ctrl.run(
        ToolCall(tool="ssrf", scan_id="S-1", target_host="demo-app:5000",
                 args={"param": "url", "test_input_id": "SSRF-CB-001"},
                 test_input_ids=["NOPE"])
    )
    assert res.ok is False and "unknown test input" in res.blocked_reason


async def test_controller_executes_and_audits_allowed_call():
    audited: list[dict] = []
    seen: dict = {}

    async def exe(call, args, inputs):
        seen["args"] = args
        seen["inputs"] = inputs
        return ToolResult(ok=True, tool=call.tool, exit_code=0, duration_ms=5)

    ctrl = _controller(exe, audit=audited.append)
    res = await ctrl.run(
        ToolCall(tool="ssrf", scan_id="S-7", target_host="demo-app:5000",
                 args={"param": "url", "test_input_id": "SSRF-CB-001"},
                 test_input_ids=["SSRF-CB-001"])
    )
    assert res.ok is True
    assert seen["inputs"] == ["http://callback:8080/hit/S-7"]  # resolved by ID
    assert len(audited) == 1 and audited[0]["scan_id"] == "S-7"
    assert audited[0]["blocked_reason"] is None


async def test_controller_default_executor_fails_closed():
    ctrl = SafetyController(Allowlist(["demo-app:5000"]), TestInputLibrary.load(), RateLimiter(rps=1000, burst=1000))
    res = await ctrl.run(ToolCall(tool="semgrep", scan_id="S-1", args={"path": "/scan"}))
    assert res.ok is False and "no executor" in res.blocked_reason
