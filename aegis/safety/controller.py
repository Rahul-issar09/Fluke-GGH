"""SafetyController (PHASES P2.6) — the one entry point for every tool call.

Order of enforcement:
  allowlist → arg policy → test-input resolve → rate limit → execute → audit

The agent can only *request* a tool call as a ``ToolCall``; it never supplies a
host, a raw payload, or a shell command. Execution is delegated to a registered
per-tool ``executor`` (the worker wrappers, built in P6/P7/P8); the controller
never builds argv itself. Any check failure returns a blocked
``ToolResult(ok=False, ...)`` — it never raises into the graph — and every call
is audited.

Audit persistence to the ``ToolCallLog`` table is wired in AG04 via the
``audit_sink`` callback; until then the audit entry is logged.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable

from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.models import ToolCall, ToolResult
from aegis.safety.policies import PolicyError, required_target, validate_args
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary, UnknownTestInput

__all__ = ["SafetyController", "Executor"]

log = get_logger("safety")

# executor(call, validated_args, resolved_inputs) -> ToolResult
Executor = Callable[[ToolCall, dict, list[str]], Awaitable[ToolResult]]


def _args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]


async def _no_executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
    return ToolResult(ok=False, tool=call.tool, blocked_reason="no executor registered")


class SafetyController:
    def __init__(
        self,
        allowlist: Allowlist,
        test_inputs: TestInputLibrary,
        rate_limiter: RateLimiter | None = None,
        *,
        executor: Executor | None = None,
        audit_sink: Callable[[dict], None] | None = None,
    ):
        self._allow = allowlist
        self._inputs = test_inputs
        self._rl = rate_limiter or RateLimiter()
        self._executor = executor or _no_executor
        self._audit = audit_sink

    def _record(
        self, call: ToolCall, args: dict, duration_ms: int, exit_code, blocked_reason
    ) -> None:
        entry = {
            "scan_id": call.scan_id,
            "tool": call.tool,
            "target_host": call.target_host,
            "args_hash": _args_hash(args),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "blocked_reason": blocked_reason,
        }
        if blocked_reason:
            log.warning("safety.blocked", **entry)
        else:
            log.info("safety.executed", **entry)
        if self._audit is not None:
            self._audit(entry)

    def _blocked(self, call: ToolCall, args: dict, reason: str) -> ToolResult:
        self._record(call, args, duration_ms=0, exit_code=None, blocked_reason=reason)
        return ToolResult(ok=False, tool=call.tool, blocked_reason=reason)

    async def run(self, call: ToolCall) -> ToolResult:
        # 1. allowlist (only when the call targets a host)
        if call.target_host is not None and not self._allow.check(call.target_host):
            return self._blocked(call, call.args, f"host not allowlisted: {call.target_host}")

        # 2. argument policy
        try:
            validated = validate_args(call.tool, call.args)
        except PolicyError as exc:
            return self._blocked(call, call.args, f"policy: {exc}")
        # a call whose args name a host (a git clone's repo) must declare that host as its target,
        # so the allowlist above checked the host that is actually contacted
        needed = required_target(call.tool, validated)
        if needed is not None and (call.target_host or "").lower() != needed:
            return self._blocked(call, validated, f"policy: target_host must be {needed} for this call")

        # 3. resolve approved test inputs (by ID only)
        resolved: list[str] = []
        for input_id in call.test_input_ids:
            try:
                resolved.append(self._inputs.resolve(input_id, call.scan_id))
            except UnknownTestInput:
                return self._blocked(call, validated, f"unknown test input: {input_id}")

        # 4. rate limit (per host, or per tool when hostless)
        await self._rl.acquire(call.target_host or call.tool)

        # 5. execute
        result = await self._executor(call, validated, resolved)

        # 6. audit
        self._record(
            call,
            validated,
            duration_ms=result.duration_ms,
            exit_code=result.exit_code,
            blocked_reason=result.blocked_reason,
        )
        return result
