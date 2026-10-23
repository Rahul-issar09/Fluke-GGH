"""Runtime step — Nuclei known-issue / misconfiguration checks (PHASES P6.8).

Builds a ``ToolCall`` and sends it through ``SafetyController`` (allowlist,
argument policy, rate limit, audit); the executor owns the command line. The
templates are the pinned, pre-staged snapshot — nothing is fetched at run time.
"""

from __future__ import annotations

from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.runtime.context import target_host


async def run_nuclei(
    controller: SafetyController, scan_id: str, base_url: str, templates_dir: str, *, rate_limit: float = 5
) -> ToolResult:
    return await controller.run(
        ToolCall(
            tool="nuclei",
            scan_id=scan_id,
            target_host=target_host(base_url),
            args={"url": base_url, "templates": templates_dir, "rate_limit": max(1, min(100, int(rate_limit)))},
        )
    )
