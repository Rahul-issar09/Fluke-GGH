"""Runtime step — Schemathesis API conformance checks (PHASES P6.8).

Read-only (``GET``) operations only; Schemathesis generates its own inputs, so
it is never allowed to send mutating requests. Optionally runs as an
authenticated identity: the credential header is handed to the tool through the
argument policy (cookie/authorization only), which keeps it out of logs (only an
args hash is audited) and out of stored evidence (the adapter drops the repro
block).
"""

from __future__ import annotations

from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.runtime.context import Session, auth_headers, target_host


async def run_schemathesis(
    controller: SafetyController,
    scan_id: str,
    base_url: str,
    openapi_url: str,
    session: Session | None = None,
    *,
    tls_verify: bool = True,
) -> ToolResult:
    args: dict = {"openapi": openapi_url, "url": base_url}
    if not tls_verify:
        args["tls_verify"] = False
    headers = auth_headers(session)
    if headers:
        args["headers"] = headers
    return await controller.run(
        ToolCall(tool="schemathesis", scan_id=scan_id, target_host=target_host(base_url), args=args)
    )
