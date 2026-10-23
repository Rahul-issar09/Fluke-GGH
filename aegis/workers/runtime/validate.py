"""Runtime step 1 — validate the target (PHASES P6.1).

The target must be reachable and its host must be on the scan's allowlist
(enforced by the egress guard). Any HTTP response — even 404 — proves the host
is up; transport failures and blocked hosts abort the runtime stage.
"""

from __future__ import annotations

import httpx

from aegis.observability import get_logger
from aegis.safety.egress import EgressBlocked
from aegis.workers.runtime.context import RuntimeStageError

log = get_logger("workers.runtime.validate")


async def validate_target(client: httpx.AsyncClient, base_url: str) -> dict:
    try:
        resp = await client.get(base_url)
    except EgressBlocked as exc:
        log.warning("validate.blocked", target=str(exc))
        raise RuntimeStageError(f"target host is not on the allowlist: {exc}") from exc
    except httpx.HTTPError as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            log.warning("validate.certificate_untrusted", error=str(exc)[:200])
            raise RuntimeStageError(
                "the target's TLS certificate is not trusted (self-signed, expired or for another host); "
                "for a test target, start the scan with options.verify_tls=false"
            ) from exc
        log.warning("validate.unreachable", error=type(exc).__name__)
        raise RuntimeStageError(f"target unreachable ({type(exc).__name__})") from exc
    info = {"reachable": True, "status": resp.status_code, "server": resp.headers.get("server")}
    log.info("validate.ok", status=resp.status_code)
    return info
