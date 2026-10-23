"""Egress guard (PHASES P2.5).

All Python HTTP goes through an httpx transport that blocks any host not on the
scan's allowlist and applies the rate limiter. This is the only place target
HTTP clients are built (STRUCTURE boundary B-3).
"""

from __future__ import annotations

import httpx

from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.rate_limiter import RateLimiter

__all__ = ["EgressBlocked", "EgressGuardTransport", "make_client"]

log = get_logger("safety.egress")


class EgressBlocked(Exception):
    """A request targeted a non-allowlisted host and was blocked."""


_DEFAULT_PORTS = {"https": 443, "http": 80}


def _target(request: httpx.Request) -> str:
    # httpx leaves the port empty for a scheme's default port, but the allowlist names
    # host:port ("example.com:443"), so the default is filled in (TNW-2: links without a port)
    host = request.url.host
    port = request.url.port or _DEFAULT_PORTS.get(request.url.scheme)
    return f"{host}:{port}" if port else host


class EgressGuardTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        allowlist: Allowlist,
        rate_limiter: RateLimiter | None = None,
        inner: httpx.AsyncBaseTransport | None = None,
        *,
        verify: bool = True,
    ):
        self._allow = allowlist
        self._rl = rate_limiter
        self._inner = inner or httpx.AsyncHTTPTransport(verify=verify)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = _target(request)
        if not self._allow.check(target):
            log.warning("egress.blocked", target=target)
            raise EgressBlocked(target)
        if self._rl is not None:
            await self._rl.acquire(target)
        return await self._inner.handle_async_request(request)


def make_client(
    allowlist: Allowlist,
    *,
    rate_limiter: RateLimiter | None = None,
    inner: httpx.AsyncBaseTransport | None = None,
    verify: bool = True,
    **kwargs,
) -> httpx.AsyncClient:
    """Build an ``AsyncClient`` whose egress is allowlist-guarded.

    ``verify=False`` accepts the target's certificate as it is (a scan option, ``verify_tls``, for
    test targets with a self-signed certificate); the TLS check reports the certificate either way."""
    transport = EgressGuardTransport(allowlist, rate_limiter, inner, verify=verify)
    return httpx.AsyncClient(transport=transport, **kwargs)
