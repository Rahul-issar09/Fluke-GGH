"""Per-host async token-bucket rate limiter (PHASES P2.4).

Default 5 rps, burst 10. ``acquire(host)`` returns immediately while tokens are
available and otherwise waits. Time and sleep are injectable so tests are
deterministic (no real clock dependence).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from aegis.observability import get_logger

__all__ = ["RateLimiter"]

log = get_logger("safety.rate_limiter")


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens: float, last: float):
        self.tokens = tokens
        self.last = last


class RateLimiter:
    def __init__(
        self,
        rps: float = 5.0,
        burst: int = 10,
        *,
        time_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.rps = float(rps)
        self.burst = float(burst)
        self._time = time_fn
        self._sleep = sleep_fn
        self._buckets: dict[str, _Bucket] = {}

    async def acquire(self, host: str) -> None:
        now = self._time()
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(tokens=self.burst, last=now)
            self._buckets[host] = bucket

        # refill
        elapsed = now - bucket.last
        bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rps)
        bucket.last = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return

        wait = (1.0 - bucket.tokens) / self.rps
        log.warning("rate_limiter.wait", host=host, seconds=round(wait, 3))
        await self._sleep(wait)
        bucket.tokens = 0.0
        bucket.last = self._time()
