"""A per-provider request budget (LLM_PROVIDER_PHASES §7.5).

A token bucket shared by every scan and question in this process, so one scan cannot drain a
free-tier per-minute quota on its own. ``acquire`` waits for a token instead of failing. The clock
and sleep are injectable so tests run instantly.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

__all__ = ["TokenBucket"]


class TokenBucket:
    def __init__(self, per_minute: float, *, burst: int | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        if per_minute <= 0:
            raise ValueError("per_minute must be positive")
        self.rate = per_minute / 60.0                 # tokens per second
        self.capacity = float(burst if burst is not None else max(1, int(per_minute // 6) or 1))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    async def acquire(self) -> float:
        """Take one token, waiting if needed; returns how long it waited (seconds)."""
        waited = 0.0
        async with self._lock:
            self._refill()
            while self._tokens < 1.0:
                delay = (1.0 - self._tokens) / self.rate
                await self._sleep(delay)
                waited += delay
                self._refill()
            self._tokens -= 1.0
        return waited
