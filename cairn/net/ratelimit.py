from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any


class TokenBucket:
    """Async token bucket with an initial burst allowance."""

    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = max(0.01, rate)
        self.capacity = max(1.0, capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                await asyncio.sleep((tokens - self._tokens) / self.rate)


class HostRateLimiter:
    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = rate
        self.capacity = capacity
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rate, self.capacity)
                self._buckets[host] = bucket
        await bucket.acquire()


class ConcurrencyGate:
    def __init__(self, limit: int):
        self.limit = max(1, limit)
        self._sem = asyncio.Semaphore(self.limit)

    @asynccontextmanager
    async def slot(self):
        async with self._sem:
            yield

    @property
    def active(self) -> int:
        return self.limit - self._sem._value  # best-effort diagnostic only


class CancellationToken:
    def __init__(self):
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self, timeout: float | None = None) -> bool:
        try:
            await asyncio.wait_for(self._event.wait(), timeout)
            return True
        except TimeoutError:
            return False


class StatsCounter:
    def __init__(self):
        self.values: dict[str, int] = defaultdict(int)
        self.timings: dict[str, list[float]] = defaultdict(list)

    def incr(self, key: str, amount: int = 1) -> None:
        self.values[key] += amount

    def time(self, key: str, seconds: float) -> None:
        self.timings[key].append(seconds)

    def to_dict(self) -> dict[str, Any]:
        timing_summary = {
            key: {
                "count": len(values),
                "total_ms": round(sum(values) * 1000, 1),
                "avg_ms": round((sum(values) / len(values)) * 1000, 1) if values else 0,
            }
            for key, values in self.timings.items()
        }
        return {"counters": dict(self.values), "timings": timing_summary}
