import asyncio
import time


class TokenBucket:
    """Async token-bucket rate limiter.

    Enforces a sustained rate (tokens/sec) with a burst allowance. Every probe
    acquires one token before it goes out on the wire; when the bucket is empty
    callers sleep just long enough for the next token to refill. This is what
    keeps a wide scan from saturating the link or tripping IDS thresholds — the
    `rate_limit` knob in the config is meaningless without it.
    """

    def __init__(self, rate: float, burst: int | None = None):
        self.rate = max(rate, 1.0)
        self.capacity = burst if burst is not None else max(int(rate), 1)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._updated = now

    async def acquire(self, tokens: int = 1) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            await asyncio.sleep(wait)


class AdaptiveRateLimiter(TokenBucket):
    """Token bucket that backs off when the target starts dropping connections.

    A sustained run of timeouts/refusals is a signal we're scanning too hard;
    we halve the effective rate and recover it slowly as probes succeed again.
    """

    def __init__(self, rate: float, burst: int | None = None, floor: float = 50.0):
        super().__init__(rate, burst)
        self._base_rate = self.rate
        self._floor = floor
        self._recent_failures = 0
        self._recent_total = 0

    def record(self, success: bool) -> None:
        self._recent_total += 1
        if not success:
            self._recent_failures += 1

        if self._recent_total >= 50:
            failure_ratio = self._recent_failures / self._recent_total
            if failure_ratio > 0.5:
                self.rate = max(self._floor, self.rate * 0.5)
            elif failure_ratio < 0.1:
                self.rate = min(self._base_rate, self.rate * 1.25)
            self._recent_failures = 0
            self._recent_total = 0
