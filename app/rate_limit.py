"""Small in-process sliding-window rate limiter.

The application is a single-process local-first server, so a process-local
limiter is sufficient and avoids another service to operate.  If VulnScanner
is later run behind multiple Uvicorn workers, move the buckets to SQLite or a
shared cache.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}

    def retry_after(self, key: str, limit: int, window_seconds: int) -> int:
        """Return 0 when allowed, otherwise seconds until the next slot."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) < limit:
                return 0
            return max(1, int(window_seconds - (now - bucket[0])) + 1)

    def hit(self, key: str, limit: int, window_seconds: int) -> int:
        """Record an attempt and return 0 when allowed or retry seconds."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, int(window_seconds - (now - bucket[0])) + 1)
            bucket.append(now)
            return 0

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)

    def prune(self, window_seconds: int = 3600) -> None:
        cutoff = time.monotonic() - window_seconds
        with self._lock:
            for key in list(self._events):
                bucket = self._events[key]
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if not bucket:
                    self._events.pop(key, None)


login_limiter = SlidingWindowLimiter()
sensitive_limiter = SlidingWindowLimiter()


def client_ip(request) -> str:
    """Return the peer address, honouring a trusted reverse proxy header.

    ``VS_TRUST_PROXY`` must be enabled explicitly.  Blindly trusting
    ``X-Forwarded-For`` lets a client rotate the rate-limit key.
    """
    import os

    if os.getenv("VS_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes", "on"}:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()[:64]
    client = getattr(request, "client", None)
    return getattr(client, "host", "") or "unknown"


def reset_rate_limits() -> None:
    """Reset all buckets (used by tests and after a successful login)."""
    login_limiter.reset()
    sensitive_limiter.reset()
