"""Small in-process sliding-window rate limiter.

The application is a single-process local-first server, so a process-local
limiter is sufficient and avoids another service to operate.  If VulnScanner
is later run behind multiple Uvicorn workers, move the buckets to SQLite or a
shared cache.
"""

from __future__ import annotations

import ipaddress
import os
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
basic_auth_limiter = SlidingWindowLimiter()


def _trust_proxy_enabled() -> bool:
    return os.getenv("VS_TRUST_PROXY", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _trusted_proxy_hops() -> int:
    try:
        hops = int(os.getenv("VS_TRUSTED_PROXY_HOPS", "1"))
    except (TypeError, ValueError):
        hops = 1
    return max(1, min(hops, 50))


def _parse_forwarded_address(value: str) -> str:
    """Return a canonical IP from one X-Forwarded-For element."""
    candidate = value.strip()
    if candidate.startswith("["):
        # Bracketed IPv6, optionally followed by :port.
        closing = candidate.find("]")
        if closing > 1:
            candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        # IPv4 with an optional :port suffix.
        host, _, port = candidate.partition(":")
        if port.isdigit():
            candidate = host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def client_ip(request) -> str:
    """Return the peer address, honouring a trusted reverse proxy header.

    ``VS_TRUST_PROXY`` must be enabled explicitly. ``X-Forwarded-For`` is
    ordered client-first, so the leftmost value is attacker-controlled. The
    rightmost ``VS_TRUSTED_PROXY_HOPS`` entries were appended by proxies we
    trust; use the address immediately before those proxies.
    """
    peer = getattr(getattr(request, "client", None), "host", "") or "unknown"
    if not _trust_proxy_enabled():
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer
    parts = [part for part in (piece.strip() for piece in forwarded.split(",")) if part]
    if not parts:
        return peer
    hops = _trusted_proxy_hops()
    index = max(0, len(parts) - hops)
    address = _parse_forwarded_address(parts[index])
    return address or peer


def reset_rate_limits() -> None:
    """Reset all buckets (used by tests and after a successful login)."""
    login_limiter.reset()
    sensitive_limiter.reset()
    basic_auth_limiter.reset()
