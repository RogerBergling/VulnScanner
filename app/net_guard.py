"""Outbound URL validation and SSRF-resistant fetching.

Administrators can configure a webhook URL and the SecLists download URL from
the GUI.  Without validation those fields are a server-side request forgery
primitive: an attacker who obtains an administrator session could make the
server call cloud metadata endpoints or internal services.

By default only public HTTP(S) destinations are allowed.  A deployment that
intentionally sends notifications to an internal service can enable
``allow_private_outbound`` in Settings; the scheme, credentials and redirect
checks still apply.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 3
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024


class UnsafeURLError(ValueError):
    """Raised when an outbound URL is not allowed by policy."""


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    content: bytes
    content_type: str


def _blocked_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def validate_outbound_url(
    url: str,
    *,
    allow_private: bool = False,
    resolve: bool = True,
    purpose: str = "URL",
) -> str:
    """Validate an outbound HTTP(S) URL and return it stripped.

    ``resolve=False`` performs syntax and literal-IP checks only.  Use it when
    saving a setting that may legitimately be configured before DNS is
    available; downloads and deliveries always resolve.
    """
    value = str(url or "").strip()
    if not value:
        raise UnsafeURLError(f"{purpose} is required")
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeURLError(f"{purpose} must use http:// or https://")
    if parsed.username or parsed.password:
        raise UnsafeURLError(f"{purpose} must not contain embedded credentials")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError(f"{purpose} has no hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURLError(f"{purpose} has an invalid port") from exc
    if port is not None and not 1 <= port <= 65_535:
        raise UnsafeURLError(f"{purpose} has an invalid port")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if _blocked_ip(str(literal)) and not allow_private:
            raise UnsafeURLError(
                f"{purpose} points to a private, loopback or reserved address"
            )
        return value

    if resolve:
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(
                    hostname, port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError as exc:
            raise UnsafeURLError(f"Could not resolve {purpose} host {hostname}: {exc}") from exc
        if not addresses:
            raise UnsafeURLError(f"Could not resolve {purpose} host {hostname}")
        if not allow_private:
            blocked = sorted(address for address in addresses if _blocked_ip(address))
            if blocked:
                raise UnsafeURLError(
                    f"{purpose} resolves to a private, loopback or reserved address "
                    f"({blocked[0]})"
                )
    return value


def safe_get(
    url: str,
    *,
    allow_private: bool = False,
    timeout: float = 30.0,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    headers: dict[str, str] | None = None,
) -> FetchResult:
    """Fetch a URL with SSRF validation on every redirect hop."""
    current = validate_outbound_url(
        url, allow_private=allow_private, resolve=True, purpose="Download URL"
    )
    for _ in range(MAX_REDIRECTS + 1):
        response = requests.get(
            current,
            timeout=timeout,
            stream=True,
            allow_redirects=False,
            headers=headers or {"User-Agent": "VulnScanner/1.0"},
        )
        try:
            if response.is_redirect:
                location = response.headers.get("location", "")
                if not location:
                    raise UnsafeURLError("Download redirect has no Location header")
                current = validate_outbound_url(
                    urljoin(current, location),
                    allow_private=allow_private,
                    resolve=True,
                    purpose="Download redirect",
                )
                continue
            if response.status_code >= 400:
                raise requests.HTTPError(
                    f"HTTP {response.status_code} from {current}", response=response
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise UnsafeURLError(
                        f"Download exceeds the {max_bytes // (1024 * 1024)} MiB limit"
                    )
                chunks.append(chunk)
            return FetchResult(
                url=current,
                status_code=response.status_code,
                content=b"".join(chunks),
                content_type=response.headers.get("content-type", ""),
            )
        finally:
            response.close()
    raise UnsafeURLError("Too many redirects")
