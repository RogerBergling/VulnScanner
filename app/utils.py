"""Shared helpers for validation, normalization and presentation."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
SEVERITY_COLORS = {
    "critical": "#8b5cf6",
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#64748b",
}


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalize_severity(value: str | None, default: str = "medium") -> str:
    value = (value or default).strip().lower()
    aliases = {"moderate": "medium", "important": "high", "informational": "info"}
    value = aliases.get(value, value)
    return value if value in SEVERITY_RANK else default


def risk_score(summary: dict[str, int]) -> int:
    """Transparent 0-100 score used in dashboards."""
    weighted = (
        summary.get("critical", 0) * 20
        + summary.get("high", 0) * 8
        + summary.get("medium", 0) * 3
        + summary.get("low", 0) * 1
        + summary.get("info", 0) * 0.2
    )
    return int(min(100, round(weighted)))


def risk_label(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 20:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def severity_summary(findings: list[dict]) -> dict[str, int]:
    summary = {name: 0 for name in SEVERITIES}
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        summary[severity] += 1
    summary["total"] = len(findings)
    return summary


def fingerprint(*parts: str | None) -> str:
    raw = "\x1f".join((part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def human_age(value: str | None) -> str:
    parsed = parse_dt(value)
    if not parsed:
        return "never"
    seconds = int((datetime.now(timezone.utc) - parsed).total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target is required")
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// targets are supported")
    if not parsed.hostname:
        raise ValueError("Target must contain a hostname")
    if re.search(r"\s", parsed.hostname):
        raise ValueError("Target hostname may not contain whitespace")
    try:
        parsed.port  # noqa: B018 - validate the optional port
    except ValueError as exc:
        raise ValueError("Target contains an invalid port") from exc
    return target.rstrip("/")


def normalize_repo_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Repository target is required")
    if re.fullmatch(r"[\w.-]+/[\w.-]+", target):
        return f"https://github.com/{target}.git"
    if target.startswith("git@") or target.startswith("ssh://"):
        raise ValueError("SSH clone URLs are not supported. Use HTTPS or a local path.")
    if target.startswith("http://"):
        raise ValueError("Plain HTTP clone URLs are not supported. Use HTTPS or a local path.")
    if target.startswith("https://"):
        return target
    path = Path(target).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    if not path.exists() or not path.is_dir():
        raise ValueError(f"Local repository path does not exist: {target}")
    return str(path)


def validate_host_target(target: str) -> tuple[str, str]:
    """Return (kind, value) for a host, address or CIDR."""
    target = target.strip()
    if not target:
        raise ValueError("Target is required")
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid network: {target}") from exc
        return "cidr", str(network)
    if re.search(r"[\s/\\]", target):
        raise ValueError("Host target may not contain whitespace or slashes")
    return "host", target


def parse_ports(value: str | None, profile: str = "common") -> list[int]:
    from .config import TOP_PORTS

    if value:
        # A bare profile name is accepted in the ports field as a convenience
        # (for example "web" or "top1000").
        named = value.strip().lower()
        if named in {"web", "common", "top1000", "all"}:
            return parse_ports(None, named)
        ports: set[int] = set()
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = (int(x) for x in part.split("-", 1))
                except ValueError as exc:
                    raise ValueError(f"Invalid port range: {part}") from exc
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                if end - start > 5000:
                    raise ValueError("Port ranges are limited to 5000 ports per range")
                ports.update(range(start, end + 1))
            else:
                try:
                    port = int(part)
                except ValueError as exc:
                    raise ValueError(f"Invalid port: {part}") from exc
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {part}")
                ports.add(port)
        if not ports:
            raise ValueError("No ports supplied")
        return sorted(ports)
    if profile == "top1000":
        return list(range(1, 1001))
    if profile == "all":
        return list(range(1, 10001))
    if profile == "web":
        return [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
    return list(TOP_PORTS)


def redact_secret(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * max(4, len(value) - keep * 2)}{value[-keep:]}"


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return parsed._replace(netloc=f"***@{host}{port}").geturl()
    return value


def safe_xml_fromstring(text: str):
    """Parse XML while rejecting DTD/entity declarations.

    The scanners parse manifests and tool output from untrusted repositories.
    ``ElementTree`` does not fetch external entities by default, but rejecting
    DTDs outright also blocks entity-expansion denial-of-service payloads.
    """
    if re.search(r"<!DOCTYPE|<!ENTITY", text or "", re.IGNORECASE):
        raise ValueError("XML with DTD or entity declarations is not accepted")
    import xml.etree.ElementTree as ET

    return ET.fromstring(text)


def clean_text(value: str | None, limit: int = 5000) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value)
    cleaned = cleaned.replace("\x00", "")
    return cleaned[:limit]


def truncate(value: str, length: int = 500) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value[:length]


def escape(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def secure_filename(value: str, fallback: str = "report") -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return value[:100] or fallback


def format_duration(start: str | None, end: str | None) -> str:
    start_dt, end_dt = parse_dt(start), parse_dt(end)
    if not start_dt or not end_dt:
        return "—"
    seconds = max(0, int((end_dt - start_dt).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
