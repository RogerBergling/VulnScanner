"""Release and build metadata.

Packaged releases should set ``VS_BUILD_NUMBER``, ``VS_BUILD_TIME`` and
``VS_BUILD_COMMIT`` in the build environment. Source checkouts fall back to the
Git commit count, commit timestamp and short SHA, so a local run still shows a
useful build identifier.

The result is cached for the process lifetime. A restart is required to pick up
new build metadata, which is the expected behaviour for a release artifact.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from functools import lru_cache

from . import __version__
from .config import BASE_DIR


def _run_git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()


def _parse_build_time(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _fallback_build_time() -> datetime:
    try:
        return datetime.fromtimestamp(
            (BASE_DIR / "app" / "__init__.py").stat().st_mtime, tz=timezone.utc
        )
    except OSError:
        return datetime.now(timezone.utc)


@lru_cache(maxsize=1)
def build_info() -> dict[str, str]:
    """Return version, build number and build date/time for the UI/API."""
    configured_number = os.getenv("VS_BUILD_NUMBER", "").strip()
    configured_commit = os.getenv("VS_BUILD_COMMIT", "").strip()
    configured_time = os.getenv("VS_BUILD_TIME", "").strip()

    commit = configured_commit or _run_git("rev-parse", "--short", "HEAD")
    number = configured_number
    if not number:
        count = _run_git("rev-list", "--count", "HEAD")
        number = count or "dev"

    parsed_time = _parse_build_time(configured_time)
    if parsed_time is None and not configured_time:
        commit_time = _run_git("log", "-1", "--format=%cI")
        parsed_time = _parse_build_time(commit_time)
    if parsed_time is None:
        parsed_time = _fallback_build_time()

    utc_time = parsed_time.astimezone(timezone.utc)
    local_time = parsed_time.astimezone()
    local_zone = local_time.tzname() or "local"
    build_date = local_time.strftime("%Y-%m-%d")
    build_hour = local_time.strftime("%H:%M")

    return {
        "version": __version__,
        "number": number,
        "commit": commit,
        "time": utc_time.replace(microsecond=0).isoformat(),
        "date": build_date,
        "hour": build_hour,
        "timezone": local_zone,
        "display": f"v{__version__} · build #{number}"
        + (f" ({commit})" if commit else "")
        + f" · {build_date} {build_hour} {local_zone}",
    }
