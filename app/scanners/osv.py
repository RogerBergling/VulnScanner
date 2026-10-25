"""OSV.dev client with a local SQLite response cache.

OSV aggregates advisories from GitHub, PyPA, npm, Go, RustSec, OSS-Fuzz,
Debian, Ubuntu and many other sources.  It is the primary public vulnerability
database used by the built-in dependency scanner.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import requests

from ..config import ENABLE_EXTERNAL_APIS
from ..database import get_db, get_setting, json_dump, utcnow

OSV_API = "https://api.osv.dev/v1"
USER_AGENT = "VulnScanner/1.0 (local vulnerability scanner)"


class OsvUnavailable(RuntimeError):
    pass


def _cache_get(key: str, allow_expired: bool = False) -> Any | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT response, expires_at FROM osv_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()
    if not row:
        return None
    if not allow_expired and row["expires_at"] < utcnow():
        return None
    try:
        return json.loads(row["response"])
    except ValueError:
        return None


def _cache_put(key: str, value: Any, hours: int) -> None:
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO osv_cache(cache_key, response, created_at, expires_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cache_key) DO UPDATE SET response = excluded.response, "
            "created_at = excluded.created_at, expires_at = excluded.expires_at",
            (key, json_dump(value), utcnow(), expires.replace(microsecond=0).isoformat()),
        )
        conn.commit()


def _post_batch(payload: dict[str, Any]) -> dict[str, Any]:
    for attempt in range(2):
        try:
            response = requests.post(
                f"{OSV_API}/querybatch",
                json=payload,
                timeout=30,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 0:
                    time.sleep(1.5)
                    continue
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            if attempt == 0:
                time.sleep(1.0)
                continue
            raise OsvUnavailable(f"OSV API request failed: {exc}") from exc
    raise OsvUnavailable("OSV API request failed")


def _get_vuln(vuln_id: str, allow_offline: bool = False) -> dict[str, Any] | None:
    cache_key = f"vuln:{vuln_id}"
    cached = _cache_get(cache_key, allow_expired=allow_offline)
    if cached:
        return cached
    if allow_offline or not ENABLE_EXTERNAL_APIS:
        return None
    for attempt in range(2):
        try:
            response = requests.get(
                f"{OSV_API}/vulns/{vuln_id}",
                timeout=25,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code == 404:
                return None
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 0:
                    time.sleep(1.0)
                    continue
            response.raise_for_status()
            data = response.json()
            _cache_put(cache_key, data, 24 * 14)
            return data
        except requests.RequestException:
            if attempt == 0:
                time.sleep(0.8)
    return None


def query_packages(
    packages: list[dict[str, Any]],
    log: Callable[[str], None] | None = None,
    batch_size: int = 100,
) -> dict[int, list[dict[str, Any]]]:
    """Return {package_index: [full OSV vulnerability records]}.

    ``packages`` entries need ``name``, ``version`` and ``ecosystem``.  Packages
    without an ecosystem are skipped because OSV cannot resolve them.
    """
    results: dict[int, list[dict[str, Any]]] = {}
    valid: list[tuple[int, dict[str, Any]]] = []
    for index, package in enumerate(packages):
        if not package.get("name") or not package.get("version") or not package.get("ecosystem"):
            continue
        valid.append((index, package))

    allow_external = ENABLE_EXTERNAL_APIS and get_setting("allow_external_apis", "true") == "true"
    for start in range(0, len(valid), batch_size):
        chunk = valid[start:start + batch_size]
        query_key = hashlib.sha256(
            json_dump(
                [
                    {
                        "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                        "version": p["version"],
                    }
                    for _, p in chunk
                ]
            ).encode()
        ).hexdigest()
        cache_key = f"batch:{query_key}"
        batch_result = _cache_get(cache_key)
        if batch_result is None:
            if not allow_external:
                batch_result = None
            else:
                payload = {
                    "queries": [
                        {
                            "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                            "version": p["version"],
                        }
                        for _, p in chunk
                    ]
                }
                try:
                    batch_result = _post_batch(payload)
                    _cache_put(cache_key, batch_result, 6)
                except OsvUnavailable as exc:
                    if log:
                        log(f"OSV lookup unavailable: {exc}")
                    # Use an expired cache if we have one.
                    batch_result = _cache_get(cache_key, allow_expired=True)
                    if batch_result is None:
                        continue
        if not batch_result:
            continue
        for offset, query_result in enumerate(batch_result.get("results", [])):
            if offset >= len(chunk):
                break
            package_index = chunk[offset][0]
            vuln_ids = [
                item.get("id") for item in query_result.get("vulns", []) if item.get("id")
            ]
            if not vuln_ids:
                continue
            full: list[dict[str, Any]] = []
            for vuln_id in vuln_ids:
                detail = _get_vuln(vuln_id, allow_offline=not allow_external)
                if detail:
                    full.append(detail)
                else:
                    full.append({"id": vuln_id, "summary": f"Advisory {vuln_id}"})
            results[package_index] = full
        if log and len(valid) > batch_size:
            log(f"OSV: resolved {min(start + batch_size, len(valid))}/{len(valid)} packages")
    return results


def kev_lookup(cve_ids: set[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    placeholders = ",".join("?" for _ in cve_ids)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM kev_catalog WHERE cve_id IN ({placeholders})",
            tuple(cve_ids),
        ).fetchall()
    return {row["cve_id"]: dict(row) for row in rows}
