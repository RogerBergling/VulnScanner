"""Service banner/CPE fingerprinting and CVE matching.

Turns banners, HTTP headers and tool-detected product versions into CPEs,
queries the NVD CVE API 2.0 for known vulnerabilities of the detected product
version, and enriches findings with CVSS, CWE and EPSS exploitation
likelihood. Results are cached in SQLite so repeated scans reuse downloaded
data and brief offline periods still produce results.

NVD API 2.0 is rate limited (5 requests/30s without a key, 50/30s with one).
The client throttles itself and supports an optional ``VS_NVD_API_KEY``.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import requests

from ..config import ENABLE_EXTERNAL_APIS
from ..database import get_db, get_setting, json_dump, setting_or_default, utcnow
from .base import Finding, ScanResult

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
USER_AGENT = "VulnScanner/1.0 (local vulnerability scanner)"
NVD_CACHE_HOURS = 24
EPSS_CACHE_HOURS = 24
MAX_NVD_PAGES = 4
NVD_PAGE_SIZE = 2000

# ---------------------------------------------------------------------------
# Fingerprint registry
# ---------------------------------------------------------------------------


class ProductMatch:
    __slots__ = ("vendor", "product", "version", "service", "source", "cpe")

    def __init__(self, vendor: str, product: str, version: str, service: str, source: str):
        self.vendor = vendor
        self.product = product
        self.version = version
        self.service = service
        self.source = source
        self.cpe = product_cpe(vendor, product, version)

    def to_dict(self) -> dict[str, str]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "service": self.service,
            "source": self.source,
            "cpe": self.cpe,
        }


def _version(value: str) -> str:
    """Normalise a raw banner version into a comparable dotted token."""
    value = (value or "").strip()
    # MariaDB banners are prefixed by the fake 5.5.5 version.
    if value.startswith("5.5.5-"):
        value = value.split("-", 1)[1]
    # Ubuntu/RedHat suffixes.
    value = re.split(r"[+~-](?:ubuntu|deb|el\d|fc\d|rh|alpine)", value, flags=re.I)[0]
    value = re.sub(r"(?i)[a-z]+$", "", value)  # trailing distro letters (2.4.41ubuntu)
    value = value.strip(".-")
    return value


def version_tuple(value: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for part in _version(value).split("."):
        match = re.match(r"^(\d+)", part)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(part)
    return tuple(parts) or (0,)


def version_in_range(version: str, start_in: str | None, start_ex: str | None,
                     end_in: str | None, end_ex: str | None) -> bool:
    """Check whether ``version`` falls inside an NVD cpeMatch version range."""
    current = version_tuple(version)
    if start_in is not None and current < version_tuple(start_in):
        return False
    if start_ex is not None and current <= version_tuple(start_ex):
        return False
    if end_in is not None and current > version_tuple(end_in):
        return False
    if end_ex is not None and current >= version_tuple(end_ex):
        return False
    return True


def split_cpe_fields(criteria: str) -> list[str]:
    """Split a CPE 2.3 string on unescaped colons (``\\:`` stays literal)."""
    fields: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(criteria):
        char = criteria[i]
        if char == "\\" and i + 1 < len(criteria) and criteria[i + 1] == ":":
            current.append(":")
            i += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    fields.append("".join(current))
    return fields


def product_cpe(vendor: str, product: str, version: str = "*") -> str:
    # cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:
    # target_sw:target_hw:other — 13 fields total.
    fields = [
        "cpe", "2.3", "a", vendor, product, version or "*",
        "*", "*", "*", "*", "*", "*", "*",
    ]
    escaped = [field.replace(":", "\\:") for field in fields]
    return ":".join(escaped)


# Entries are tried in order; the first regex match wins.  ``version`` names
# the regex group containing the version.  ``fallbacks`` lists alternative
# (vendor, product) pairs NVD uses for the same software.  Patterns accept
# both banner separators (``OpenSSH_8.2``) and nmap-style joins
# (``OpenSSH 8.2``).
FINGERPRINTS: list[dict[str, Any]] = [
    {"name": "OpenSSH", "regex": re.compile(r"OpenSSH[\s_-]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "openbsd", "product": "openssh", "service": "ssh"},
    {"name": "Dropbear SSH", "regex": re.compile(r"dropbear[\s_-]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "dropbear_ssh_project", "product": "dropbear_ssh", "service": "ssh"},
    {"name": "Apache httpd", "regex": re.compile(r"Apache[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "apache", "product": "http_server", "service": "http"},
    {"name": "nginx", "regex": re.compile(r"\bnginx[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "f5", "product": "nginx", "service": "http",
     "fallbacks": [("nginx", "nginx")]},
    {"name": "Microsoft IIS", "regex": re.compile(r"Microsoft-IIS[/\s]+(?P<v>\d+\.\d+)", re.I),
     "version": "v", "vendor": "microsoft", "product": "internet_information_services", "service": "http"},
    {"name": "MariaDB", "regex": re.compile(
        r"(?:(?P<v>5\.5\.5-\d+\.\d+\.\d+)-MariaDB|MariaDB[/\s-]+(?P<v2>\d+\.\d+\.\d+))", re.I),
     "version": ["v", "v2"], "vendor": "mariadb", "product": "mariadb", "service": "mysql"},
    {"name": "MySQL", "regex": re.compile(r"(?:mysql|MySQL)[/\s_-]*(?P<v>\d+\.\d+\.\d+)"),
     "version": "v", "vendor": "oracle", "product": "mysql", "service": "mysql",
     "fallbacks": [("mysql", "mysql")]},
    {"name": "PostgreSQL", "regex": re.compile(r"PostgreSQL(?: DB)?\s+(?P<v>\d+(?:\.\d+)+)", re.I),
     "version": "v", "vendor": "postgresql", "product": "postgresql", "service": "postgresql"},
    {"name": "Redis", "regex": re.compile(r"redis_version\s*:\s*(?P<v>\d+\.\d+[^\s\r]*)", re.I),
     "version": "v", "vendor": "redis", "product": "redis", "service": "redis"},
    {"name": "MongoDB", "regex": re.compile(r'"version"\s*:\s*"(?P<v>\d+\.\d+[^"]*)"', re.I),
     "version": "v", "vendor": "mongodb", "product": "mongodb", "service": "mongodb"},
    {"name": "Elasticsearch", "regex": re.compile(r'"number"\s*:\s*"(?P<v>\d+\.\d+[^"]*)"', re.I),
     "version": "v", "vendor": "elastic", "product": "elasticsearch", "service": "elasticsearch"},
    {"name": "Kibana", "regex": re.compile(r'"name"\s*:\s*"kibana"[^}]*"number"\s*:\s*"(?P<v>\d+\.\d+[^"]*)"', re.I),
     "version": "v", "vendor": "elastic", "product": "kibana", "service": "http"},
    {"name": "Apache Tomcat", "regex": re.compile(r"Apache[ -]Tomcat[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "apache", "product": "tomcat", "service": "http"},
    {"name": "Jetty", "regex": re.compile(r"Jetty[/\s(]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "eclipse", "product": "jetty", "service": "http"},
    {"name": "lighttpd", "regex": re.compile(r"lighttpd[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "lighttpd", "product": "lighttpd", "service": "http"},
    {"name": "Squid", "regex": re.compile(r"squid[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "squid-cache", "product": "squid", "service": "http"},
    {"name": "PHP", "regex": re.compile(r"PHP[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "php", "product": "php", "service": "http"},
    {"name": "WordPress", "regex": re.compile(r"WordPress\s+(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "version": "v", "vendor": "wordpress", "product": "wordpress", "service": "http"},
    {"name": "Drupal", "regex": re.compile(r"Drupal\s+(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "version": "v", "vendor": "drupal", "product": "drupal", "service": "http"},
    {"name": "Jenkins", "regex": re.compile(r"(?:X-Jenkins|Jenkins)[:/\s]+(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "version": "v", "vendor": "jenkins", "product": "jenkins", "service": "http"},
    {"name": "vsftpd", "regex": re.compile(r"vsFTPd\s+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "vsftpd_project", "product": "vsftpd", "service": "ftp"},
    {"name": "ProFTPD", "regex": re.compile(r"ProFTPD\s+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "proftpd", "product": "proftpd", "service": "ftp"},
    {"name": "Postfix", "regex": re.compile(r"Postfix[^\d]{0,24}(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "postfix", "product": "postfix", "service": "smtp"},
    {"name": "Exim", "regex": re.compile(r"\bExim[^\d]{0,24}(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "exim", "product": "exim", "service": "smtp"},
    {"name": "Sendmail", "regex": re.compile(r"\bSendmail[^\d]{0,24}(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "sendmail", "product": "sendmail", "service": "smtp"},
    {"name": "Dovecot", "regex": re.compile(r"Dovecot[^\d]{0,24}(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "dovecot", "product": "dovecot", "service": "imap"},
    {"name": "CUPS", "regex": re.compile(r"CUPS[/\s]+(?P<v>\d+\.\d+[^\s)]*)", re.I),
     "version": "v", "vendor": "apple", "product": "cups", "service": "ipp"},
    {"name": "Memcached", "regex": re.compile(r"STAT version\s+(?P<v>\d+\.\d+[^\s\r]*)", re.I),
     "version": "v", "vendor": "memcached", "product": "memcached", "service": "memcached"},
    {"name": "Docker Engine", "regex": re.compile(r'"Version"\s*:\s*"(?P<v>\d+\.\d+[^"]*)"', re.I),
     "version": "v", "vendor": "docker", "product": "docker", "service": "docker"},
    {"name": "Kubernetes", "regex": re.compile(r'"gitVersion"\s*:\s*"v(?P<v>\d+\.\d+[^"]*)"', re.I),
     "version": "v", "vendor": "kubernetes", "product": "kubernetes", "service": "kubernetes"},
    {"name": "VNC", "regex": re.compile(r"RFB\s+(\d{3})\.(\d{3})", re.I),
     "version": None, "vendor": "", "product": "", "service": "vnc"},
]


def fingerprint_text(text: str, source: str) -> list[ProductMatch]:
    """Match a banner/header/meta string against the fingerprint registry."""
    if not text:
        return []
    matches: list[ProductMatch] = []
    seen: set[str] = set()
    for entry in FINGERPRINTS:
        m = entry["regex"].search(text)
        if not m:
            continue
        if entry["version"] is None:
            continue
        group_names = entry["version"]
        if isinstance(group_names, str):
            group_names = [group_names]
        raw_version = next(
            (m.group(name) for name in group_names if m.group(name)), ""
        )
        version = _version(raw_version)
        if not version:
            continue
        key = f"{entry['vendor']}:{entry['product']}:{version}"
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            ProductMatch(
                vendor=entry["vendor"],
                product=entry["product"],
                version=version,
                service=entry["service"],
                source=source,
            )
        )
    return matches


# ---------------------------------------------------------------------------
# NVD client
# ---------------------------------------------------------------------------

_nvd_lock = threading.Lock()
_nvd_last_request = 0.0


def nvd_api_key() -> str:
    """Return the NVD API key from the environment or encrypted Settings.

    Settings is preferred for GUI-managed installs; the environment variable
    remains a deployment-level override.
    """
    value = os.getenv("VS_NVD_API_KEY", "").strip()
    if value:
        return value
    try:
        stored = get_setting("nvd_api_key", "").strip()
        if stored:
            from ..credentials import decrypt_secret

            return decrypt_secret(stored)
    except Exception:
        pass
    return ""


def _nvd_throttle() -> None:
    """Space NVD requests to stay within the published rate limits."""
    global _nvd_last_request
    with _nvd_lock:
        gap = 0.75 if nvd_api_key() else 6.5
        wait = gap - (time.monotonic() - _nvd_last_request)
        if wait > 0:
            time.sleep(min(wait, 60.0))
        _nvd_last_request = time.monotonic()


def _cache_get(key: str, allow_expired: bool = False) -> Any | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT response, expires_at FROM nvd_cache WHERE cache_key = ?", (key,)
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
            "INSERT INTO nvd_cache(cache_key, response, created_at, expires_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET "
            "response = excluded.response, created_at = excluded.created_at, "
            "expires_at = excluded.expires_at",
            (key, json_dump(value), utcnow(), expires.replace(microsecond=0).isoformat()),
        )
        conn.commit()


def _cpe_match_applies(match: dict[str, Any], vendor: str, product: str, version: str) -> bool:
    if not match.get("vulnerable", True):
        return False
    criteria = match.get("criteria") or ""
    fields = split_cpe_fields(criteria)
    if len(fields) < 6 or fields[1:3] != ["2.3", "a"]:
        return False
    if fields[3].lower() != vendor.lower() or fields[4].lower() != product.lower():
        return False
    cpe_version = fields[5]
    has_range = any(
        match.get(key) is not None
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    if cpe_version in {"*", "-"} and not has_range:
        return True
    if cpe_version not in {"*", "-"} and _version(cpe_version) == _version(version):
        return True
    if not has_range:
        return False
    return version_in_range(
        version,
        match.get("versionStartIncluding"),
        match.get("versionStartExcluding"),
        match.get("versionEndIncluding"),
        match.get("versionEndExcluding"),
    )


def filter_cves_for_product(data: dict[str, Any], vendor: str, product: str,
                            version: str) -> list[dict[str, Any]]:
    """Return the CVE records from an NVD API response that apply to the
    detected product version. Pure function so tests can feed canned data."""
    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        configurations = cve.get("configurations") or []
        applies = False
        for config in configurations:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    if _cpe_match_applies(match, vendor, product, version):
                        applies = True
                        break
                if applies:
                    break
            if applies:
                break
        if applies:
            results.append(cve)
    return results


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower() == "en":
            return str(item.get("value") or "")
    for item in descriptions:
        if isinstance(item, dict) and item.get("value"):
            return str(item["value"])
    return ""


def _cve_metrics(cve: dict[str, Any]) -> tuple[float | None, str]:
    """Return (cvss3 score or cvss2 score, severity label)."""
    metrics = cve.get("metrics") or {}
    for version_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version_key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            try:
                score = float(data.get("baseScore") or 0)
            except (TypeError, ValueError):
                continue
            severity = str(entry.get("baseSeverity") or data.get("baseSeverity") or "")
            if score > 0:
                return score, severity
    entries = metrics.get("cvssMetricV2") or []
    for entry in entries:
        data = entry.get("cvssData") or {}
        try:
            score = float(data.get("baseScore") or 0)
        except (TypeError, ValueError):
            continue
        severity = str(entry.get("baseSeverity") or data.get("baseSeverity") or "")
        if score > 0:
            return score, severity
    return None, ""


def _severity_from_cvss(score: float | None) -> str:
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


def _cve_weaknesses(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value") or "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def cve_record(cve: dict[str, Any]) -> dict[str, Any]:
    score, severity = _cve_metrics(cve)
    return {
        "id": str(cve.get("id") or ""),
        "description": _english_description(cve),
        "cvss": score,
        "cvss_severity": severity,
        "severity": _severity_from_cvss(score) if score is not None else severity.lower() or "medium",
        "cwe": _cve_weaknesses(cve),
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "status": str(cve.get("vulnStatus") or ""),
        "reference": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


def _fetch_nvd_pages(
    params: dict[str, str],
    log: Callable[[str], None] | None,
    max_pages: int = MAX_NVD_PAGES,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    headers = {"User-Agent": USER_AGENT}
    api_key = nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key
    for page in range(max(1, max_pages)):
        page_params = dict(params)
        page_params["startIndex"] = str(page * NVD_PAGE_SIZE)
        for attempt in range(2):
            try:
                _nvd_throttle()
                response = requests.get(NVD_API, params=page_params, headers=headers, timeout=45)
            except requests.RequestException as exc:
                if attempt == 0:
                    time.sleep(1.5)
                    continue
                if log:
                    log(f"NVD request failed: {exc}")
                return items
            if response.status_code == 429 or response.status_code >= 500:
                retry_after = response.headers.get("Retry-After")
                try:
                    time.sleep(min(float(retry_after), 60.0) if retry_after else 5.0)
                except ValueError:
                    time.sleep(5.0)
                if attempt == 0:
                    continue
                return items
            if response.status_code in (403, 404):
                return items
            if response.status_code != 200:
                if attempt == 0:
                    time.sleep(1.0)
                    continue
                return items
            try:
                data = response.json()
            except ValueError:
                return items
            vulns = data.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                return items
            items.extend(vulns)
            total = int(data.get("totalResults") or len(vulns))
            if (page + 1) * NVD_PAGE_SIZE >= total:
                return items
            break
    return items


def product_cache_key(vendor: str, product: str) -> str:
    return f"nvd:product:{vendor}:{product}"


def sync_product_cves(
    vendor: str,
    product: str,
    log: Callable[[str], None] | None = None,
    *,
    max_pages: int = 20,
) -> int:
    """Download and cache every CVE that mentions a vendor/product.

    The response keeps the full NVD ``configurations`` block so versions can be
    evaluated locally later, including while the machine is offline.
    """
    vendor = (vendor or "").strip().lower()
    product = (product or "").strip().lower()
    if not vendor or not product:
        return 0
    params = {
        "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
        "resultsPerPage": str(NVD_PAGE_SIZE),
    }
    raw = _fetch_nvd_pages(params, log, max_pages=max_pages)
    if not raw:
        return 0
    _cache_put(
        product_cache_key(vendor, product),
        {
            "vulnerabilities": raw,
            "source": "virtualMatchString",
            "vendor": vendor,
            "product": product,
            "synced_at": utcnow(),
        },
        24 * 7,
    )
    if log:
        log(f"NVD: cached {len(raw)} product-level CVE record(s) for {vendor}/{product}")
    return len(raw)


def fingerprinted_products() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in FINGERPRINTS:
        candidates = [(entry.get("vendor"), entry.get("product"))]
        candidates.extend(entry.get("fallbacks") or [])
        for vendor, product in candidates:
            if not vendor or not product:
                continue
            key = (str(vendor).lower(), str(product).lower())
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def lookup_cves(match: ProductMatch, log: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
    """Resolve applicable CVEs for a fingerprinted product version.

    Lookup order:
    1. exact version cache (fast, from the previous online query),
    2. product-level offline cache (all versions, evaluated locally),
    3. live NVD query when external APIs are enabled.
    """
    if not match.vendor or not match.product or not match.version:
        return []
    external = ENABLE_EXTERNAL_APIS and setting_or_default(
        "allow_external_apis", "true"
    ) == "true"
    attempts: list[tuple[str, str]] = [(match.vendor, match.product)]
    for fallback in FINGERPRINTS:
        if fallback.get("vendor") == match.vendor and fallback.get("product") == match.product:
            attempts.extend(fallback.get("fallbacks") or [])
            break
    for vendor, product in attempts:
        # Product-level cache works offline and covers versions that were
        # never queried individually.
        product_data = _cache_get(
            product_cache_key(vendor, product), allow_expired=True
        )
        if product_data:
            cves = filter_cves_for_product(
                product_data, vendor, product, match.version
            )
            if cves:
                records = [cve_record(cve) for cve in cves]
                return sorted(records, key=lambda item: item["cvss"] or 0.0, reverse=True)

        if not external:
            continue
        cache_key = f"nvd:cpe:{vendor}:{product}:{match.version}"
        data = _cache_get(cache_key)
        if data is None:
            # The NVD API matches CPE criteria including version ranges when
            # given a versioned CPE. The local filter below is a second gate
            # that also guards against unrelated matches.
            params = {
                "cpeName": product_cpe(vendor, product, match.version),
                "resultsPerPage": str(NVD_PAGE_SIZE),
            }
            raw = _fetch_nvd_pages(params, log)
            if raw:
                data = {"vulnerabilities": raw}
                _cache_put(cache_key, data, NVD_CACHE_HOURS)
                if log:
                    log(f"NVD: cached {len(raw)} CVE record(s) for {vendor}/{product} {match.version}")
        if not data:
            continue
        cves = filter_cves_for_product(data, vendor, product, match.version)
        if cves:
            records = [cve_record(cve) for cve in cves]
            return sorted(records, key=lambda item: item["cvss"] or 0.0, reverse=True)
    return []


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

_epss_lock = threading.Lock()
_epss_last_request = 0.0


def _epss_cached(cve_ids: list[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    found: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    with get_db() as conn:
        for cve_id in cve_ids:
            row = conn.execute(
                "SELECT cve_id, score, percentile, fetched_at FROM epss_cache WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
            if not row:
                missing.append(cve_id)
                continue
            fetched = row["fetched_at"]
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(fetched)
                stale = age > timedelta(hours=EPSS_CACHE_HOURS)
            except ValueError:
                stale = True
            if stale:
                missing.append(cve_id)
                continue
            found[cve_id] = {"score": row["score"], "percentile": row["percentile"]}
    return found, missing


def _epss_store(rows: dict[str, dict[str, Any]]) -> None:
    with get_db() as conn:
        conn.executemany(
            "INSERT INTO epss_cache(cve_id, score, percentile, fetched_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET score = excluded.score, "
            "percentile = excluded.percentile, fetched_at = excluded.fetched_at",
            [
                (cve_id, row["score"], row["percentile"], utcnow())
                for cve_id, row in rows.items()
            ],
        )
        conn.commit()


def lookup_epss(cve_ids: list[str], log: Callable[[str], None] | None = None) -> dict[str, dict[str, Any]]:
    """Return {cve_id: {score, percentile}} for the given CVEs."""
    if not cve_ids or not ENABLE_EXTERNAL_APIS or setting_or_default("allow_external_apis", "true") != "true":
        return {}
    found, missing = _epss_cached(cve_ids)
    if not missing:
        return found
    global _epss_last_request
    for start in range(0, len(missing), 100):
        chunk = missing[start:start + 100]
        with _epss_lock:
            wait = 1.5 - (time.monotonic() - _epss_last_request)
            if wait > 0:
                time.sleep(min(wait, 30.0))
            _epss_last_request = time.monotonic()
        try:
            response = requests.get(
                EPSS_API,
                params={"cve": ",".join(chunk)},
                timeout=30,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code != 200:
                if log:
                    log(f"EPSS lookup failed with status {response.status_code}")
                continue
            data = response.json()
        except (requests.RequestException, ValueError):
            continue
        rows: dict[str, dict[str, Any]] = {}
        for item in data.get("data") or []:
            cve_id = str(item.get("cve") or "")
            if not cve_id.startswith("CVE-"):
                continue
            try:
                score = float(item.get("epss") or 0)
                percentile = float(item.get("percentile") or 0)
            except (TypeError, ValueError):
                score, percentile = 0.0, 0.0
            rows[cve_id] = {"score": score, "percentile": percentile}
        _epss_store(rows)
        found.update(rows)
    return found


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def add_cve_findings(
    result: ScanResult,
    match: ProductMatch,
    location: str,
    cves: list[dict[str, Any]],
    category: str,
    epss: dict[str, dict[str, Any]] | None = None,
    max_findings: int = 50,
) -> int:
    """Append CVE findings for a fingerprinted service, newest risk first."""
    epss = epss or {}
    added = 0
    for record in cves[:max_findings]:
        cve_id = record["id"]
        epss_row = epss.get(cve_id)
        description = record["description"] or f"See NVD for {cve_id}"
        evidence_lines = [
            f"CVE: {cve_id}",
            f"Product: {match.product} {match.version}",
            f"Detected via: {match.source}",
            f"Reference: {record['reference']}",
        ]
        if record["cvss"] is not None:
            evidence_lines.append(f"CVSS: {record['cvss']} ({record['cvss_severity']})")
        if epss_row:
            evidence_lines.append(
                f"EPSS: {epss_row['score']:.4f} ({epss_row['percentile'] * 100:.0f}th percentile)"
            )
        result.add(
            Finding(
                severity=record["severity"],
                title=f"{cve_id} - {description[:120]} ({match.product} {match.version})",
                category=category,
                description=(
                    f"{description}\n\nDetected {match.product} version {match.version} "
                    f"matches the vulnerable CPE range for {cve_id}."
                ),
                evidence="\n".join(evidence_lines),
                remediation=f"Upgrade {match.product} to a fixed version and verify the advisory for {cve_id}.",
                cve=cve_id,
                cwe=",".join(record["cwe"]) if record["cwe"] else "",
                cvss=record["cvss"],
                location=location,
                resource=f"cpe:{match.cpe}",
                key=f"cve:{cve_id}:{match.product}:{match.version}",
                raw={
                    "cpe": match.cpe,
                    "product": match.product,
                    "version": match.version,
                    "cvss_severity": record["cvss_severity"],
                    "epss": epss_row or None,
                    "reference": record["reference"],
                    "published": record["published"],
                },
            )
        )
        added += 1
    return added
