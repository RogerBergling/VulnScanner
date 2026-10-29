"""Application configuration.

Everything is intentionally local-first.  The only outbound calls are made by
scanners you enable (OSV, CISA KEV, GitHub, or optional CLI tools).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
_LIMIT_CACHE: dict[tuple[str, int, str, int], tuple[float, int]] = {}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def data_dir() -> Path:
    path = Path(os.getenv("VS_DATA_DIR", BASE_DIR / "data")).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _database_file() -> Path:
    """Return the configured database path without creating directories.

    ``database_path()`` is the normal accessor used by the database layer. This
    helper exists so read-only consumers such as ``get_limit()`` can check
    whether a database exists without accidentally creating ``data/`` during
    tests or one-off CLI imports.
    """
    configured = os.getenv("VS_DATABASE")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(os.getenv("VS_DATA_DIR", BASE_DIR / "data")).expanduser().resolve() / "vulnscanner.db"


def database_path() -> Path:
    path = _database_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def clear_limit_cache() -> None:
    _LIMIT_CACHE.clear()


def get_limit(name: str, default: int) -> int:
    """Return an operator-editable guardrail from SQLite, with env fallback.

    The Settings UI stores guardrails in the ``settings`` table. Scanners must
    read the current value at scan time rather than the process-start constant,
    otherwise changing a setting has no effect until a restart. A short cache
    avoids opening SQLite for every file visited by the repository scanners.
    """
    now = time.monotonic()
    try:
        path = _database_file()
        stamp = path.stat().st_mtime_ns if path.is_file() else 0
    except OSError:
        path = Path("")
        stamp = 0
    key = (name, int(default), str(path), stamp)
    cached = _LIMIT_CACHE.get(key)
    if cached and now - cached[0] < 5.0:
        return cached[1]
    try:
        if not path.is_file():
            value = default
        else:
            from .database import get_setting

            value = int(get_setting(name, str(default)))
    except (ImportError, OSError, TypeError, ValueError):
        value = default
    _LIMIT_CACHE[key] = (now, value)
    return value


def reports_dir() -> Path:
    path = data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def clone_dir() -> Path:
    path = data_dir() / "clones"
    path.mkdir(parents=True, exist_ok=True)
    return path


def wordlists_dir() -> Path:
    path = data_dir() / "wordlists"
    path.mkdir(parents=True, exist_ok=True)
    return path


def subfinder_wordlist_path() -> Path:
    """Return the editable subdomain wordlist path.

    The default lives under the data directory so it is never committed. A
    deployment that keeps a SecLists checkout elsewhere can point
    ``VS_SUBFINDER_WORDLIST`` at it; in that case the GUI treats the file as
    read-only unless it is inside ``VS_DATA_DIR``.
    """
    configured = os.getenv("VS_SUBFINDER_WORDLIST", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return wordlists_dir() / "subdomains.txt"


# SecLists is the standard source for the editable subdomain wordlist. The
# download action is deliberately explicit so scans never fetch wordlists on
# their own.
SECLISTS_SUBDOMAIN_URL = os.getenv(
    "VS_SECLISTS_SUBDOMAIN_URL",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
)
SECLISTS_REPOSITORY_URL = "https://github.com/danielmiessler/SecLists"


HOST = os.getenv("VS_HOST", "127.0.0.1")
PORT = int(os.getenv("VS_PORT", "8765"))

# Guardrails for scans.
MAX_REPO_BYTES = int(os.getenv("VS_MAX_REPO_BYTES", str(512 * 1024 * 1024)))
MAX_SOURCE_FILE_BYTES = int(os.getenv("VS_MAX_SOURCE_FILE_BYTES", str(1024 * 1024)))
MAX_SCAN_FILES = int(os.getenv("VS_MAX_SCAN_FILES", "20000"))
MAX_CIDR_HOSTS = int(os.getenv("VS_MAX_CIDR_HOSTS", "256"))
AGENT_JOB_TIMEOUT_SECONDS = int(os.getenv("VS_AGENT_JOB_TIMEOUT", str(60 * 60)))
# Optional known-hosts file for authenticated SSH scans. When set, the server
# verifies the remote host key before sending credentials. When unset, the
# fingerprint is logged but the connection is allowed (compatible with existing
# lab deployments). Production deployments should set this.
SSH_KNOWN_HOSTS = os.getenv("VS_SSH_KNOWN_HOSTS", "").strip()
# Background scans are independent jobs. Raise this on a larger host to run more
# server-side scans at the same time. Delegated agent scans wait on the agent
# and do not consume a worker slot.
SCAN_WORKERS = max(1, min(32, int(os.getenv("VS_SCAN_WORKERS", "4"))))
ENABLE_EXTERNAL_APIS = _env_bool("VS_ENABLE_EXTERNAL_APIS", True)

# Optional CLI integrations. Empty means "look in PATH". The GUI writes these
# values to .env and updates the in-process mapping immediately.
TOOL_ENV_VARS = {
    "nmap": "VS_NMAP_PATH",
    "nuclei": "VS_NUCLEI_PATH",
    "testssl": "VS_TESTSSL_PATH",
    "trivy": "VS_TRIVY_PATH",
    "subfinder": "VS_SUBFINDER_PATH",
    "osv-scanner": "VS_OSV_SCANNER_PATH",
    "gitleaks": "VS_GITLEAKS_PATH",
    "semgrep": "VS_SEMGREP_PATH",
    "git": "VS_GIT_PATH",
}
TOOL_PATHS = {
    name: os.getenv(env_name, "") for name, env_name in TOOL_ENV_VARS.items()
}


def _env_tool_paths() -> dict[str, str]:
    return {name: os.getenv(env_name, "") for name, env_name in TOOL_ENV_VARS.items()}


def reload_tool_paths() -> dict[str, str]:
    """Load tool paths from SQLite, falling back to environment variables.

    The Settings page stores paths in the database so they travel with a
    database backup. The environment variables remain supported for
    service-level overrides and for older installations.
    """
    paths = _env_tool_paths()
    try:
        from .database import get_setting_optional

        raw = get_setting_optional("tool_paths")
        if raw is not None:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                for name in TOOL_ENV_VARS:
                    if name in parsed:
                        paths[name] = str(parsed.get(name) or "")
    except Exception:
        pass
    TOOL_PATHS.clear()
    TOOL_PATHS.update(paths)
    return dict(TOOL_PATHS)


def migrate_env_tool_paths() -> None:
    """Store non-empty environment tool paths in the database once.

    This makes the first backup after an upgrade self-contained without
    overwriting paths that an operator later changes through Settings.
    """
    try:
        from .database import get_setting_optional, set_setting

        if get_setting_optional("tool_paths") is not None:
            return
        env_paths = {name: value for name, value in _env_tool_paths().items() if value}
        if env_paths:
            set_setting("tool_paths", json.dumps(env_paths, separators=(",", ":")))
    except Exception:
        pass

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2181, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900,
    5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018,
]

DANGEROUS_PORTS = {
    21: ("FTP", "medium", "FTP is unencrypted. Prefer SFTP/FTPS and restrict access."),
    23: ("Telnet", "high", "Telnet sends credentials in clear text. Disable it and use SSH."),
    69: ("TFTP", "medium", "TFTP has no authentication. Restrict it to management networks."),
    111: ("rpcbind", "medium", "rpcbind can expose RPC services. Restrict or disable it."),
    135: ("MS RPC", "medium", "Do not expose MS RPC to untrusted networks."),
    139: ("NetBIOS", "medium", "Legacy NetBIOS should not be internet-facing."),
    161: ("SNMP", "medium", "SNMPv1/v2 use weak community strings. Use SNMPv3 and filter access."),
    445: ("SMB", "high", "SMB should never be exposed directly to untrusted networks."),
    512: ("rexec", "high", "Legacy rexec is insecure. Disable it."),
    513: ("rlogin", "high", "Legacy rlogin is insecure. Disable it."),
    514: ("rsh", "high", "Legacy rsh is insecure. Disable it."),
    1433: ("Microsoft SQL Server", "high", "Database ports should not be exposed to untrusted networks."),
    1521: ("Oracle Database", "high", "Database ports should not be exposed to untrusted networks."),
    2375: ("Docker API", "critical", "An unauthenticated Docker API gives full host control."),
    2376: ("Docker API (TLS)", "high", "Expose the Docker API only on a protected management network."),
    3306: ("MySQL", "high", "Database ports should not be exposed to untrusted networks."),
    3389: ("RDP", "high", "RDP is a common ransomware entry point. Use VPN, MFA and allow-lists."),
    5432: ("PostgreSQL", "high", "Database ports should not be exposed to untrusted networks."),
    5900: ("VNC", "high", "VNC is often unauthenticated or weakly protected. Tunnel it over SSH/VPN."),
    6379: ("Redis", "critical", "An exposed Redis service is frequently abused for remote code execution."),
    9200: ("Elasticsearch", "high", "Elasticsearch should not be exposed without authentication and TLS."),
    11211: ("Memcached", "high", "Memcached has no authentication and can be abused for amplification."),
    27017: ("MongoDB", "high", "MongoDB should not be exposed to untrusted networks."),
}

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "shell", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "http", 3306: "mysql", 3389: "rdp", 4443: "https", 5000: "http",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 7001: "weblogic", 8000: "http", 8008: "http",
    8080: "http-proxy", 8081: "http", 8443: "https-alt", 8888: "http", 9000: "http",
    9090: "http", 9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb",
}
