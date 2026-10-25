"""Application configuration.

Everything is intentionally local-first.  The only outbound calls are made by
scanners you enable (OSV, CISA KEV, GitHub, or optional CLI tools).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def data_dir() -> Path:
    path = Path(os.getenv("VS_DATA_DIR", BASE_DIR / "data")).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    configured = os.getenv("VS_DATABASE")
    if configured:
        path = Path(configured).expanduser().resolve()
    else:
        path = data_dir() / "vulnscanner.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def reports_dir() -> Path:
    path = data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def clone_dir() -> Path:
    path = data_dir() / "clones"
    path.mkdir(parents=True, exist_ok=True)
    return path


HOST = os.getenv("VS_HOST", "127.0.0.1")
PORT = int(os.getenv("VS_PORT", "8765"))

# Guardrails for scans.
MAX_REPO_BYTES = int(os.getenv("VS_MAX_REPO_BYTES", str(512 * 1024 * 1024)))
MAX_SOURCE_FILE_BYTES = int(os.getenv("VS_MAX_SOURCE_FILE_BYTES", str(1024 * 1024)))
MAX_SCAN_FILES = int(os.getenv("VS_MAX_SCAN_FILES", "20000"))
MAX_CIDR_HOSTS = int(os.getenv("VS_MAX_CIDR_HOSTS", "256"))
AGENT_JOB_TIMEOUT_SECONDS = int(os.getenv("VS_AGENT_JOB_TIMEOUT", str(60 * 60)))
ENABLE_EXTERNAL_APIS = _env_bool("VS_ENABLE_EXTERNAL_APIS", True)

# Optional CLI integrations.  Empty means "look in PATH".
TOOL_PATHS = {
    "nmap": os.getenv("VS_NMAP_PATH", ""),
    "nuclei": os.getenv("VS_NUCLEI_PATH", ""),
    "osv-scanner": os.getenv("VS_OSV_SCANNER_PATH", ""),
    "gitleaks": os.getenv("VS_GITLEAKS_PATH", ""),
    "semgrep": os.getenv("VS_SEMGREP_PATH", ""),
    "git": os.getenv("VS_GIT_PATH", ""),
}

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
