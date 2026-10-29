#!/usr/bin/env python3
"""VulnScanner endpoint agent (Linux, Windows, macOS).

The agent polls the local VulnScanner server for jobs and performs checks on the
endpoint itself, so inbound firewall rules are not required.  It uses only the
Python standard library.

Commands:
    vulnscanner_agent.py enroll --server URL --token TOKEN --name NAME
    vulnscanner_agent.py run
    vulnscanner_agent.py run --once
    vulnscanner_agent.py status
    vulnscanner_agent.py scan --modules system,packages,ports --output result.json
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import getpass
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AGENT_VERSION = "1.1.0"
USER_AGENT = f"VulnScanner-Agent/{AGENT_VERSION}"
DEFAULT_INTERVAL = 30
MAX_NETWORK_HOSTS = 256

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 1433: "mssql",
    1521: "oracle", 2375: "docker", 2376: "docker-tls", 3000: "http",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http", 8080: "http", 8443: "https",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2181, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900,
    5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018,
]
WEB_PORTS = [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
BANNER_PORTS = {
    21, 22, 23, 25, 110, 143, 389, 587, 993, 995, 1433, 1521, 3306, 5432,
    5900, 6379, 9200, 11211, 27017,
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "dist", "build",
    "target", "coverage", ".next", ".nuxt", ".cache", ".idea", ".terraform",
    "vendor", "Pods", "DerivedData", ".gradle", ".m2", "site-packages",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".class", ".exe",
    ".dll", ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".iso", ".img",
    ".pyc", ".pyo", ".o", ".a", ".obj", ".pdb", ".lockb",
}
MAX_FILE_SIZE = 1024 * 1024
MAX_FILES = 20000

SECRET_RULES = [
    ("private-key", "Private key committed to source", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", "AWS access key ID detected", "critical",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token detected", "high",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("gitlab-token", "GitLab token detected", "high",
     re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", "Slack token detected", "high",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", "Stripe live secret key detected", "critical",
     re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("google-api-key", "Google API key detected", "high",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai-key", "OpenAI/Anthropic API key detected", "high",
     re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("database-url", "Database connection string with password", "high",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/@]+:[^@\s/]+@[^\s'\"]+", re.I)),
]
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\n]{12,160})['\"]"
)
PLACEHOLDER_RE = re.compile(
    r"^(?:x+|\*+|\.+|your[-_ ]|example|sample|changeme|change[-_ ]?me|placeholder|"
    r"replace[-_ ]?me|dummy|test(?:ing)?|none|null|true|false|redacted|secret|password|"
    r"insert[-_ ]|todo|fixme|env\(|process\.env|\$\{|<|\{\{|%\().*",
    re.I,
)


def log(message: str) -> None:
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return root / "VulnScanner" / "agent.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "VulnScanner" / "agent.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "vulnscanner" / "agent.json"


def state_dir() -> Path:
    path = config_path().parent
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_config(path: str | None = None) -> dict[str, Any]:
    target = Path(path).expanduser() if path else config_path()
    if not target.exists():
        raise SystemExit(f"No agent configuration at {target}. Run 'enroll' first.")
    return json.loads(target.read_text(encoding="utf-8"))


def save_config(config: dict[str, Any], path: str | None = None) -> Path:
    target = Path(path).expanduser() if path else config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def request_json(
    config: dict[str, Any],
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 45,
) -> dict[str, Any]:
    url = config["server"].rstrip("/") + path
    data = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, default=str).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if config.get("token"):
        headers["X-Agent-Token"] = config["token"]
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(
            req,
            timeout=timeout,
            context=ssl_context(bool(config.get("verify_tls", True))),
        ) as response:
            body = response.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"Server returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc.reason}") from exc


def system_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "os": platform.system(),
        "os_release": platform.release(),
        "version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "agent_version": AGENT_VERSION,
        "user": getpass.getuser(),
        "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    if platform.system() == "Linux":
        try:
            release = {}
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    release[key] = value.strip().strip('"')
            info.update(
                {
                    "distro_id": release.get("ID", "").lower(),
                    "distro_version": release.get("VERSION_ID", ""),
                    "distro_name": release.get("PRETTY_NAME", ""),
                    "kernel": platform.release(),
                }
            )
        except OSError:
            pass
    elif platform.system() == "Windows":
        info["os"] = "Windows"
        info["distro_name"] = f"Windows {platform.release()}"
    elif platform.system() == "Darwin":
        info["distro_id"] = "macos"
        info["distro_name"] = f"macOS {platform.mac_ver()[0]}"
    return info


def run_command(args: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def powershell(script: str, timeout: int = 60) -> str:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    for executable in ("powershell", "pwsh"):
        if shutil.which(executable):
            output = run_command(
                [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                timeout=timeout,
            )
            if output:
                return output
    return ""


# ---------------------------------------------------------------------------
# Package inventory
# ---------------------------------------------------------------------------

def _distro_ecosystem(info: dict[str, Any]) -> str | None:
    distro = (info.get("distro_id") or "").lower()
    version = (info.get("distro_version") or "").strip()
    if not version:
        return None
    major_minor = ".".join(version.split(".")[:2])
    major = version.split(".")[0]
    if distro == "ubuntu":
        return f"Ubuntu:{major_minor}"
    if distro == "debian":
        return f"Debian:{major}"
    if distro == "alpine":
        return f"Alpine:v{major_minor}"
    if distro in {"rhel", "redhat"}:
        return f"Red Hat:{major}"
    if distro == "rocky":
        return f"Rocky Linux:{major}"
    if distro == "almalinux":
        return f"AlmaLinux:{major}"
    if distro in {"opensuse-leap", "opensuse-tumbleweed", "suse", "sles"}:
        return f"openSUSE:{version}"
    return None


def collect_os_packages(info: dict[str, Any]) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    ecosystem = _distro_ecosystem(info) if platform.system() == "Linux" else None
    if not ecosystem:
        return packages
    if shutil.which("dpkg-query"):
        output = run_command(
            [
                "dpkg-query", "-W",
                "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n",
            ],
            timeout=45,
        )
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) < 5 or not parts[1]:
                continue
            name = parts[2] if parts[2] and parts[2] != "(none)" else parts[0]
            version = parts[3] if parts[3] and parts[3] != "(none)" else parts[1]
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "source": "dpkg",
                    "arch": parts[4],
                }
            )
    elif shutil.which("rpm"):
        output = run_command(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
            timeout=45,
        )
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0] and parts[1]:
                packages.append(
                    {
                        "name": parts[0],
                        "version": parts[1],
                        "ecosystem": ecosystem,
                        "source": "rpm",
                        "arch": parts[2] if len(parts) > 2 else "",
                    }
                )
    return packages


def collect_python_packages() -> list[dict[str, Any]]:
    packages = []
    try:
        from importlib import metadata

        seen = set()
        for dist in metadata.distributions():
            try:
                name = dist.metadata.get("Name")
                version = dist.version
            except Exception:
                continue
            if not name or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "source": "python",
                }
            )
    except Exception:
        pass
    return packages


def collect_npm_packages() -> list[dict[str, Any]]:
    npm = shutil.which("npm")
    if not npm:
        return []
    output = run_command([npm, "ls", "-g", "--json", "--depth=0"], timeout=45)
    if not output:
        return []
    try:
        data = json.loads(output)
    except ValueError:
        return []
    packages = []
    for name, item in (data.get("dependencies") or {}).items():
        if isinstance(item, dict) and item.get("version"):
            packages.append(
                {
                    "name": name,
                    "version": str(item["version"]),
                    "ecosystem": "npm",
                    "source": "npm-global",
                }
            )
    return packages


def collect_windows_programs() -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$paths=@(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$items=@()
foreach($p in $paths){ $items += Get-ItemProperty $p | Where-Object {$_.DisplayName} | ForEach-Object { [pscustomobject]@{name=$_.DisplayName;version=$_.DisplayVersion;source='windows-registry'} } }
$items | ConvertTo-Json -Compress
"""
    output = powershell(script, timeout=45)
    if not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
    except ValueError:
        return []
    packages = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and item.get("name") and item.get("version"):
            packages.append(
                {
                    "name": str(item["name"]),
                    "version": str(item["version"]),
                    "ecosystem": "",
                    "source": "windows-registry",
                }
            )
    return packages


def collect_packages(info: dict[str, Any]) -> list[dict[str, Any]]:
    packages = collect_os_packages(info)
    packages.extend(collect_python_packages())
    packages.extend(collect_npm_packages())
    packages.extend(collect_windows_programs())
    deduped = {}
    for package in packages:
        key = (package.get("ecosystem"), package.get("name"), package.get("version"))
        deduped.setdefault(key, package)
    return list(deduped.values())[:6000]


# ---------------------------------------------------------------------------
# Listening ports
# ---------------------------------------------------------------------------

def _port_entry(address: str, port: int, protocol: str, process: str = "", pid: int | None = None) -> dict[str, Any]:
    return {
        "address": address,
        "port": port,
        "protocol": protocol,
        "process": process,
        "pid": pid,
        "service": SERVICE_NAMES.get(port, "unknown"),
    }


def collect_ports() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if platform.system() == "Windows":
        script = r"""
$ErrorActionPreference='SilentlyContinue'
$procs=@{}; Get-Process | ForEach-Object { $procs[$_.Id]=$_.ProcessName }
$out=@()
Get-NetTCPConnection -State Listen | ForEach-Object { $out += [pscustomobject]@{address=$_.LocalAddress;port=[int]$_.LocalPort;protocol='tcp';pid=[int]$_.OwningProcess;process=$procs[[int]$_.OwningProcess]} }
Get-NetUDPEndpoint | ForEach-Object { $out += [pscustomobject]@{address=$_.LocalAddress;port=[int]$_.LocalPort;protocol='udp';pid=[int]$_.OwningProcess;process=$procs[[int]$_.OwningProcess]} }
$out | ConvertTo-Json -Compress
"""
        output = powershell(script, timeout=40)
        if output:
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    if not isinstance(item, dict) or not item.get("port"):
                        continue
                    entries.append(
                        _port_entry(
                            str(item.get("address") or ""),
                            int(item["port"]),
                            str(item.get("protocol") or "tcp"),
                            str(item.get("process") or ""),
                            item.get("pid"),
                        )
                    )
            except (ValueError, TypeError):
                pass
        return entries
    if shutil.which("ss"):
        output = run_command(["ss", "-tulnH"], timeout=20)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            protocol = parts[0].lower()
            local = parts[4]
            address, _, port_text = local.rpartition(":")
            if not port_text.isdigit():
                continue
            entries.append(
                _port_entry(address.strip("[]"), int(port_text), protocol, "", None)
            )
    elif shutil.which("netstat"):
        output = run_command(["netstat", "-tuln"], timeout=20)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 4 or not parts[0].lower().startswith(("tcp", "udp")):
                continue
            local = parts[3]
            address, _, port_text = local.rpartition(":")
            if port_text.isdigit():
                entries.append(
                    _port_entry(address.strip("[]"), int(port_text), parts[0].lower()[:3], "", None)
                )
    seen = set()
    result = []
    for item in entries:
        key = (item["protocol"], item["address"], item["port"])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# Local security baseline
# ---------------------------------------------------------------------------

def check(
    identifier: str,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    remediation: str,
    cwe: str = "",
) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "category": "host",
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "cwe": cwe,
        "location": socket.gethostname(),
        "resource": identifier,
        "key": f"host-check:{identifier}",
        "raw": {"check_id": identifier},
    }


def linux_checks() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    # Additional UID 0 accounts
    try:
        extra_root = []
        for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                extra_root.append(parts[0])
        if extra_root:
            findings.append(
                check(
                    "uid0-accounts",
                    f"Additional UID 0 account(s): {', '.join(extra_root[:5])}",
                    "high",
                    "More than one account has root-level UID 0. This expands the attack surface and weakens accountability.",
                    f"Accounts: {', '.join(extra_root)}",
                    "Remove or change the UID of unnecessary root-equivalent accounts.",
                    "CWE-250",
                )
            )
    except OSError:
        pass

    # SSH configuration
    ssh_config = Path("/etc/ssh/sshd_config")
    if ssh_config.exists():
        try:
            lines = [
                line.strip() for line in ssh_config.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            values = {}
            for line in lines:
                parts = line.split(None, 1)
                if len(parts) == 2:
                    values[parts[0].lower()] = parts[1].strip().lower()
            if values.get("permitrootlogin") in {"yes", "without-password", "prohibit-password"}:
                findings.append(
                    check(
                        "ssh-root-login",
                        "SSH permits direct root login",
                        "medium",
                        "Direct root login over SSH removes accountability and increases the impact of stolen credentials.",
                        f"PermitRootLogin {values.get('permitrootlogin')}",
                        "Set PermitRootLogin no and use sudo from named accounts.",
                        "CWE-250",
                    )
                )
            if values.get("passwordauthentication") == "yes":
                findings.append(
                    check(
                        "ssh-password-auth",
                        "SSH password authentication is enabled",
                        "low",
                        "Password authentication is more susceptible to brute force and credential stuffing than public-key or SSO authentication.",
                        "PasswordAuthentication yes",
                        "Prefer key-based or SSO authentication and restrict SSH to trusted networks.",
                        "CWE-307",
                    )
                )
        except OSError:
            pass

    # Firewall state, only if a known firewall tool is installed.
    ufw = shutil.which("ufw")
    firewalld = shutil.which("firewall-cmd")
    if ufw:
        output = run_command(["ufw", "status"], timeout=10).lower()
        if "status: inactive" in output:
            findings.append(
                check(
                    "firewall-inactive",
                    "Host firewall (ufw) is inactive",
                    "medium",
                    "The local firewall is not filtering inbound traffic.",
                    "ufw status: inactive",
                    "Enable the host firewall and allow only required services.",
                    "CWE-284",
                )
            )
    elif firewalld:
        output = run_command(["firewall-cmd", "--state"], timeout=10).lower()
        if "not running" in output:
            findings.append(
                check(
                    "firewall-inactive",
                    "Host firewall (firewalld) is not running",
                    "medium",
                    "The local firewall is not filtering inbound traffic.",
                    "firewall-cmd --state: not running",
                    "Start and enable firewalld with a minimal rule set.",
                    "CWE-284",
                )
            )

    # SELinux / AppArmor
    selinux = Path("/sys/fs/selinux/enforce")
    if selinux.exists():
        try:
            if selinux.read_text().strip() == "0":
                findings.append(
                    check(
                        "selinux-permissive",
                        "SELinux is in permissive mode",
                        "medium",
                        "SELinux is not enforcing mandatory access controls.",
                        "/sys/fs/selinux/enforce = 0",
                        "Investigate denials and set SELinux to enforcing.",
                        "CWE-693",
                    )
                )
        except OSError:
            pass
    apparmor = Path("/sys/module/apparmor/parameters/enabled")
    if apparmor.exists():
        try:
            if apparmor.read_text().strip().lower() == "n":
                findings.append(
                    check(
                        "apparmor-disabled",
                        "AppArmor is disabled",
                        "low",
                        "An additional mandatory access control layer is unavailable.",
                        "/sys/module/apparmor/parameters/enabled = N",
                        "Enable AppArmor and load profiles for exposed services.",
                        "CWE-693",
                    )
                )
        except OSError:
            pass

    # Docker socket permissions
    docker_socket = Path("/var/run/docker.sock")
    if docker_socket.exists():
        try:
            mode = docker_socket.stat().st_mode & 0o777
            if mode & 0o002:
                findings.append(
                    check(
                        "docker-socket-world-writable",
                        "Docker socket is world-writable",
                        "critical",
                        "Access to the Docker socket is equivalent to root on the host.",
                        f"/var/run/docker.sock mode {oct(mode)}",
                        "Restrict the socket to root and a dedicated docker group, and never expose it to untrusted users.",
                        "CWE-732",
                    )
                )
        except OSError:
            pass

    # Passwordless sudo
    sudo_files = [Path("/etc/sudoers")]
    sudo_dir = Path("/etc/sudoers.d")
    if sudo_dir.is_dir():
        sudo_files.extend(sorted(sudo_dir.glob("*")))
    for sudo_path in sudo_files:
        try:
            if not sudo_path.is_file():
                continue
            content = sudo_path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"NOPASSWD\s*:", content, re.I):
                findings.append(
                    check(
                        "sudo-nopasswd",
                        "Passwordless sudo rule detected",
                        "medium",
                        "A sudo rule allows commands without re-authentication, increasing the impact of a hijacked session.",
                        f"File: {sudo_path}",
                        "Require a password for privileged commands unless there is a documented operational need.",
                        "CWE-521",
                    )
                )
                break
        except OSError:
            continue
    return findings


def windows_checks() -> list[dict[str, Any]]:
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$result=[ordered]@{}
try { $d=Get-MpComputerStatus; $result.defender_enabled=$d.AntivirusEnabled; $result.realtime_enabled=$d.RealTimeProtectionEnabled } catch {}
try { $fw=Get-NetFirewallProfile; $result.firewall_disabled=@($fw | Where-Object {$_.Enabled -eq $false} | Select-Object -ExpandProperty Name) } catch {}
try { $smb=Get-SmbServerConfiguration; $result.smb1=$smb.EnableSMB1Protocol } catch {}
try { $rdp=Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'; $result.rdp_enabled=($rdp.fDenyTSConnections -eq 0) } catch {}
try { $uac=Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; $result.uac_enabled=($uac.EnableLUA -ne 0) } catch {}
try { $g=Get-LocalUser -Name Guest; $result.guest_enabled=$g.Enabled } catch {}
try { $result.secure_boot=(Confirm-SecureBootUEFI) } catch {}
$result | ConvertTo-Json -Compress
"""
    output = powershell(script, timeout=60)
    if not output:
        return []
    try:
        data = json.loads(output)
    except ValueError:
        return []
    findings = []
    if data.get("defender_enabled") is False:
        findings.append(
            check("defender-disabled", "Microsoft Defender antivirus is disabled", "high",
                  "No active Microsoft Defender antivirus protection was reported.",
                  "AntivirusEnabled = false", "Enable Microsoft Defender or an approved EDR product.", "CWE-693")
        )
    if data.get("realtime_enabled") is False:
        findings.append(
            check("defender-realtime", "Microsoft Defender real-time protection is disabled", "high",
                  "Real-time malware protection is not active.",
                  "RealTimeProtectionEnabled = false", "Enable real-time protection and investigate why it was disabled.", "CWE-693")
        )
    disabled = data.get("firewall_disabled") or []
    if isinstance(disabled, str):
        disabled = [disabled]
    if disabled:
        findings.append(
            check("firewall-disabled", "Windows Firewall profile disabled", "high",
                  "One or more Windows Firewall profiles do not filter traffic.",
                  f"Disabled profiles: {', '.join(disabled)}", "Enable all firewall profiles and allow only required ports.", "CWE-284")
        )
    if data.get("smb1") is True:
        findings.append(
            check("smb1-enabled", "SMBv1 is enabled", "high",
                  "SMBv1 is obsolete and has repeatedly been exploited by ransomware and worms.",
                  "EnableSMB1Protocol = true", "Disable SMBv1 and remove dependencies.", "CWE-1104")
        )
    if data.get("rdp_enabled") is True:
        findings.append(
            check("rdp-enabled", "Remote Desktop is enabled", "medium",
                  "RDP is enabled and is a frequent target for credential attacks and ransomware.",
                  "fDenyTSConnections = 0", "Restrict RDP behind VPN/zero-trust access with MFA and network allow-lists.", "CWE-284")
        )
    if data.get("uac_enabled") is False:
        findings.append(
            check("uac-disabled", "User Account Control (UAC) is disabled", "high",
                  "Without UAC, processes run with elevated privileges without consent.",
                  "EnableLUA = 0", "Enable UAC and set it to at least the default level.", "CWE-269")
        )
    if data.get("guest_enabled") is True:
        findings.append(
            check("guest-enabled", "Windows Guest account is enabled", "high",
                  "The built-in Guest account is enabled.", "Guest.Enabled = true",
                  "Disable the Guest account.", "CWE-284")
        )
    if data.get("secure_boot") is False:
        findings.append(
            check("secure-boot-disabled", "Secure Boot is disabled", "low",
                  "Secure Boot helps prevent boot-level tampering.",
                  "Confirm-SecureBootUEFI = false", "Enable Secure Boot if the hardware and OS support it.", "CWE-693")
        )
    return findings


def local_checks() -> list[dict[str, Any]]:
    if platform.system() == "Windows":
        return windows_checks()
    if platform.system() == "Linux":
        return linux_checks()
    return []


# ---------------------------------------------------------------------------
# AD audit
# ---------------------------------------------------------------------------

AD_SCRIPT = r"""
$ErrorActionPreference='Stop'
$WarningPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
function PrivSet {
  param([string[]]$Names)
  $set=New-Object System.Collections.Generic.HashSet[string]
  foreach($n in $Names){ [void]$set.Add($n.ToLower()) }
  return ,$set
}
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $domain = Get-ADDomain
  $forest = Get-ADForest
  $policy = Get-ADDefaultDomainPasswordPolicy
  $now = Get-Date
  $cutoff = $now.AddDays(-90)
  $privGroupNames = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators')
  $privNames = New-Object System.Collections.Generic.HashSet[string]
  $privCounts = [ordered]@{}
  foreach($g in $privGroupNames){
    try {
      $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object {$_.objectClass -eq 'user'} | Select-Object -ExpandProperty SamAccountName)
      $privCounts[$g] = $members.Count
      foreach($m in $members){ [void]$privNames.Add($m.ToLower()) }
    } catch { $privCounts[$g] = 0 }
  }
  $users = @(Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordNeverExpires,ServicePrincipalName,DoesNotRequirePreAuth,AdminCount,PasswordLastSet,whenCreated,TrustedForDelegation)
  $enabled = @($users | Where-Object {$_.Enabled})
  $stale = @($enabled | Where-Object { ($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and $_.whenCreated -lt $cutoff) })
  $stalePriv = @($stale | Where-Object { $privNames.Contains($_.SamAccountName.ToLower()) })
  $never = @($enabled | Where-Object {$_.PasswordNeverExpires})
  $neverPriv = @($never | Where-Object { $privNames.Contains($_.SamAccountName.ToLower()) })
  $kerb = @($enabled | Where-Object { $_.ServicePrincipalName -and $_.ServicePrincipalName.Count -gt 0 })
  $kerbPriv = @($kerb | Where-Object { $privNames.Contains($_.SamAccountName.ToLower()) })
  $asrep = @($enabled | Where-Object {$_.DoesNotRequirePreAuth})
  $asrepPriv = @($asrep | Where-Object { $privNames.Contains($_.SamAccountName.ToLower()) })
  $adminNonPriv = @($enabled | Where-Object { $_.AdminCount -eq 1 -and -not $privNames.Contains($_.SamAccountName.ToLower()) })
  $computers = @(Get-ADComputer -Filter * -Properties Enabled,LastLogonDate,TrustedForDelegation,OperatingSystem)
  $staleComputers = @($computers | Where-Object {$_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff})
  $unconComputers = @($computers | Where-Object {$_.TrustedForDelegation})
  $unconUsers = @($enabled | Where-Object {$_.TrustedForDelegation})
  $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
  $guest = Get-ADUser Guest -Properties Enabled
  $krbtgtAge = if($krbtgt.PasswordLastSet){ [int]($now - $krbtgt.PasswordLastSet).TotalDays } else { $null }
  $recycleEnabled = $false
  try { $rb = Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"'; $recycleEnabled = ($rb.EnabledScopes.Count -gt 0) } catch {}
  $unconNames = @($unconComputers | Select-Object -ExpandProperty Name)
  $unconNames += @($unconUsers | Select-Object -ExpandProperty SamAccountName)
  $report = [ordered]@{
    domain = [ordered]@{
      name = "$($domain.DNSRoot)"
      forest = "$($forest.RootDomain)"
      domain_controller = "$($env:COMPUTERNAME)"
      functional_level = "$($domain.DomainMode)"
      machine_account_quota = $domain.MachineAccountQuota
      recycle_bin_enabled = $recycleEnabled
    }
    password_policy = [ordered]@{
      min_length = $policy.MinPasswordLength
      complexity = $policy.ComplexityEnabled
      lockout_threshold = $policy.LockoutThreshold
      lockout_duration_minutes = $policy.LockoutDuration.TotalMinutes
      max_age_days = if($policy.MaxPasswordAge.TotalDays -gt 0){ [int]$policy.MaxPasswordAge.TotalDays } else { $null }
      history = $policy.PasswordHistoryCount
    }
    krbtgt_password_age_days = $krbtgtAge
    guest_enabled = [bool]$guest.Enabled
    counts = [ordered]@{
      users = $users.Count
      enabled_users = $enabled.Count
      computers = $computers.Count
      groups = 0
    }
    stale_users = [ordered]@{ count = $stale.Count; privileged = $stalePriv.Count; sample = @($stale | Select-Object -First 10 -ExpandProperty SamAccountName) }
    stale_computers = $staleComputers.Count
    never_expires = [ordered]@{ count = $never.Count; privileged = $neverPriv.Count }
    kerberoastable = [ordered]@{ count = $kerb.Count; privileged = $kerbPriv.Count; sample = @($kerb | Select-Object -First 10 -ExpandProperty SamAccountName) }
    asrep_roastable = [ordered]@{ count = $asrep.Count; privileged = $asrepPriv.Count; sample = @($asrep | Select-Object -First 10 -ExpandProperty SamAccountName) }
    unconstrained_delegation = [ordered]@{ count = $unconNames.Count; accounts = @($unconNames | Select-Object -First 20) }
    admin_count = [ordered]@{ count = $adminNonPriv.Count; non_privileged = @($adminNonPriv | Select-Object -First 10 -ExpandProperty SamAccountName) }
    privileged_groups = $privCounts
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    collector = 'VulnScanner Windows agent'
  }
  $report | ConvertTo-Json -Depth 10 -Compress
} catch {
  @{ _error = $_.Exception.Message } | ConvertTo-Json -Compress
}
"""


def collect_ad() -> tuple[dict[str, Any] | None, str]:
    if platform.system() != "Windows":
        return None, "Active Directory audits require Windows with the RSAT ActiveDirectory PowerShell module"
    output = powershell(AD_SCRIPT, timeout=300)
    if not output:
        return None, "PowerShell did not return an Active Directory report"
    try:
        data = json.loads(output)
    except ValueError:
        return None, f"Could not parse AD report: {output[:300]}"
    if not isinstance(data, dict):
        return None, "Active Directory report had an unexpected format"
    if data.get("_error"):
        return None, str(data["_error"])
    return data, ""


# ---------------------------------------------------------------------------
# Secret and repository scanning
# ---------------------------------------------------------------------------

def _safe_text(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        if path.stat().st_size > MAX_FILE_SIZE:
            return ""
        if path.suffix.lower() in BINARY_SUFFIXES:
            return ""
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            return ""
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _walk_files(root: Path, max_files: int = MAX_FILES):
    count = 0
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink()]
        for name in files:
            path = Path(current) / name
            if path.is_symlink() or path.suffix.lower() in BINARY_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * max(4, len(value) - 8) + value[-4:]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    import math
    return -sum((c / len(value)) * math.log2(c / len(value)) for c in counts.values())


def scan_secret_files(paths: list[str]) -> tuple[list[dict[str, Any]], list[str], int]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    files = 0
    seen = set()
    for raw_path in paths:
        root = Path(raw_path).expanduser()
        if not root.exists():
            errors.append(f"Path does not exist: {raw_path}")
            continue
        for path in _walk_files(root):
            text = _safe_text(path)
            if not text:
                continue
            files += 1
            try:
                display = str(path.relative_to(root if root.is_dir() else root.parent))
            except ValueError:
                display = str(path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if len(line) > 4000:
                    continue
                for rule_id, title, severity, pattern in SECRET_RULES:
                    for match in pattern.finditer(line):
                        key = (rule_id, str(path), line_no)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            {
                                "severity": severity,
                                "title": title,
                                "category": "secret",
                                "description": "A credential pattern was found in a file on this endpoint.",
                                "evidence": f"{display}:{line_no}\nMatch: {_redact(match.group(0))}",
                                "remediation": "Remove the secret, rotate it, and store credentials in a secrets manager.",
                                "cwe": "CWE-798",
                                "location": f"{display}:{line_no}",
                                "resource": display,
                                "key": f"secret:{rule_id}",
                                "raw": {"rule": rule_id, "line": line_no, "preview": _redact(match.group(0))},
                            }
                        )
                match = GENERIC_SECRET_RE.search(line)
                if match:
                    key_name, value = match.group(1), match.group(2)
                    if len(value) >= 12 and not PLACEHOLDER_RE.match(value) and _entropy(value) > 3.0:
                        key = ("generic-secret", str(path), line_no)
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                {
                                    "severity": "high",
                                    "title": f"Possible hard-coded secret ({key_name})",
                                    "category": "secret",
                                    "description": "A high-entropy credential-like value was found. Confirm whether it is live.",
                                    "evidence": f"{display}:{line_no}\nVariable: {key_name}\nMatch: {_redact(value)}",
                                    "remediation": "Remove the secret, rotate it, and load it from a secure secret store.",
                                    "cwe": "CWE-798",
                                    "location": f"{display}:{line_no}",
                                    "resource": display,
                                    "key": "secret:generic",
                                    "raw": {"rule": "generic-secret", "line": line_no, "preview": _redact(value)},
                                }
                            )
                if len(findings) >= 500:
                    return findings, errors, files
    return findings, errors, files


# ---------------------------------------------------------------------------
# Manifest inventory for local paths
# ---------------------------------------------------------------------------

def collect_manifest_packages(paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    packages: list[dict[str, Any]] = []
    errors: list[str] = []
    names = {
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "requirements.txt",
        "pyproject.toml", "Pipfile.lock", "poetry.lock", "go.mod", "composer.lock",
        "Gemfile.lock", "Cargo.lock", "pom.xml",
    }
    for raw_path in paths:
        root = Path(raw_path).expanduser()
        if not root.exists():
            errors.append(f"Path does not exist: {raw_path}")
            continue
        for path in _walk_files(root, max_files=5000):
            if path.name not in names and path.suffix.lower() != ".csproj":
                continue
            try:
                text = _safe_text(path)
                if not text:
                    continue
                found = _parse_manifest_text(path.name, text)
                for item in found:
                    item["source"] = str(path)
                packages.extend(found)
            except Exception as exc:
                errors.append(f"Could not parse {path}: {exc}")
    deduped = {}
    for package in packages:
        key = (package.get("ecosystem"), package.get("name"), package.get("version"))
        deduped.setdefault(key, package)
    return list(deduped.values())[:6000], errors


def _safe_xml_fromstring(text: str):
    if re.search(r"<!DOCTYPE|<!ENTITY", text or "", re.IGNORECASE):
        raise ValueError("XML with DTD or entity declarations is not accepted")
    import xml.etree.ElementTree as ET

    return ET.fromstring(text)


def _parse_manifest_text(name: str, text: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(text)
        for key, item in (data.get("packages") or {}).items():
            if not isinstance(item, dict) or item.get("link") or not item.get("version"):
                continue
            package_name = item.get("name") or (key.rsplit("node_modules/", 1)[-1] if key else "")
            if package_name:
                packages.append({"name": package_name, "version": str(item["version"]), "ecosystem": "npm", "source": "package-lock.json"})
    elif name == "package.json":
        data = json.loads(text)
        for section in ("dependencies", "devDependencies"):
            for package_name, version in (data.get(section) or {}).items():
                value = str(version).lstrip("=~^<> ")
                if re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?", value):
                    packages.append({"name": package_name, "version": value, "ecosystem": "npm", "source": "package.json"})
    elif name == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)", line)
            if match:
                packages.append({"name": re.sub(r"[-_.]+", "-", match.group(1)).lower(), "version": match.group(2), "ecosystem": "PyPI", "source": "requirements.txt"})
    elif name in {"pyproject.toml", "poetry.lock", "Cargo.lock"}:
        try:
            import tomllib
            data = tomllib.loads(text)
        except Exception:
            return packages
        if name == "pyproject.toml":
            specs = list((data.get("project") or {}).get("dependencies") or [])
            for group in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
                specs.extend(group or [])
            for spec in specs:
                match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)", str(spec))
                if match:
                    packages.append({"name": re.sub(r"[-_.]+", "-", match.group(1)).lower(), "version": match.group(2), "ecosystem": "PyPI", "source": "pyproject.toml"})
        elif name == "poetry.lock":
            for item in data.get("package") or []:
                if item.get("name") and item.get("version"):
                    packages.append({"name": re.sub(r"[-_.]+", "-", str(item["name"])).lower(), "version": str(item["version"]), "ecosystem": "PyPI", "source": "poetry.lock"})
        else:
            for item in data.get("package") or []:
                if item.get("name") and item.get("version"):
                    packages.append({"name": str(item["name"]), "version": str(item["version"]), "ecosystem": "crates.io", "source": "Cargo.lock"})
    elif name == "Pipfile.lock":
        data = json.loads(text)
        for section in ("default", "develop"):
            for package_name, item in (data.get(section) or {}).items():
                if isinstance(item, dict) and item.get("version"):
                    packages.append({"name": re.sub(r"[-_.]+", "-", package_name).lower(), "version": str(item["version"]).lstrip("= "), "ecosystem": "PyPI", "source": "Pipfile.lock"})
    elif name == "go.mod":
        for line in text.splitlines():
            match = re.match(r"^(?:require\s+)?([\w.\-/]+)\s+(v[\w.+-]+)$", line.split("//", 1)[0].strip())
            if match:
                packages.append({"name": match.group(1), "version": match.group(2), "ecosystem": "Go", "source": "go.mod"})
    elif name == "composer.lock":
        data = json.loads(text)
        for item in data.get("packages") or []:
            if item.get("name") and item.get("version"):
                packages.append({"name": item["name"], "version": str(item["version"]).lstrip("v"), "ecosystem": "Packagist", "source": "composer.lock"})
    elif name == "Gemfile.lock":
        in_specs = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and line and not line.startswith(" "):
                in_specs = False
            if in_specs:
                match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
                if match:
                    packages.append({"name": match.group(1), "version": match.group(2), "ecosystem": "RubyGems", "source": "Gemfile.lock"})
    elif name == "pom.xml":
        root = _safe_xml_fromstring(text)
        ns = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
        for dep in root.iter(f"{ns}dependency"):
            group = dep.findtext(f"{ns}groupId") or ""
            artifact = dep.findtext(f"{ns}artifactId") or ""
            version = (dep.findtext(f"{ns}version") or "").strip()
            if group and artifact and version and "${" not in version:
                packages.append({"name": f"{group}:{artifact}", "version": version, "ecosystem": "Maven", "source": "pom.xml"})
    elif name.endswith(".csproj"):
        root = _safe_xml_fromstring(text)
        for element in root.iter():
            if element.tag.endswith("PackageReference"):
                package_name = element.attrib.get("Include")
                version = element.attrib.get("Version")
                if package_name and version and "$(" not in version:
                    packages.append({"name": package_name, "version": version, "ecosystem": "NuGet", "source": name})
    return packages


# ---------------------------------------------------------------------------
# Delegated network scans
# ---------------------------------------------------------------------------

def agent_parse_ports(value: str | None, profile: str = "common") -> list[int]:
    if value:
        named = value.strip().lower()
        if named in {"web", "common", "top1000", "all"}:
            return agent_parse_ports(None, named)
        ports: set[int] = set()
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = (int(item) for item in part.split("-", 1))
                except ValueError as exc:
                    raise ValueError(f"Invalid port range: {part}") from exc
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                if end - start > 5000:
                    raise ValueError("Port ranges are limited to 5000 ports")
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
        return list(WEB_PORTS)
    return list(TOP_PORTS)


def agent_expand_targets(target: str) -> list[str]:
    target = (target or "").strip()
    if not target:
        raise ValueError("A network scan target is required")
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > MAX_NETWORK_HOSTS:
            raise ValueError(
                f"Network contains {network.num_addresses} addresses; "
                f"limit is {MAX_NETWORK_HOSTS}"
            )
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(host) for host in network.hosts()]
    if re.search(r"[\s/\\]", target):
        raise ValueError("Host target may not contain whitespace or slashes")
    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host {target}: {exc}") from exc
    return [target]


def _probe_network_port(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            if port in BANNER_PORTS:
                sock.settimeout(min(timeout, 0.8))
                try:
                    raw = sock.recv(512)
                    banner = raw.decode("utf-8", errors="replace")
                    banner = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", banner)[:500]
                except (socket.timeout, OSError):
                    banner = ""
            return {
                "host": host,
                "port": port,
                "service": SERVICE_NAMES.get(port, "unknown"),
                "banner": banner,
            }
    except (OSError, socket.timeout):
        return None


def _collect_probe(future: concurrent.futures.Future, open_ports: list[dict[str, Any]]) -> None:
    try:
        item = future.result()
    except Exception:
        return
    if item:
        open_ports.append(item)


def collect_network(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a TCP connect scan from this endpoint's network position."""
    options = options or {}
    hosts = agent_expand_targets(target)
    ports = agent_parse_ports(str(options.get("ports") or "") or None, str(options.get("profile") or "common"))
    try:
        timeout = float(options.get("connect_timeout", 0.45))
    except (TypeError, ValueError):
        timeout = 0.45
    timeout = max(0.1, min(timeout, 3.0))
    try:
        workers = int(options.get("workers", 300))
    except (TypeError, ValueError):
        workers = 300
    workers = max(10, min(workers, 600))
    started = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    open_ports: list[dict[str, Any]] = []
    pending: set[concurrent.futures.Future] = set()
    # Keep a bounded number of futures in flight. A large CIDR with the "all"
    # profile can represent millions of host/port pairs; submitting them all at
    # once would exhaust memory on an endpoint.
    window = max(workers * 4, 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for host in hosts:
            for port in ports:
                pending.add(executor.submit(_probe_network_port, host, port, timeout))
                if len(pending) >= window:
                    done, pending = concurrent.futures.wait(
                        pending, return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for future in done:
                        _collect_probe(future, open_ports)
        for future in concurrent.futures.as_completed(pending):
            _collect_probe(future, open_ports)
    open_ports.sort(key=lambda item: (item["host"], item["port"]))
    return {
        "target": target,
        "hosts": hosts[:500],
        "host_count": len(hosts),
        "ports_scanned": len(ports),
        "open_ports": open_ports[:5000],
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


# ---------------------------------------------------------------------------
# Job execution
# ---------------------------------------------------------------------------

def capabilities() -> list[str]:
    caps = ["system", "packages", "ports", "network", "secrets", "repo"]
    if platform.system() == "Windows":
        caps.append("ad")
    return caps


def collect_job(job: dict[str, Any], stop_event=None) -> dict[str, Any]:
    payload = job.get("payload") or {}
    modules = payload.get("modules") or ["system", "packages", "ports"]
    paths = payload.get("paths") or []
    options = payload.get("options") or {}
    network_target = payload.get("target") or options.get("target") or ""
    info = system_info()
    result: dict[str, Any] = {
        "system": info,
        "packages": [],
        "listening_ports": [],
        "secrets": [],
        "checks": [],
        "source_findings": [],
        "modules": modules,
        "agent_version": AGENT_VERSION,
    }
    errors: list[str] = []
    if "system" in modules:
        try:
            result["checks"] = local_checks()
        except Exception as exc:
            errors.append(f"System checks failed: {exc}")
    if "packages" in modules:
        try:
            result["packages"] = collect_packages(info)
        except Exception as exc:
            errors.append(f"Package inventory failed: {exc}")
    if "ports" in modules:
        try:
            result["listening_ports"] = collect_ports()
        except Exception as exc:
            errors.append(f"Port inventory failed: {exc}")
    if "network" in modules:
        try:
            result["network"] = collect_network(str(network_target), options)
        except Exception as exc:
            errors.append(f"Network scan failed: {exc}")
    if "secrets" in modules or "repo" in modules:
        if not paths:
            errors.append("Secrets/repository modules requested without paths")
        else:
            try:
                findings, path_errors, files = scan_secret_files(paths)
                result["secrets"].extend(findings)
                errors.extend(path_errors)
                result["files_scanned"] = files
            except Exception as exc:
                errors.append(f"Secret scan failed: {exc}")
    if "repo" in modules and paths:
        try:
            packages, path_errors = collect_manifest_packages(paths)
            result["packages"].extend(packages)
            errors.extend(path_errors)
        except Exception as exc:
            errors.append(f"Repository inventory failed: {exc}")
    if "ad" in modules:
        try:
            ad_report, ad_error = collect_ad()
            if ad_report:
                result["ad"] = ad_report
            if ad_error:
                result["ad_error"] = ad_error
                errors.append(ad_error)
        except Exception as exc:
            result["ad_error"] = str(exc)
            errors.append(f"Active Directory audit failed: {exc}")
    if errors:
        result["warnings"] = errors
        result["error"] = "; ".join(errors[:10])
    return result


def heartbeat(config: dict[str, Any]) -> dict[str, Any]:
    info = system_info()
    return request_json(
        config,
        "POST",
        "/api/agent/heartbeat",
        {
            "platform": platform.system(),
            "version": AGENT_VERSION,
            "hostname": info.get("hostname", ""),
            "capabilities": capabilities(),
        },
        timeout=20,
    )


def send_result(config: dict[str, Any], job_id: str, result: dict[str, Any], status: str = "completed", error: str = "") -> None:
    request_json(
        config,
        "POST",
        f"/api/agent/jobs/{job_id}/result",
        {"status": status, "results": result, "error": error},
        timeout=120,
    )


def pending_path() -> Path:
    return state_dir() / "pending-result.json"


def save_pending(job_id: str, result: dict[str, Any], status: str, error: str) -> None:
    pending_path().write_text(
        json.dumps({"job_id": job_id, "result": result, "status": status, "error": error}),
        encoding="utf-8",
    )


def retry_pending(config: dict[str, Any]) -> bool:
    path = pending_path()
    if not path.exists():
        return True
    try:
        pending = json.loads(path.read_text(encoding="utf-8"))
        send_result(config, pending["job_id"], pending.get("result") or {}, pending.get("status", "completed"), pending.get("error", ""))
        path.unlink(missing_ok=True)
        log(f"Uploaded previously pending result for job {pending['job_id']}")
        return True
    except Exception as exc:
        log(f"Pending result still cannot be uploaded: {exc}")
        return False


def run_once(config: dict[str, Any]) -> bool:
    try:
        heartbeat(config)
    except Exception as exc:
        log(f"Heartbeat failed: {exc}")
        return False
    retry_pending(config)
    try:
        response = request_json(config, "POST", "/api/agent/jobs/next", {}, timeout=30)
    except Exception as exc:
        log(f"Could not fetch job: {exc}")
        return False
    job = response.get("job")
    if not job:
        return False
    job_id = job["id"]
    log(f"Starting job {job_id} (scan #{job.get('scan_id')})")
    try:
        result = collect_job(job)
        warnings = result.get("warnings") or []
        modules = (job.get("payload") or {}).get("modules") or []
        if result.get("error") and "network" in modules and not result.get("network"):
            raise RuntimeError(result["error"])
        if result.get("error") and result.get("ad_error") and len(warnings) == 1:
            # AD-only failure should be a failed job with a clear error.
            raise RuntimeError(result["error"])
        send_result(config, job_id, result, "completed")
        log(f"Job {job_id} completed")
    except Exception as exc:
        message = f"{exc.__class__.__name__}: {exc}"
        log(f"Job {job_id} failed: {message}")
        try:
            send_result(config, job_id, {"error": message}, "failed", message[:3000])
        except Exception as upload_exc:
            log(f"Could not upload failure: {upload_exc}")
            save_pending(job_id, {"error": message}, "failed", message[:3000])
    return True


def run_loop(config: dict[str, Any], interval: int, once: bool = False) -> int:
    log(f"VulnScanner agent {AGENT_VERSION} starting; server={config['server']} name={config.get('name', '')}")
    if once:
        run_once(config)
        return 0
    while True:
        try:
            did_work = run_once(config)
            time.sleep(2 if did_work else interval)
        except KeyboardInterrupt:
            log("Stopping agent")
            return 0
        except Exception as exc:
            log(f"Agent loop error: {exc}")
            time.sleep(min(interval * 2, 120))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _normalize_server(server: str) -> str:
    server = (server or "").strip().rstrip("/")
    if not server.startswith(("http://", "https://")):
        raise SystemExit("--server must start with http:// or https://")
    return server


def command_enroll(args: argparse.Namespace) -> int:
    server = _normalize_server(args.server)
    verify = not args.insecure
    if getattr(args, "verify_tls", False):
        verify = True
    info = system_info()
    temp_config = {"server": server, "token": None, "verify_tls": verify}
    log(f"Enrolling with {server} as {args.name or info['hostname']}…")
    try:
        response = request_json(
            temp_config,
            "POST",
            "/api/agent/enroll",
            {
                "enrollment_token": args.token,
                "name": args.name or "",
                "platform": platform.system(),
                "version": AGENT_VERSION,
                "hostname": info.get("hostname", ""),
                "capabilities": capabilities(),
            },
            timeout=30,
        )
    except Exception as exc:
        raise SystemExit(f"Enrollment failed: {exc}") from exc
    config = {
        "server": server,
        "token": response["token"],
        "agent_id": response["agent_id"],
        "name": response["name"],
        "customer_id": response.get("customer_id"),
        "group_id": response.get("group_id"),
        "asset_id": response.get("asset_id"),
        "verify_tls": verify,
        "enrolled_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "poll_interval": int(args.poll_interval or response.get("poll_interval", DEFAULT_INTERVAL)),
        "agent_kind": "python",
    }
    target = save_config(config, args.config)
    log(f"Enrolled as agent {response['agent_id']} ({response['name']})")
    log(f"Configuration saved to {target}")
    log("Start the agent with: python3 vulnscanner_agent.py run")
    return 0


def command_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    interval = args.interval or int(config.get("poll_interval") or DEFAULT_INTERVAL)
    return run_loop(config, interval, once=args.once)


def command_status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(json.dumps({key: value for key, value in config.items() if key != "token"}, indent=2))
    try:
        result = heartbeat(config)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"Server unreachable: {exc}")
        return 1


def command_update_token(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    new_token = (args.token or "").strip()
    if not new_token.startswith("vs_agent_"):
        raise SystemExit("That does not look like an agent token")
    config["token"] = new_token
    target = save_config(config, args.config)
    log(f"Updated the agent token in {target}")
    log("Restart the agent service so the running process uses the new token.")
    return 0


def command_configure(args: argparse.Namespace) -> int:
    """Update an existing agent configuration without re-enrolling."""
    target = Path(args.config).expanduser() if args.config else config_path()
    if target.exists():
        try:
            config = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Could not read {target}: {exc}") from exc
    else:
        config = {}
    if args.server:
        config["server"] = _normalize_server(args.server)
    if args.name:
        config["name"] = args.name.strip()
    if args.poll_interval:
        config["poll_interval"] = max(5, min(int(args.poll_interval), 3600))
    if args.insecure:
        config["verify_tls"] = False
    elif args.verify_tls:
        config["verify_tls"] = True
    if args.token:
        new_token = args.token.strip()
        if not new_token.startswith("vs_agent_"):
            raise SystemExit("That does not look like an agent token")
        config["token"] = new_token
    if not config.get("server"):
        raise SystemExit("--server is required when creating a new configuration")
    saved = save_config(config, args.config)
    log(f"Updated agent configuration at {saved}")
    if not config.get("token"):
        log("No agent token is configured yet. Enroll the agent before starting it.")
    return 0


def command_scan(args: argparse.Namespace) -> int:
    modules = [item.strip() for item in args.modules.split(",") if item.strip()]
    job = {
        "payload": {
            "modules": modules,
            "paths": args.path or [],
            "target": args.target or "",
            "options": {"ports": args.ports} if args.ports else {},
        }
    }
    result = collect_job(job)
    output = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        log(f"Wrote result to {args.output}")
    else:
        print(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScanner endpoint agent")
    parser.add_argument("--config", help="Path to agent configuration")
    sub = parser.add_subparsers(dest="command", required=True)

    enroll = sub.add_parser("enroll", help="Enroll this endpoint with a VulnScanner server")
    enroll.add_argument("--server", required=True, help="Server URL, e.g. http://127.0.0.1:8765")
    enroll.add_argument("--token", required=True, help="One-time enrollment token")
    enroll.add_argument("--name", default="", help="Friendly agent name")
    tls = enroll.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true", help="Do not verify the server TLS certificate")
    tls.add_argument("--verify-tls", action="store_true", help="Verify the server TLS certificate (default)")
    enroll.add_argument("--poll-interval", type=int, default=0, help="Seconds between polls")
    enroll.set_defaults(func=command_enroll)

    run = sub.add_parser("run", help="Poll the server and execute scan jobs")
    run.add_argument("--once", action="store_true", help="Process at most one poll and exit")
    run.add_argument("--interval", type=int, default=0, help="Seconds between polls")
    run.set_defaults(func=command_run)

    status = sub.add_parser("status", help="Show configuration and heartbeat")
    status.set_defaults(func=command_status)

    update_token = sub.add_parser(
        "update-token", help="Replace the agent token after rotating it in the server UI"
    )
    update_token.add_argument("--token", required=True, help="New agent token")
    update_token.set_defaults(func=command_update_token)

    configure = sub.add_parser(
        "configure", help="Change server URL, name, TLS or poll interval after installation"
    )
    configure.add_argument("--server", default="", help="VulnScanner server URL")
    configure.add_argument("--name", default="", help="Friendly agent name")
    configure.add_argument("--token", default="", help="Updated agent token")
    configure.add_argument("--poll-interval", type=int, default=0, help="Seconds between polls")
    configure_tls = configure.add_mutually_exclusive_group()
    configure_tls.add_argument("--insecure", action="store_true", help="Do not verify TLS")
    configure_tls.add_argument("--verify-tls", action="store_true", help="Verify TLS")
    configure.set_defaults(func=command_configure)

    scan = sub.add_parser("scan", help="Run modules locally (without a server) and print JSON")
    scan.add_argument("--modules", default="system,packages,ports", help="Comma-separated modules")
    scan.add_argument("--path", action="append", help="Path for secrets/repo modules (repeatable)")
    scan.add_argument("--target", default="", help="Network target for the network module")
    scan.add_argument("--ports", default="", help="Custom ports for the network module")
    scan.add_argument("--output", help="Write JSON to this file")
    scan.set_defaults(func=command_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
