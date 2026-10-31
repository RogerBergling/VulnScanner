"""Authenticated inventory and vulnerability checks over SSH and WinRM.

The scanner authenticates once per host and operating system. There is no
retry loop: a rejected password or key is reported and the scan moves on. This
is deliberate so a misconfigured scan cannot lock out a domain or local
account.

Linux hosts are inspected over SSH (paramiko). Windows hosts are inspected over
WinRM (pywinrm). Both collectors run read-only commands and return an inventory
that is converted into findings. Linux package versions are matched against
OSV.dev when external API access is enabled; the same OSV cache used by the
repository scanner is reused.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from typing import Any

from ..config import DANGEROUS_PORTS, ENABLE_EXTERNAL_APIS, ssh_known_hosts_path
from ..credentials import CredentialError, resolve_for_scan
from ..database import get_setting
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult

MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 4000
MAX_SOFTWARE = 3000
MAX_AUTH_HOSTS = 32
DEFAULT_AUTH_TIMEOUT = 15

SSH_PORTS = {22}
WINRM_PORTS = {5985, 5986}
WINDOWS_INDICATORS = {135, 139, 445, 3389, 5985, 5986}

ECOSYSTEMS = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "alpine": "Alpine",
    "rhel": "Red Hat",
    "centos": "Red Hat",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "ol": "Red Hat",
    "opensuse-leap": "openSUSE",
    "opensuse-tumbleweed": "openSUSE",
    "sles": "SUSE",
    "sled": "SUSE",
}

# Conservative end-of-support dates used for a local EOL check. The dates are
# the published vendor end-of-life (or end-of-standard-support) dates.
EOL_LINUX = {
    ("ubuntu", "14.04"): "2019-04-30",
    ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-04-30",
    ("ubuntu", "24.04"): "2029-04-30",
    ("debian", "9"): "2022-06-30",
    ("debian", "10"): "2024-06-30",
    ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30",
    ("debian", "13"): "2030-06-30",
    ("centos", "6"): "2020-11-30",
    ("centos", "7"): "2024-06-30",
    ("centos", "8"): "2021-12-31",
    ("rhel", "6"): "2020-11-30",
    ("rhel", "7"): "2024-06-30",
    ("rhel", "8"): "2029-05-31",
    ("rhel", "9"): "2032-05-31",
    ("almalinux", "8"): "2029-05-31",
    ("rocky", "8"): "2029-05-31",
    ("alpine", "3.14"): "2023-05-01",
    ("alpine", "3.15"): "2023-11-01",
    ("alpine", "3.16"): "2024-05-23",
    ("alpine", "3.17"): "2024-11-22",
    ("alpine", "3.18"): "2025-05-09",
    ("alpine", "3.19"): "2025-11-01",
    ("alpine", "3.20"): "2026-04-01",
    ("alpine", "3.21"): "2026-11-01",
    ("opensuse-leap", "15.4"): "2023-12-07",
    ("opensuse-leap", "15.5"): "2024-12-31",
    ("opensuse-leap", "15.6"): "2025-12-31",
}

WINDOWS_EOL = [
    (r"windows server 2008(?! r2)", "2020-01-14", "critical"),
    (r"windows server 2008 r2", "2020-01-14", "critical"),
    (r"windows 7", "2020-01-14", "critical"),
    (r"windows server 2012(?! r2)", "2023-10-10", "high"),
    (r"windows server 2012 r2", "2023-10-10", "high"),
    (r"windows 8(\.1)?", "2023-01-10", "high"),
    (r"windows 10", "2025-10-14", "critical"),
]

EOL_SOFTWARE = [
    (r"internet explorer", "Internet Explorer", "critical", "Remove Internet Explorer and use a supported browser."),
    (r"adobe flash", "Adobe Flash", "critical", "Uninstall Adobe Flash; it is end-of-life and unsupported."),
    (r"microsoft silverlight", "Microsoft Silverlight", "high", "Remove Silverlight or upgrade to a supported platform."),
    (r"python 2(\.|$)", "Python 2", "high", "Upgrade Python 2 applications to Python 3."),
    (r"apache tomcat (6|7)(\.|$)", "Apache Tomcat 6/7", "high", "Upgrade Apache Tomcat to a supported release."),
    (r"openssl 1\.0", "OpenSSL 1.0", "high", "Upgrade software that bundles OpenSSL 1.0."),
    (r"microsoft sql server (2008|2012|2014)", "SQL Server 2008/2012/2014", "high", "Upgrade SQL Server to a supported version."),
]

LINUX_SCRIPT = r"""
set +e
echo "===VS:OS==="
if [ -r /etc/os-release ]; then cat /etc/os-release; fi
uname -srm
id -un
echo "===VS:PACKAGES==="
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' 2>/dev/null | awk -F'\t' '$3 ~ /^ii/ {print $1"\t"$2}'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | awk '{line=$0; name=line; sub(/-[0-9][^-]*-r[0-9]+$/, "", name); version=line; sub("^" name "-", "", version); print name"\t"version}'
fi
echo "===VS:UPDATES==="
if command -v apt-get >/dev/null 2>&1; then
  LC_ALL=C apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | awk '/^Inst / {print $2}' | head -200
elif command -v dnf >/dev/null 2>&1; then
  LC_ALL=C dnf -q check-update 2>/dev/null | awk '/^[A-Za-z0-9]/ {print $1}' | head -200
elif command -v yum >/dev/null 2>&1; then
  LC_ALL=C yum -q check-update 2>/dev/null | awk '/^[A-Za-z0-9]/ {print $1}' | head -200
elif command -v zypper >/dev/null 2>&1; then
  LC_ALL=C zypper -q lu 2>/dev/null | awk -F'|' '/^v[[:space:]]*\|/ {gsub(/ /,"",$3); print $3}' | head -200
elif command -v apk >/dev/null 2>&1; then
  apk version -l '<' 2>/dev/null | awk 'NR>1 {print $1}' | head -200
fi
echo "===VS:REBOOT==="
if [ -f /var/run/reboot-required ]; then echo yes; cat /var/run/reboot-required 2>/dev/null; else echo no; fi
echo "===VS:PORTS==="
if command -v ss >/dev/null 2>&1; then
  ss -tulpn 2>/dev/null | head -500
elif command -v netstat >/dev/null 2>&1; then
  netstat -tulpn 2>/dev/null | head -500
fi
echo "===VS:PASSWD==="
(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null) | head -2000
echo "===VS:GROUPS==="
(getent group sudo 2>/dev/null || true)
(getent group wheel 2>/dev/null || true)
grep -Rhs 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -50
echo "===VS:SSHD==="
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|maxauthtries|protocol)' | head -20
fi
grep -Eis '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|MaxAuthTries)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -20
echo "===VS:FIREWALL==="
(ufw status 2>/dev/null || true)
(firewall-cmd --state 2>/dev/null || true)
(systemctl is-active firewalld 2>/dev/null || true)
(systemctl is-active nftables 2>/dev/null || true)
(nft list ruleset 2>/dev/null | head -20 || true)
(iptables -S 2>/dev/null | head -20 || true)
echo "===VS:KERNEL==="
uname -r
echo "===VS:END==="
"""

WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function Get-Safe([scriptblock]$Block) { try { & $Block } catch { $null } }
$out = [ordered]@{}
$out.os = Get-Safe { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime }
$out.computer = Get-Safe { Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model,PartOfDomain }
$out.hotfixes = @(Get-Safe { Get-HotFix | Select-Object HotFixID,Description,InstalledOn })
$out.software = @(Get-Safe {
  Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher
})
$out.users = @(Get-Safe { Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,Description })
$out.admins = @(Get-Safe {
  try { Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,ObjectClass,PrincipalSource }
  catch { Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource }
})
$out.ports = @(Get-Safe { Get-NetTCPConnection -State Listen | Select-Object -First 2000 LocalAddress,LocalPort,OwningProcess })
$out.services = @(Get-Safe { Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1000 Name,DisplayName })
$out.defender = Get-Safe { Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,NISEnabled }
$out.firewall = @(Get-Safe { Get-NetFirewallProfile | Select-Object Name,Enabled })
$out.smb = Get-Safe { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature }
$out.rdp = Get-Safe { Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' | Select-Object fDenyTSConnections }
$out.rdp_nla = Get-Safe { Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select-Object UserAuthentication,SecurityLayer }
$out.uac = Get-Safe { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,FilterAdministratorToken }
$out.autologon = Get-Safe { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object AutoAdminLogon,DefaultUserName,DefaultDomainName }
$out.always_install = Get-Safe { Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' | Select-Object AlwaysInstallElevated }
$out.winrm = @(Get-Safe { Get-ChildItem WSMan:\localhost\Service\Auth\* | Select-Object Name,Value })
$out.ps_logging = Get-Safe { Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' | Select-Object EnableScriptBlockLogging }
$out.unquoted = @(Get-Safe {
  Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match '\s' } |
    Select-Object -First 200 Name,PathName,StartMode
})
$out.password_policy = Get-Safe { (net accounts 2>$null) -join "`n" }
$out | ConvertTo-Json -Depth 8 -Compress
"""


class AuthFailed(RuntimeError):
    """Authentication was rejected. The scanner must not retry."""


class ConnectionFailed(RuntimeError):
    """The service could not be reached or the collector failed."""


def _paramiko():
    try:
        import paramiko

        return paramiko
    except ImportError:
        return None


def _winrm():
    try:
        import winrm

        return winrm
    except ImportError:
        return None


def _int_option(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, parsed))


def _float_option(value: Any, default: float, low: float, high: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, parsed))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean(value: Any, limit: int = 300) -> str:
    return truncate(str(value or ""), limit)


def _sanitize_error(message: str, secret: str) -> str:
    text = truncate(message, 500)
    if secret:
        text = text.replace(secret, "[redacted]")
    return text


def _port_numbers(ports: list[Any]) -> set[int]:
    result = set()
    for item in ports:
        port = getattr(item, "port", None)
        if port is None and isinstance(item, dict):
            port = item.get("port")
        try:
            result.add(int(port))
        except (TypeError, ValueError):
            continue
    return result


def _banner_text(ports: list[Any]) -> str:
    banners = []
    for item in ports:
        banner = getattr(item, "banner", "")
        if not banner and isinstance(item, dict):
            banner = item.get("banner", "")
        if banner:
            banners.append(str(banner))
    return " ".join(banners)


def select_target_os(
    ports: list[Any], hint: str, available: set[str]
) -> str | None:
    """Pick one operating system for a host without trying multiple accounts."""
    hint = (hint or "auto").lower()
    if hint in {"linux", "windows"}:
        return hint if hint in available else None
    port_numbers = _port_numbers(ports)
    banner = _banner_text(ports).lower()
    if "openssh_for_windows" in banner and "windows" in available:
        return "windows"
    if port_numbers & {3389, 5985, 5986} and "windows" in available:
        return "windows"
    if 22 in port_numbers:
        if "linux" in available:
            return "linux"
        if "windows" in available and "windows" in banner:
            return "windows"
    if port_numbers & {445, 135, 139} and "windows" in available:
        return "windows"
    if len(available) == 1:
        only = next(iter(available))
        if only == "linux" and 22 in port_numbers:
            return "linux"
        if only == "windows" and port_numbers & WINDOWS_INDICATORS:
            return "windows"
    return None


def authenticated_scan(
    result: ScanResult,
    ctx: ScanContext,
    open_by_host: dict[str, list[Any]],
    customer_id: int | None = None,
    asset_id: int | None = None,
) -> None:
    """Run authenticated checks for hosts with a usable credential."""
    if not ctx.option_bool("authenticated", False):
        return
    max_hosts = _int_option(ctx.option("max_auth_hosts", MAX_AUTH_HOSTS), MAX_AUTH_HOSTS, 1, 256)
    timeout = _float_option(
        ctx.option("auth_timeout", DEFAULT_AUTH_TIMEOUT), DEFAULT_AUTH_TIMEOUT, 3.0, 90.0
    )
    hint = str(ctx.option("target_os", "auto") or "auto").lower()

    if not _paramiko() or not _winrm():
        ctx.log(
            "Authenticated scanning needs the 'paramiko' and 'pywinrm' packages; "
            "install the server requirements",
            "warning",
        )

    credentials: dict[str, dict[str, Any] | None] = {}
    for os_name in ("linux", "windows"):
        try:
            credentials[os_name] = resolve_for_scan(ctx.scan_id, os_name)
        except CredentialError as exc:
            ctx.log(f"Stored {os_name} credential could not be loaded: {exc}", "warning")
            credentials[os_name] = None
        except Exception as exc:  # never fail a scan because of credential lookup
            ctx.log(f"Credential lookup failed for {os_name}: {_clean(exc)}", "warning")
            credentials[os_name] = None

    available = {name for name, value in credentials.items() if value}
    if not available:
        ctx.log(
            "Authenticated checks enabled, but no Linux/Windows credential is configured. "
            "Add one in Settings or provide a per-scan credential.",
            "warning",
        )
        return

    attempted = 0
    for host, ports in open_by_host.items():
        if ctx.cancelled():
            return
        os_name = select_target_os(ports, hint, available)
        if not os_name:
            continue
        if attempted >= max_hosts:
            ctx.log(
                f"Authenticated checks limited to {max_hosts} host(s); remaining hosts were skipped",
                "warning",
            )
            break
        credential = credentials.get(os_name)
        if not credential:
            continue
        attempted += 1
        ctx.check_cancel()
        ctx.progress(
            min(95, 82 + attempted),
            f"Authenticated {os_name} checks on {host}",
        )
        _attempt_host(result, ctx, host, ports, os_name, credential, timeout)


def _attempt_host(
    result: ScanResult,
    ctx: ScanContext,
    host: str,
    ports: list[Any],
    os_name: str,
    credential: dict[str, Any],
    timeout: float,
) -> None:
    method = "ssh" if os_name == "linux" else "winrm"
    logger = result.metadata.setdefault("authenticated", [])
    entry: dict[str, Any] = {
        "host": host,
        "os": os_name,
        "method": method,
        "username": credential.get("username", ""),
        "account_type": credential.get("account_type", ""),
        "domain": credential.get("domain", ""),
        "source": credential.get("source", "saved"),
        "authenticated": False,
    }
    logger.append(entry)
    try:
        if os_name == "linux":
            inventory = collect_linux(host, credential, timeout, ctx)
            package_count = len(inventory.get("packages") or [])
            entry["packages"] = package_count
            entry["updates"] = len(inventory.get("updates") or [])
            _add_linux_findings(result, ctx, host, inventory)
            entry["authenticated"] = True
            ctx.log(f"Authenticated Linux checks completed on {host}")
        else:
            inventory = collect_windows(host, credential, timeout, ctx)
            entry["software"] = len(inventory.get("software") or [])
            entry["hotfixes"] = len(inventory.get("hotfixes") or [])
            _add_windows_findings(result, ctx, host, inventory)
            entry["authenticated"] = True
            ctx.log(f"Authenticated Windows checks completed on {host}")
    except AuthFailed as exc:
        message = _sanitize_error(str(exc), str(credential.get("secret") or ""))
        entry["error"] = message
        ctx.log(f"Authentication rejected on {host} ({method}); not retrying", "warning")
        _add(
            result,
            severity="medium",
            title=f"Authenticated scan failed on {host}",
            category="host",
            description=(
                "The configured account was rejected. Only one authentication "
                "attempt is made per host to avoid locking the account."
            ),
            evidence=(
                f"Host: {host}\nMethod: {method.upper()}\n"
                f"Account: {credential.get('username', '')}\nReason: {message}"
            ),
            remediation=(
                "Verify the username, domain/local account form, password or key, and that "
                "SSH/WinRM is enabled. Correct the credential and start a new scan; the scanner "
                "does not retry automatically."
            ),
            key=f"auth-failed:{host}:{os_name}",
            location=host,
            cwe="CWE-287",
        )
    except ConnectionFailed as exc:
        message = _sanitize_error(str(exc), str(credential.get("secret") or ""))
        entry["error"] = message
        ctx.log(f"Authenticated checks could not connect to {host}: {message}", "warning")
        _add(
            result,
            severity="low",
            title=f"Authenticated checks could not connect to {host}",
            category="host",
            description=(
                "The host exposes a management service but the authenticated collector "
                "could not complete the session."
            ),
            evidence=f"Host: {host}\nMethod: {method.upper()}\nReason: {message}",
            remediation=(
                "Confirm SSH/WinRM is enabled, the port is reachable from the server, the "
                "account is allowed to log on, and the host key/certificate settings are correct."
            ),
            key=f"auth-connect:{host}:{os_name}",
            location=host,
        )
    except Exception as exc:  # defensive: never fail the whole scan
        message = _sanitize_error(f"{exc.__class__.__name__}: {exc}", str(credential.get("secret") or ""))
        entry["error"] = message
        ctx.log(f"Authenticated checks failed on {host}: {message}", "warning")
        _add(
            result,
            severity="low",
            title=f"Authenticated checks failed on {host}",
            category="host",
            description="The authenticated collector raised an unexpected error.",
            evidence=f"Host: {host}\nMethod: {method.upper()}\nReason: {message}",
            remediation="Check the server log and the host's SSH/WinRM service, then run a new scan.",
            key=f"auth-error:{host}:{os_name}",
            location=host,
        )


# ---------------------------------------------------------------------------
# SSH collector
# ---------------------------------------------------------------------------


def _verify_ssh_host_key(transport, host: str, port: int, ctx: ScanContext | None) -> None:
    """Verify the remote SSH host key when a known_hosts file is configured."""
    paramiko = _paramiko()
    remote = transport.get_remote_server_key()
    fingerprint = ":".join(f"{byte:02x}" for byte in remote.get_fingerprint())
    known_hosts = ssh_known_hosts_path()
    if not known_hosts:
        if ctx:
            ctx.log(
                f"SSH host key for {host}:{port} is {remote.get_name()} "
                f"MD5:{fingerprint} (set VS_SSH_KNOWN_HOSTS to enforce verification)",
                "warning",
            )
        return
    try:
        host_keys = paramiko.HostKeys(known_hosts)
    except (OSError, paramiko.SSHException) as exc:
        raise ConnectionFailed(f"Could not load SSH known_hosts file: {exc}") from exc
    candidates = [host, f"[{host}]:{port}"]
    entry = next((host_keys.lookup(item) for item in candidates if host_keys.lookup(item)), None)
    if not entry:
        raise ConnectionFailed(
            f"SSH host key for {host}:{port} is not present in {known_hosts}; "
            "add it before scanning"
        )
    expected = entry.get(remote.get_name())
    if expected is None or expected != remote:
        raise ConnectionFailed(
            f"SSH host key mismatch for {host}:{port}; possible man-in-the-middle"
        )


def _ssh_connect(
    host: str,
    port: int,
    credential: dict[str, Any],
    timeout: float,
    ctx: ScanContext | None = None,
):
    paramiko = _paramiko()
    if not paramiko:
        raise ConnectionFailed("The 'paramiko' package is not installed")
    try:
        transport = paramiko.Transport((host, port))
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        try:
            transport.start_client(timeout=timeout)
        except paramiko.SSHException as exc:
            transport.close()
            raise ConnectionFailed(f"SSH negotiation failed: {exc}") from exc
        try:
            _verify_ssh_host_key(transport, host, port, ctx)
        except Exception:
            transport.close()
            raise
        username = str(credential.get("username") or "")
        try:
            if credential.get("auth_type") == "key":
                pkey = _load_private_key(
                    str(credential.get("secret") or ""),
                    str(credential.get("passphrase") or ""),
                )
                transport.auth_publickey(username, pkey)
            else:
                transport.auth_password(username, str(credential.get("secret") or ""))
        except paramiko.AuthenticationException as exc:
            transport.close()
            raise AuthFailed("The SSH server rejected the username or secret") from exc
        except paramiko.SSHException as exc:
            transport.close()
            raise ConnectionFailed(f"SSH authentication could not be completed: {exc}") from exc
        return transport
    except AuthFailed:
        raise
    except ConnectionFailed:
        raise
    except (socket.error, OSError) as exc:
        raise ConnectionFailed(f"SSH connection failed: {exc}") from exc


def _load_private_key(key_text: str, passphrase: str):
    paramiko = _paramiko()
    if not paramiko:
        raise ConnectionFailed("The 'paramiko' package is not installed")
    import io

    password = passphrase or None
    errors = []
    for key_class_name in ("RSAKey", "ECDSAKey", "Ed25519Key"):
        key_class = getattr(paramiko, key_class_name, None)
        if not key_class:
            continue
        try:
            return key_class.from_private_key(io.StringIO(key_text), password=password)
        except Exception as exc:
            errors.append(str(exc))
            continue
    try:
        return paramiko.PKey.from_private_key(io.StringIO(key_text), password=password)
    except Exception as exc:
        errors.append(str(exc))
    raise ConnectionFailed("Could not load the SSH private key: " + truncate("; ".join(errors), 300))


def _ssh_run(transport, command: str, timeout: float) -> str:
    try:
        channel = transport.open_session(timeout=timeout)
        channel.settimeout(timeout)
        channel.set_combine_stderr(True)
        channel.exec_command(command)
    except Exception as exc:
        raise ConnectionFailed(f"Could not start the remote command: {exc}") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            data = channel.recv(65536)
            if not data:
                break
            total += len(data)
            if total > MAX_OUTPUT_BYTES:
                break
            chunks.append(data)
        try:
            status = channel.recv_exit_status()
        except Exception:
            status = -1
    finally:
        channel.close()
    text = b"".join(chunks).decode("utf-8", errors="replace")
    if not text and status not in (0, -1, None):
        raise ConnectionFailed(f"The remote command exited with status {status}")
    return text


def collect_linux(
    host: str, credential: dict[str, Any], timeout: float, ctx: ScanContext
) -> dict[str, Any]:
    port = _int_option(
        ctx.option("ssh_port") or credential.get("port") or 22, 22, 1, 65535
    )
    transport = _ssh_connect(host, port, credential, timeout, ctx)
    try:
        output = _ssh_run(transport, LINUX_SCRIPT, timeout)
    finally:
        transport.close()
    inventory = parse_linux_output(output)
    if not inventory.get("os_release") and not inventory.get("packages"):
        raise ConnectionFailed("The SSH session returned no recognisable inventory")
    inventory["collector"] = "ssh"
    return inventory


def _sections(text: str) -> dict[str, str]:
    parts = re.split(r"^===VS:([A-Z0-9_]+)===\s*$", text, flags=re.M)
    result: dict[str, str] = {}
    for index in range(1, len(parts), 2):
        result[parts[index]] = parts[index + 1]
    if not result:
        raise ConnectionFailed("The remote collector returned an unexpected format")
    return result


def _parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def parse_linux_output(text: str) -> dict[str, Any]:
    sections = _sections(text)
    os_release = _parse_os_release(sections.get("OS", ""))
    packages: list[tuple[str, str]] = []
    for line in sections.get("PACKAGES", "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        if name and version:
            packages.append((name, version))
        if len(packages) >= MAX_PACKAGES:
            break
    updates = []
    for line in sections.get("UPDATES", "").splitlines():
        name = line.strip().split()[0] if line.strip() else ""
        if name and name not in updates:
            updates.append(name)
        if len(updates) >= 200:
            break
    reboot_text = sections.get("REBOOT", "").strip()
    users = []
    for line in sections.get("PASSWD", "").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        users.append(
            {
                "name": parts[0],
                "uid": parts[2],
                "password": parts[1],
                "home": parts[5],
                "shell": parts[6],
            }
        )
    sudo_text = sections.get("GROUPS", "")
    sshd = {}
    for line in sections.get("SSHD", "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            sshd[parts[0].lower()] = parts[1].strip()
    return {
        "os_release": os_release,
        "kernel": (sections.get("KERNEL", "").strip().splitlines() or [""])[0],
        "login_user": (sections.get("OS", "").strip().splitlines() or [""])[-1],
        "packages": packages,
        "updates": updates,
        "reboot_required": reboot_text.lower().startswith("yes"),
        "reboot_detail": truncate(reboot_text, 300),
        "ports": _parse_linux_ports(sections.get("PORTS", "")),
        "users": users,
        "sudo_members": _parse_group_members(sudo_text),
        "sudo_nopasswd": [
            truncate(line, 220)
            for line in sudo_text.splitlines()
            if "nopasswd" in line.lower()
        ][:20],
        "sshd": sshd,
        "firewall": _firewall_active(sections.get("FIREWALL", "")),
        "raw_firewall": truncate(sections.get("FIREWALL", ""), 2000),
    }


def _parse_linux_ports(text: str) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if not any(part in {"LISTEN", "UNCONN"} for part in parts):
            continue
        protocol = "tcp" if parts[0].lower().startswith("tcp") else "udp"
        match = None
        for field in parts[3:6]:
            match = re.match(r"^(\[[^\]]+\]|[0-9a-fA-F:.]+):(\d+)$", field)
            if match:
                break
        if not match:
            continue
        address = match.group(1).strip("[]")
        try:
            port = int(match.group(2))
        except ValueError:
            continue
        key = (address, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        ports.append({"address": address, "port": port, "protocol": protocol})
    return ports[:1000]


def _parse_group_members(text: str) -> list[str]:
    members: list[str] = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            for member in parts[3].split(","):
                member = member.strip()
                if member and member not in members:
                    members.append(member)
    return members


def _firewall_active(text: str) -> bool:
    lowered = text.lower()
    if not lowered.strip():
        return False
    if "status: active" in lowered or "state: active" in lowered:
        return True
    if re.search(r"^running$", lowered, re.M):
        return True
    if "not running" in lowered or "inactive" in lowered:
        return False
    # nft/iptables output with at least one rule still counts as a firewall.
    if "chain " in lowered or "table " in lowered:
        return True
    return False


def _add(
    result: ScanResult,
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    key: str,
    location: str,
    category: str = "host",
    cve: str = "",
    cwe: str = "",
    cvss: float | None = None,
    raw: dict[str, Any] | None = None,
) -> None:
    result.add(
        Finding(
            severity=severity,
            title=title,
            category=category,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cve=cve,
            cwe=cwe,
            cvss=cvss,
            location=location,
            key=key,
            raw=raw or {},
        )
    )


def _eol_status(distribution: str, version: str) -> tuple[bool, str, bool]:
    """Return (is_eol, eol_date, soon)."""
    distribution = (distribution or "").lower()
    version = (version or "").strip()
    best: tuple[str, str] | None = None
    for (distro, prefix), eol in EOL_LINUX.items():
        if distro != distribution:
            continue
        if version == prefix or version.startswith(prefix + ".") or version.startswith(prefix):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, eol)
    if not best:
        return False, "", False
    eol_date = datetime.strptime(best[1], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    today = datetime.now(timezone.utc)
    return today > eol_date, best[1], (eol_date - today).days <= 180


def _add_linux_findings(
    result: ScanResult, ctx: ScanContext, host: str, inventory: dict[str, Any]
) -> None:
    os_release = inventory.get("os_release") or {}
    distro = str(os_release.get("ID") or "").lower()
    version = str(os_release.get("VERSION_ID") or "")
    pretty = str(os_release.get("PRETTY_NAME") or f"{distro} {version}".strip() or "Linux")
    kernel = str(inventory.get("kernel") or "")
    result.metadata.setdefault("host_inventory", []).append(
        {
            "host": host,
            "os": pretty,
            "kernel": kernel,
            "packages": len(inventory.get("packages") or []),
            "pending_updates": len(inventory.get("updates") or []),
            "users": len(inventory.get("users") or []),
            "open_ports": len(inventory.get("ports") or []),
            "method": "ssh",
        }
    )

    is_eol, eol_date, soon = _eol_status(distro, version)
    if is_eol:
        _add(
            result,
            severity="critical",
            title=f"Unsupported operating system: {pretty}",
            description=(
                "The operating system has reached its vendor end-of-life date and no longer "
                "receives security updates."
            ),
            evidence=f"Host: {host}\nOS: {pretty}\nEnd of support: {eol_date}",
            remediation="Upgrade to a supported release or arrange extended security maintenance.",
            key=f"auth-os-eol:{host}",
            location=host,
            cwe="CWE-1104",
        )
    elif soon:
        _add(
            result,
            severity="medium",
            title=f"Operating system support ends soon: {pretty}",
            description="The operating system will reach end-of-life within six months.",
            evidence=f"Host: {host}\nOS: {pretty}\nEnd of standard support: {eol_date}",
            remediation="Plan an upgrade before the vendor stops publishing security updates.",
            key=f"auth-os-eol-soon:{host}",
            location=host,
            cwe="CWE-1104",
        )

    updates = inventory.get("updates") or []
    if updates:
        _add(
            result,
            severity="high" if len(updates) >= 20 else "medium",
            title=f"{len(updates)} pending package update(s) on {host}",
            description=(
                "The authenticated package manager reports pending updates, which may include "
                "security fixes."
            ),
            evidence=(
                f"Host: {host}\nOS: {pretty}\nPending: {', '.join(updates[:20])}"
                + (" …" if len(updates) > 20 else "")
            ),
            remediation="Apply vendor security updates and reboot if the kernel or libraries require it.",
            key=f"auth-updates:{host}",
            location=host,
            cwe="CWE-1104",
        )
    if inventory.get("reboot_required"):
        _add(
            result,
            severity="medium",
            title=f"Reboot required on {host}",
            description="A previous update left the host waiting for a reboot, so the running kernel or libraries may be vulnerable.",
            evidence=f"Host: {host}\n{inventory.get('reboot_detail') or '/var/run/reboot-required'}",
            remediation="Schedule a reboot during a maintenance window.",
            key=f"auth-reboot:{host}",
            location=host,
        )

    _add_linux_packages(result, ctx, host, inventory.get("packages") or [], distro, pretty)

    users = inventory.get("users") or []
    root_users = [user for user in users if str(user.get("uid")) == "0" and user.get("name") != "root"]
    for user in root_users:
        _add(
            result,
            severity="high",
            title=f"Additional UID 0 account on {host}: {user.get('name')}",
            description="An account other than root has full superuser privileges.",
            evidence=f"Host: {host}\nAccount: {user.get('name')}\nUID: 0\nShell: {user.get('shell')}",
            remediation="Remove the account or assign a non-zero UID unless it is a documented emergency account.",
            key=f"auth-uid0:{host}:{user.get('name')}",
            location=host,
            cwe="CWE-250",
        )
    empty_passwords = [
        user for user in users if user.get("password") == "" and user.get("shell") not in {"", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}
    ]
    for user in empty_passwords[:20]:
        _add(
            result,
            severity="critical",
            title=f"Account with an empty password on {host}: {user.get('name')}",
            description="The password hash field is empty, which can allow passwordless logon.",
            evidence=f"Host: {host}\nAccount: {user.get('name')}\nShell: {user.get('shell')}",
            remediation="Lock the account or set a strong password immediately.",
            key=f"auth-empty-password:{host}:{user.get('name')}",
            location=host,
            cwe="CWE-258",
        )

    sshd = inventory.get("sshd") or {}
    root_login = str(sshd.get("permitrootlogin", "")).lower()
    if root_login in {"yes", "without-password", "prohibit-password", "forced-commands-only"} and root_login == "yes":
        _add(
            result,
            severity="high",
            title=f"SSH permits direct root login on {host}",
            description="The SSH daemon accepts root logons, which removes an accountability layer and increases brute-force impact.",
            evidence=f"Host: {host}\nPermitRootLogin {root_login}",
            remediation="Set PermitRootLogin to no or prohibit-password and use a named account with sudo.",
            key=f"auth-ssh-root:{host}",
            location=host,
            cwe="CWE-284",
        )
    if str(sshd.get("passwordauthentication", "")).lower() == "yes":
        _add(
            result,
            severity="medium",
            title=f"SSH password authentication enabled on {host}",
            description="Password authentication is easier to brute force than key-based authentication.",
            evidence=f"Host: {host}\nPasswordAuthentication yes",
            remediation="Prefer key-based authentication and restrict password auth to a bastion if it is required.",
            key=f"auth-ssh-password:{host}",
            location=host,
            cwe="CWE-307",
        )
    if str(sshd.get("permitemptypasswords", "")).lower() == "yes":
        _add(
            result,
            severity="critical",
            title=f"SSH permits empty passwords on {host}",
            description="The SSH daemon allows accounts with empty passwords to log in.",
            evidence=f"Host: {host}\nPermitEmptyPasswords yes",
            remediation="Set PermitEmptyPasswords to no and lock accounts without passwords.",
            key=f"auth-ssh-empty:{host}",
            location=host,
            cwe="CWE-258",
        )

    if not inventory.get("firewall"):
        _add(
            result,
            severity="medium",
            title=f"No active host firewall detected on {host}",
            description="The collector could not find an active ufw, firewalld, nftables or iptables policy.",
            evidence=f"Host: {host}\nFirewall output: {inventory.get('raw_firewall') or 'none'}",
            remediation="Enable a default-deny host firewall and allow only the required services.",
            key=f"auth-firewall:{host}",
            location=host,
            cwe="CWE-284",
        )

    for entry in (inventory.get("sudo_nopasswd") or [])[:10]:
        _add(
            result,
            severity="medium",
            title=f"Passwordless sudo rule on {host}",
            description="A sudo rule grants elevated commands without re-authentication.",
            evidence=f"Host: {host}\nRule: {entry}",
            remediation="Require a password for sudo or restrict NOPASSWD to tightly scoped commands.",
            key=f"auth-sudo-nopasswd:{host}:{hashlib_key(entry)}",
            location=host,
            cwe="CWE-269",
        )

    _add_listening_port_findings(result, host, inventory.get("ports") or [], "ssh")


def hashlib_key(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _add_listening_port_findings(
    result: ScanResult, host: str, ports: list[dict[str, Any]], method: str
) -> None:
    for item in ports[:1000]:
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            continue
        address = str(item.get("address") or "")
        if port <= 0:
            continue
        exposed = _address_exposed(address)
        dangerous = DANGEROUS_PORTS.get(port)
        if exposed and dangerous:
            _, severity, remediation = dangerous
            _add(
                result,
                severity=severity,
                title=f"Risky service listening on all interfaces: {dangerous[0]} (port {port})",
                description=(
                    f"The authenticated host inventory found {dangerous[0]} on {address}:{port}. "
                    "A service bound to a non-loopback address is reachable from the network."
                ),
                evidence=f"Host: {host}\nAddress: {address}:{port}\nCollector: {method}",
                remediation=remediation,
                key=f"auth-risky-port:{host}:{port}",
                location=f"{host}:{port}",
            )


def _address_exposed(address: str) -> bool:
    address = (address or "").strip().strip("[]")
    if not address or address.lower() in {"localhost", "::1"}:
        return False
    if address.startswith("127."):
        return False
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return not ip.is_loopback
    except ValueError:
        return True


def _add_linux_packages(
    result: ScanResult,
    ctx: ScanContext,
    host: str,
    packages: list[tuple[str, str]],
    distro: str,
    pretty: str,
) -> None:
    if not packages:
        ctx.log(f"No package inventory returned by {host}")
        return
    ecosystem = ECOSYSTEMS.get(distro)
    if not ecosystem:
        ctx.log(
            f"No OSV ecosystem mapping for {pretty}; package CVE matching skipped for {host}",
            "warning",
        )
        return
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        ctx.log(
            "OSV package CVE matching is disabled by the external-API setting; "
            f"skipping {len(packages)} package(s) on {host}",
            "warning",
        )
        return
    from .cvss import osv_severity
    from .dependencies import PackageRef
    from .osv import query_packages

    selected = packages[:MAX_PACKAGES]
    refs = [PackageRef(name, version, ecosystem, host) for name, version in selected]
    ctx.log(f"Checking {len(refs)} {ecosystem} package version(s) on {host} against OSV")
    matches = query_packages(
        [ref.as_query() for ref in refs],
        log=lambda message: ctx.log(message, "warning") if "unavailable" in message.lower() else ctx.log(message),
    )
    count = 0
    for index, vulns in matches.items():
        package = refs[index]
        for vuln in vulns[:100]:
            vuln_id = str(vuln.get("id") or "")
            aliases = [str(alias) for alias in vuln.get("aliases") or []]
            cves = [alias for alias in aliases if alias.startswith("CVE-")]
            fixed_versions: list[str] = []
            for affected in vuln.get("affected") or []:
                for version_range in affected.get("ranges") or []:
                    for event in version_range.get("events") or []:
                        if event.get("fixed"):
                            fixed_versions.append(str(event["fixed"]))
            cvss, severity = osv_severity(vuln)
            summary = str(vuln.get("summary") or "").strip()
            details = str(vuln.get("details") or "").strip()
            fixed_text = ", ".join(sorted(set(fixed_versions))[:5])
            remediation = (
                f"Upgrade {package.name} to {fixed_text} or later."
                if fixed_text
                else "Apply the vendor advisory or upgrade to a supported, patched release."
            )
            _add(
                result,
                severity=severity,
                title=f"Vulnerable package: {package.name} {package.version} ({vuln_id})",
                category="host",
                description=truncate((summary + "\n\n" + details).strip(), 7000),
                evidence=(
                    f"Host: {host}\nPackage: {package.name}@{package.version}\n"
                    f"Ecosystem: {package.ecosystem}\nOS: {pretty}\n"
                    f"Advisory: {vuln_id}\nAliases: {', '.join(aliases) or 'none'}\n"
                    f"Fixed versions: {fixed_text or 'not specified'}"
                ),
                remediation=remediation,
                cve=",".join(cves),
                cvss=None,
                key=f"osv:{package.ecosystem}:{package.name}:{vuln_id}",
                location=host,
                raw={
                    "osv_id": vuln_id,
                    "aliases": aliases,
                    "ecosystem": package.ecosystem,
                    "package": package.name,
                    "version": package.version,
                    "fixed_versions": sorted(set(fixed_versions)),
                    "cvss": cvss,
                    "authenticated": True,
                },
            )
            count += 1
    ctx.log(f"OSV matched {count} host package advisory(ies) on {host}")


# ---------------------------------------------------------------------------
# WinRM collector
# ---------------------------------------------------------------------------


def _winrm_username(credential: dict[str, Any]) -> str:
    username = str(credential.get("username") or "").strip()
    domain = str(credential.get("domain") or "").strip()
    if (
        credential.get("account_type") == "domain"
        and domain
        and "\\" not in username
        and "@" not in username
    ):
        return f"{domain}\\{username}"
    return username


def collect_windows(
    host: str, credential: dict[str, Any], timeout: float, ctx: ScanContext
) -> dict[str, Any]:
    winrm = _winrm()
    if not winrm:
        raise ConnectionFailed("The 'pywinrm' package is not installed")
    use_https = ctx.option_bool("winrm_https", False) or bool(credential.get("winrm_https"))
    default_port = 5986 if use_https else 5985
    port = _int_option(
        ctx.option("winrm_port") or credential.get("port") or default_port,
        default_port,
        1,
        65535,
    )
    scheme = "https" if use_https or port == 5986 else "http"
    transport = str(ctx.option("winrm_transport", "ntlm") or "ntlm").lower()
    if transport not in {"ntlm", "basic", "credssp", "kerberos"}:
        transport = "ntlm"
    verify = ctx.option_bool("verify_tls", False)
    endpoint = f"{scheme}://{host}:{port}/wsman"
    operation_timeout = max(20, int(timeout) + 5)
    read_timeout = max(60, int(timeout) * 4)
    session = winrm.Session(
        endpoint,
        auth=(_winrm_username(credential), str(credential.get("secret") or "")),
        transport=transport,
        server_cert_validation="validate" if verify else "ignore",
        operation_timeout_sec=operation_timeout,
        read_timeout_sec=read_timeout,
    )
    ctx.log(f"Opening WinRM ({transport}) session to {host}:{port}")
    try:
        response = session.run_ps(WINDOWS_SCRIPT)
    except Exception as exc:  # pywinrm exception types vary by version
        name = exc.__class__.__name__.lower()
        message = truncate(str(exc), 400) or exc.__class__.__name__
        if any(token in name for token in ("invalidcredential", "unauthorized", "authentication")):
            raise AuthFailed("WinRM rejected the username or password") from exc
        raise ConnectionFailed(f"WinRM connection failed: {message}") from exc
    status = getattr(response, "status_code", 0)
    stdout = (getattr(response, "std_out", b"") or b"").decode("utf-8", errors="replace")
    stderr = (getattr(response, "std_err", b"") or b"").decode("utf-8", errors="replace")
    if status and status != 0:
        raise ConnectionFailed(
            f"WinRM collector exited with status {status}: {truncate(stderr or stdout, 400)}"
        )
    inventory = parse_windows_output(stdout)
    inventory["collector"] = "winrm"
    inventory["winrm_port"] = port
    inventory["winrm_https"] = scheme == "https"
    return inventory


def _dict_value(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _list_value(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return default


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _date_text(value: Any) -> str:
    """Best-effort conversion of WinRM DateTime JSON to an ISO-ish string."""
    if not value:
        return ""
    if isinstance(value, str):
        match = re.match(r"^/?Date\((-?\d+)", value)
        if match:
            try:
                stamp = int(match.group(1)) / 1000.0
                return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d")
            except (ValueError, OSError):
                return truncate(value, 40)
        return truncate(value, 40)
    return truncate(str(value), 40)


def parse_windows_output(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ConnectionFailed("The WinRM session returned no inventory")
    start = text.find("{")
    if start < 0:
        raise ConnectionFailed("The WinRM collector returned an unexpected format")
    try:
        data = json.loads(text[start:])
    except ValueError as exc:
        raise ConnectionFailed(f"Could not parse the WinRM inventory: {truncate(str(exc), 200)}") from exc
    if not isinstance(data, dict):
        raise ConnectionFailed("The WinRM collector returned an unexpected payload")

    os_info = _dict_value(data.get("os"))
    computer = _dict_value(data.get("computer"))
    caption = str(os_info.get("Caption") or "").strip()
    version = str(os_info.get("Version") or "").strip()
    build = str(os_info.get("BuildNumber") or "").strip()
    if caption.lower().startswith("microsoft windows"):
        caption = caption[len("microsoft "):].strip()
    pretty = " ".join(
        part for part in (caption, f"({build})" if build and build not in caption else "") if part
    ) or "Windows"

    hotfixes = []
    for item in _list_value(data.get("hotfixes")):
        if not isinstance(item, dict):
            continue
        hotfixes.append(
            {
                "id": truncate(str(item.get("HotFixID") or ""), 40),
                "description": truncate(str(item.get("Description") or ""), 120),
                "installed_on": _date_text(item.get("InstalledOn")),
            }
        )

    software = []
    for item in _list_value(data.get("software")):
        if not isinstance(item, dict):
            continue
        name = truncate(str(item.get("DisplayName") or "").strip(), 200)
        if not name:
            continue
        software.append(
            {
                "name": name,
                "version": truncate(str(item.get("DisplayVersion") or "").strip(), 60),
                "publisher": truncate(str(item.get("Publisher") or "").strip(), 160),
            }
        )
        if len(software) >= MAX_SOFTWARE:
            break

    users = []
    for item in _list_value(data.get("users")):
        if not isinstance(item, dict):
            continue
        users.append(
            {
                "name": truncate(str(item.get("Name") or ""), 120),
                "enabled": _bool_value(item.get("Enabled")),
                "password_required": _bool_value(item.get("PasswordRequired"), True),
                "password_last_set": _date_text(item.get("PasswordLastSet")),
                "description": truncate(str(item.get("Description") or ""), 200),
            }
        )

    admins = []
    for item in _list_value(data.get("admins")):
        if not isinstance(item, dict):
            continue
        admins.append(
            {
                "name": truncate(str(item.get("Name") or ""), 200),
                "class": truncate(str(item.get("ObjectClass") or ""), 60),
                "source": truncate(str(item.get("PrincipalSource") or ""), 60),
            }
        )

    ports = []
    for item in _list_value(data.get("ports")):
        if not isinstance(item, dict):
            continue
        address = str(item.get("LocalAddress") or "")
        port = _int_value(item.get("LocalPort"))
        if port <= 0:
            continue
        ports.append({"address": address, "port": port, "protocol": "tcp"})

    services = []
    for item in _list_value(data.get("services")):
        if not isinstance(item, dict):
            continue
        services.append(
            {
                "name": truncate(str(item.get("Name") or ""), 120),
                "display": truncate(str(item.get("DisplayName") or ""), 200),
            }
        )

    firewall = {}
    for item in _list_value(data.get("firewall")):
        if isinstance(item, dict) and item.get("Name"):
            firewall[str(item["Name"])] = _bool_value(item.get("Enabled"))

    unquoted = []
    for item in _list_value(data.get("unquoted")):
        if not isinstance(item, dict):
            continue
        unquoted.append(
            {
                "name": truncate(str(item.get("Name") or ""), 120),
                "path": truncate(str(item.get("PathName") or ""), 400),
                "start_mode": truncate(str(item.get("StartMode") or ""), 40),
            }
        )

    password_policy = {
        "raw": truncate(str(data.get("password_policy") or ""), 2000),
        "min_length": _min_password_length(str(data.get("password_policy") or "")),
    }

    if not os_info and not software and not hotfixes:
        raise ConnectionFailed("The WinRM inventory did not include OS or software details")

    return {
        "os": {
            "caption": caption,
            "pretty": pretty,
            "version": version,
            "build": build,
            "architecture": truncate(str(os_info.get("OSArchitecture") or ""), 40),
            "install_date": _date_text(os_info.get("InstallDate")),
            "last_boot": _date_text(os_info.get("LastBootUpTime")),
        },
        "computer": {
            "name": truncate(str(computer.get("Name") or ""), 120),
            "domain": truncate(str(computer.get("Domain") or ""), 200),
            "manufacturer": truncate(str(computer.get("Manufacturer") or ""), 160),
            "model": truncate(str(computer.get("Model") or ""), 160),
            "part_of_domain": _bool_value(computer.get("PartOfDomain")),
        },
        "hotfixes": hotfixes,
        "software": software,
        "users": users,
        "admins": admins,
        "ports": ports[:1000],
        "services": services,
        "defender": _dict_value(data.get("defender")),
        "firewall": firewall,
        "smb": _dict_value(data.get("smb")),
        "rdp": _dict_value(data.get("rdp")),
        "rdp_nla": _dict_value(data.get("rdp_nla")),
        "uac": _dict_value(data.get("uac")),
        "autologon": _dict_value(data.get("autologon")),
        "always_install": _dict_value(data.get("always_install")),
        "winrm": _list_value(data.get("winrm")),
        "ps_logging": _dict_value(data.get("ps_logging")),
        "unquoted": unquoted,
        "password_policy": password_policy,
    }


def _min_password_length(raw: str) -> int:
    match = re.search(r"Minimum password length\s+(\d+)", raw, re.I)
    if not match:
        return -1
    try:
        return int(match.group(1))
    except ValueError:
        return -1


def _add_windows_findings(
    result: ScanResult, ctx: ScanContext, host: str, inventory: dict[str, Any]
) -> None:
    os_info = inventory.get("os") or {}
    pretty = str(os_info.get("pretty") or "Windows")
    caption = str(os_info.get("caption") or pretty)
    build = str(os_info.get("build") or "")
    computer = inventory.get("computer") or {}
    result.metadata.setdefault("host_inventory", []).append(
        {
            "host": host,
            "os": pretty,
            "build": build,
            "role": "domain member" if computer.get("part_of_domain") else "workstation/server",
            "hotfixes": len(inventory.get("hotfixes") or []),
            "software": len(inventory.get("software") or []),
            "users": len(inventory.get("users") or []),
            "open_ports": len(inventory.get("ports") or []),
            "method": "winrm",
        }
    )

    _windows_eol(result, host, caption, build)
    _windows_patch_level(result, host, inventory.get("hotfixes") or [])
    _windows_software(result, host, inventory.get("software") or [])
    _windows_accounts(result, host, inventory)
    _windows_policy(result, host, inventory)
    _add_listening_port_findings(result, host, inventory.get("ports") or [], "winrm")


def _windows_eol(result: ScanResult, host: str, caption: str, build: str) -> None:
    name = caption.lower()
    # Windows 10 and 11 share a caption on some builds; the build number decides.
    if "windows 1" in name:
        try:
            build_number = int(build)
        except (TypeError, ValueError):
            build_number = 0
        if build_number >= 22000:
            name = "windows 11"
        elif build_number:
            name = "windows 10"
    for pattern, eol, severity in WINDOWS_EOL:
        if not re.search(pattern, name):
            continue
        eol_date = datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        today = datetime.now(timezone.utc)
        if today > eol_date:
            _add(
                result,
                severity=severity,
                title=f"Unsupported operating system: {caption or 'Windows'}",
                description=(
                    "The Windows version no longer receives security updates from Microsoft."
                ),
                evidence=f"Host: {host}\nOS: {caption or 'Windows'}\nBuild: {build}\nEnd of support: {eol}",
                remediation="Upgrade to a supported Windows release or buy Extended Security Updates.",
                key=f"auth-os-eol:{host}",
                location=host,
                cwe="CWE-1104",
            )
        elif (eol_date - today).days <= 180:
            _add(
                result,
                severity="medium",
                title=f"Windows support ends soon: {caption}",
                description="The Windows release reaches end-of-support within six months.",
                evidence=f"Host: {host}\nOS: {caption}\nEnd of support: {eol}",
                remediation="Plan an in-place upgrade or replacement before support ends.",
                key=f"auth-os-eol-soon:{host}",
                location=host,
                cwe="CWE-1104",
            )
        return


def _windows_patch_level(
    result: ScanResult, host: str, hotfixes: list[dict[str, Any]]
) -> None:
    if not hotfixes:
        _add(
            result,
            severity="low",
            title=f"No installed update inventory returned by {host}",
            description=(
                "The collector did not return installed hotfixes. The host may use a different "
                "update mechanism, or the scan account lacks permission to query updates."
            ),
            evidence=f"Host: {host}\nGet-HotFix returned no records",
            remediation="Confirm Windows Update/WSUS patching and that the scan account can read update history.",
            key=f"auth-patch-inventory:{host}",
            location=host,
            cwe="CWE-1104",
        )
        return
    dates = sorted(item["installed_on"] for item in hotfixes if item.get("installed_on"))
    if not dates:
        return
    try:
        newest = datetime.strptime(dates[-1], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return
    age_days = (datetime.now(timezone.utc) - newest).days
    if age_days > 90:
        _add(
            result,
            severity="medium",
            title=f"No recent update recorded on {host} ({age_days} days)",
            description=(
                "The newest installed hotfix is older than 90 days. Missing cumulative updates "
                "usually mean missing security fixes."
            ),
            evidence=(
                f"Host: {host}\nNewest hotfix: {dates[-1]}\n"
                f"Installed hotfixes: {len(hotfixes)}\nAge: {age_days} days"
            ),
            remediation="Review Windows Update/WSUS compliance and install the latest cumulative updates.",
            key=f"auth-patch-stale:{host}",
            location=host,
            cwe="CWE-1104",
        )


def _windows_software(
    result: ScanResult, host: str, software: list[dict[str, Any]]
) -> None:
    for item in software:
        label = f"{item.get('name', '')} {item.get('version', '')}".strip()
        lowered = label.lower()
        for pattern, product, severity, remediation in EOL_SOFTWARE:
            if not re.search(pattern, lowered):
                continue
            _add(
                result,
                severity=severity,
                title=f"Unsupported software on {host}: {product}",
                description=(
                    f"The host has {label}, which is no longer supported or no longer receives "
                    "security updates."
                ),
                evidence=f"Host: {host}\nSoftware: {label}\nPublisher: {item.get('publisher', '')}",
                remediation=remediation,
                key=f"auth-software-eol:{host}:{hashlib_key(label)}",
                location=host,
                cwe="CWE-1104",
            )
            break


def _windows_accounts(
    result: ScanResult, host: str, inventory: dict[str, Any]
) -> None:
    users = inventory.get("users") or []
    for user in users:
        name = str(user.get("name") or "")
        if name.lower() == "guest" and user.get("enabled"):
            _add(
                result,
                severity="high",
                title=f"Guest account enabled on {host}",
                description="The built-in Guest account is enabled and may allow unauthenticated access.",
                evidence=f"Host: {host}\nAccount: {name}\nEnabled: yes",
                remediation="Disable the Guest account and use named, authenticated accounts.",
                key=f"auth-guest:{host}",
                location=host,
                cwe="CWE-284",
            )
        if user.get("enabled") and not user.get("password_required", True) and name.lower() != "guest":
            _add(
                result,
                severity="high",
                title=f"Account can log on without a password on {host}: {name}",
                description="The account is enabled and is not required to have a password.",
                evidence=f"Host: {host}\nAccount: {name}\nPasswordRequired: false",
                remediation="Require a strong password and review the account's purpose.",
                key=f"auth-no-password:{host}:{name}",
                location=host,
                cwe="CWE-258",
            )

    admins = inventory.get("admins") or []
    if admins:
        names = ", ".join(str(item.get("name") or "") for item in admins[:20])
        _add(
            result,
            severity="info",
            title=f"Local administrators on {host}",
            description="Accounts with local administrator rights. Review for unnecessary or shared accounts.",
            evidence=f"Host: {host}\nAdministrators: {names}",
            remediation="Keep the local Administrators group minimal and use LAPS or a PAM tool for local passwords.",
            key=f"auth-local-admins:{host}",
            location=host,
            raw={"admins": admins[:50]},
        )
        domain_admins = [
            item for item in admins if str(item.get("source") or "").lower() == "activedirectory"
        ]
        if len(admins) > 5:
            _add(
                result,
                severity="low",
                title=f"Large local Administrators group on {host} ({len(admins)} members)",
                description=(
                    "A large local Administrators group increases the impact of a single compromised "
                    "account."
                ),
                evidence=f"Host: {host}\nMembers: {names}",
                remediation="Remove unnecessary members and prefer just-in-time administration.",
                key=f"auth-admin-count:{host}",
                location=host,
                cwe="CWE-250",
            )
        if domain_admins:
            _add(
                result,
                severity="info",
                title=f"Domain principals hold local admin rights on {host}",
                description="Domain accounts or groups are members of the local Administrators group.",
                evidence=(
                    f"Host: {host}\n"
                    + ", ".join(
                        str(item.get("name") or "") for item in domain_admins[:20]
                    )
                ),
                remediation="Limit domain wide local-admin rights (for example with LAPS and tiered administration).",
                key=f"auth-domain-admins:{host}",
                location=host,
            )

    policy = inventory.get("password_policy") or {}
    min_length = int(policy.get("min_length", -1))
    if 0 <= min_length < 8:
        _add(
            result,
            severity="medium",
            title=f"Weak minimum password length on {host} ({min_length})",
            description="The local password policy allows short passwords.",
            evidence=f"Host: {host}\nMinimum password length: {min_length}",
            remediation="Set the minimum password length to at least 12 characters (14 for privileged accounts).",
            key=f"auth-password-length:{host}",
            location=host,
            cwe="CWE-521",
        )


def _windows_policy(result: ScanResult, host: str, inventory: dict[str, Any]) -> None:
    defender = inventory.get("defender") or {}
    if defender:
        antivirus = _bool_value(defender.get("AntivirusEnabled"), True)
        realtime = _bool_value(defender.get("RealTimeProtectionEnabled"), True)
        if not antivirus or not realtime:
            _add(
                result,
                severity="high",
                title=f"Microsoft Defender protection disabled on {host}",
                description="Antivirus or real-time protection is turned off.",
                evidence=(
                    f"Host: {host}\nAntivirusEnabled: {antivirus}\n"
                    f"RealTimeProtectionEnabled: {realtime}"
                ),
                remediation="Re-enable Defender or confirm that another endpoint protection product is active.",
                key=f"auth-defender:{host}",
                location=host,
                cwe="CWE-693",
            )
    else:
        _add(
            result,
            severity="low",
            title=f"Endpoint protection status unavailable on {host}",
            description="The scan account could not read Microsoft Defender status.",
            evidence=f"Host: {host}\nGet-MpComputerStatus returned no data",
            remediation="Confirm that endpoint protection is installed and that the scan account can read its status.",
            key=f"auth-defender-unknown:{host}",
            location=host,
        )

    firewall = inventory.get("firewall") or {}
    if firewall:
        disabled = [name for name, enabled in firewall.items() if not enabled]
        if disabled:
            _add(
                result,
                severity="high",
                title=f"Windows Firewall disabled on {host}",
                description="One or more Windows Firewall profiles are turned off.",
                evidence=f"Host: {host}\nDisabled profiles: {', '.join(disabled)}",
                remediation="Enable Windows Firewall for the Domain, Private and Public profiles.",
                key=f"auth-firewall:{host}",
                location=host,
                cwe="CWE-284",
            )
    else:
        _add(
            result,
            severity="medium",
            title=f"Windows Firewall state unavailable on {host}",
            description="The collector could not read the Windows Firewall profile state.",
            evidence=f"Host: {host}\nGet-NetFirewallProfile returned no data",
            remediation="Confirm Windows Firewall is enabled and that the scan account can read its configuration.",
            key=f"auth-firewall-unknown:{host}",
            location=host,
        )

    smb = inventory.get("smb") or {}
    if _bool_value(smb.get("EnableSMB1Protocol")):
        _add(
            result,
            severity="high",
            title=f"SMBv1 is enabled on {host}",
            description="SMBv1 is obsolete and has well-known remote code execution vulnerabilities.",
            evidence=f"Host: {host}\nEnableSMB1Protocol: true",
            remediation="Disable SMBv1 and remove it from the Windows optional features.",
            key=f"auth-smb1:{host}",
            location=host,
            cwe="CWE-1104",
        )
    if smb and not _bool_value(smb.get("RequireSecuritySignature")):
        _add(
            result,
            severity="medium",
            title=f"SMB signing is not required on {host}",
            description="Without required SMB signing, an attacker on the network can relay authentication.",
            evidence=f"Host: {host}\nRequireSecuritySignature: false",
            remediation="Require SMB signing for the server and SMB clients.",
            key=f"auth-smb-signing:{host}",
            location=host,
            cwe="CWE-345",
        )

    rdp = inventory.get("rdp") or {}
    rdp_nla = inventory.get("rdp_nla") or {}
    if rdp and _int_value(rdp.get("fDenyTSConnections"), 1) == 0:
        nla = _int_value(rdp_nla.get("UserAuthentication"), 0)
        if not nla:
            _add(
                result,
                severity="high",
                title=f"RDP enabled without Network Level Authentication on {host}",
                description="Remote Desktop accepts connections before authentication, exposing the logon screen to the network.",
                evidence=f"Host: {host}\nfDenyTSConnections: 0\nUserAuthentication: 0",
                remediation="Require NLA for RDP and restrict port 3389 with a firewall or VPN.",
                key=f"auth-rdp-nla:{host}",
                location=host,
                cwe="CWE-287",
            )
        else:
            _add(
                result,
                severity="info",
                title=f"Remote Desktop enabled on {host}",
                description="RDP is enabled. Confirm that it is required and restricted to trusted networks.",
                evidence=f"Host: {host}\nfDenyTSConnections: 0\nNLA: enabled",
                remediation="Restrict RDP to a VPN or jump host and enforce account lockout and MFA.",
                key=f"auth-rdp:{host}",
                location=host,
            )

    uac = inventory.get("uac") or {}
    if uac and not _bool_value(uac.get("EnableLUA"), True):
        _add(
            result,
            severity="high",
            title=f"User Account Control is disabled on {host}",
            description="Without UAC, processes run with full administrator rights without an elevation prompt.",
            evidence=f"Host: {host}\nEnableLUA: 0",
            remediation="Enable UAC and set ConsentPromptBehaviorAdmin to the default prompt-for-consent.",
            key=f"auth-uac:{host}",
            location=host,
            cwe="CWE-269",
        )

    autologon = inventory.get("autologon") or {}
    if _bool_value(autologon.get("AutoAdminLogon")):
        _add(
            result,
            severity="high",
            title=f"Automatic logon is configured on {host}",
            description="Windows stores an account for automatic logon, which exposes credentials to anyone with local access.",
            evidence=(
                f"Host: {host}\nAutoAdminLogon: 1\n"
                f"Account: {autologon.get('DefaultDomainName', '')}\\{autologon.get('DefaultUserName', '')}"
            ),
            remediation="Disable AutoAdminLogon and remove stored logon credentials (use a service account or kiosk mode).",
            key=f"auth-autologon:{host}",
            location=host,
            cwe="CWE-522",
        )

    always_install = inventory.get("always_install") or {}
    if _bool_value(always_install.get("AlwaysInstallElevated")):
        _add(
            result,
            severity="critical",
            title=f"AlwaysInstallElevated is enabled on {host}",
            description="Any user can install an MSI package with SYSTEM privileges, which allows local privilege escalation.",
            evidence=(
                f"Host: {host}\n"
                f"HKLM AlwaysInstallElevated: {always_install.get('AlwaysInstallElevated')}"
            ),
            remediation="Remove the AlwaysInstallElevated policy from both HKLM and HKCU.",
            key=f"auth-always-install:{host}",
            location=host,
            cwe="CWE-269",
        )

    ps_logging = inventory.get("ps_logging") or {}
    if not _bool_value(ps_logging.get("EnableScriptBlockLogging")):
        _add(
            result,
            severity="low",
            title=f"PowerShell script block logging is disabled on {host}",
            description="Script block logging helps detect and investigate malicious PowerShell activity.",
            evidence=f"Host: {host}\nEnableScriptBlockLogging: 0",
            remediation="Enable PowerShell script block logging and transcription through Group Policy.",
            key=f"auth-ps-logging:{host}",
            location=host,
            cwe="CWE-778",
        )

    unquoted = inventory.get("unquoted") or []
    for item in unquoted[:20]:
        _add(
            result,
            severity="medium",
            title=f"Unquoted service path on {host}: {item.get('name')}",
            description="A service path with spaces and no quotes can let a local user place a malicious executable earlier in the search path.",
            evidence=f"Host: {host}\nService: {item.get('name')}\nPath: {item.get('path')}",
            remediation="Quote the full service executable path and ensure parent directories are not writable by unprivileged users.",
            key=f"auth-unquoted:{host}:{item.get('name')}",
            location=host,
            cwe="CWE-428",
        )

    if not inventory.get("winrm_https") and inventory.get("winrm_port") == 5985:
        _add(
            result,
            severity="medium",
            title=f"WinRM is using unencrypted HTTP on {host}",
            description="WinRM over HTTP sends management traffic without transport encryption.",
            evidence=f"Host: {host}\nEndpoint: http://{host}:5985/wsman",
            remediation="Configure a WinRM HTTPS listener with a trusted certificate and use port 5986.",
            key=f"auth-winrm-http:{host}",
            location=host,
            cwe="CWE-319",
        )

    winrm_config = inventory.get("winrm") or []
    basic = next(
        (
            item
            for item in winrm_config
            if isinstance(item, dict) and str(item.get("Name") or "").lower() == "basic"
        ),
        None,
    )
    if basic and _bool_value(basic.get("Value")):
        _add(
            result,
            severity="medium",
            title=f"WinRM Basic authentication is enabled on {host}",
            description="Basic authentication sends credentials with weak protection and is unnecessary with NTLM or Kerberos.",
            evidence=f"Host: {host}\nService\\Auth\\Basic = true",
            remediation="Disable WinRM Basic authentication (Set-Item WSMan:\\localhost\\Service\\Auth\\Basic $false).",
            key=f"auth-winrm-basic:{host}",
            location=host,
            cwe="CWE-522",
        )

