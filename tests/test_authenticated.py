"""Authenticated SSH/WinRM inventory and finding tests."""

from __future__ import annotations

import json
import types

import pytest

from app.scanners import authenticated
from app.scanners.authenticated import (
    AuthFailed,
    _add_linux_findings,
    _add_windows_findings,
    _attempt_host,
    _windows_eol,
    authenticated_scan,
    parse_linux_output,
    parse_windows_output,
    select_target_os,
)
from app.scanners.base import ScanResult
from app.scanners.network import PortResult
from tests.helpers import DummyContext

LINUX_OUTPUT = """===VS:OS===
NAME="Ubuntu"
VERSION_ID="20.04"
PRETTY_NAME="Ubuntu 20.04.6 LTS"
ID=ubuntu
Linux 5.4.0-1 x86_64
svcuser
===VS:PACKAGES===
openssl\t1.1.1f-1ubuntu2
bash\t5.0-6ubuntu1
===VS:UPDATES===
openssl
bash
===VS:REBOOT===
no
===VS:PORTS===
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 4096 0.0.0.0:6379 0.0.0.0:* users:(("redis",pid=2,fd=4))
tcp LISTEN 0 4096 127.0.0.1:8080 127.0.0.1:* users:(("local",pid=3,fd=5))
===VS:PASSWD===
root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/bash
guest::1000:1000::/home/guest:/bin/bash
===VS:GROUPS===
sudo:x:27:svcuser
svcuser ALL=(ALL) NOPASSWD: ALL
===VS:SSHD===
permitrootlogin yes
passwordauthentication yes
permitemptypasswords no
===VS:FIREWALL===
Status: inactive
===VS:KERNEL===
5.4.0-1
===VS:END===
"""

WINDOWS_PAYLOAD = {
    "os": {
        "Caption": "Microsoft Windows Server 2012 R2 Standard",
        "Version": "6.3.9600",
        "BuildNumber": "9600",
        "OSArchitecture": "64-bit",
        "InstallDate": "/Date(1600000000000)/",
    },
    "computer": {"Name": "WIN01", "Domain": "CORP", "PartOfDomain": True},
    "hotfixes": [
        {"HotFixID": "KB5000001", "Description": "Security Update", "InstalledOn": "/Date(1600000000000)/"}
    ],
    "software": [
        {"DisplayName": "Adobe Flash Player 32", "DisplayVersion": "32.0.0.465", "Publisher": "Adobe"}
    ],
    "users": [
        {"Name": "Guest", "Enabled": True, "PasswordRequired": False},
        {"Name": "svc", "Enabled": True, "PasswordRequired": True},
    ],
    "admins": [
        {"Name": "CORP\\Domain Admins", "ObjectClass": "Group", "PrincipalSource": "ActiveDirectory"}
    ],
    "ports": [
        {"LocalAddress": "0.0.0.0", "LocalPort": 3389},
        {"LocalAddress": "127.0.0.1", "LocalPort": 5985},
    ],
    "services": [{"Name": "Spooler", "DisplayName": "Print Spooler"}],
    "defender": {"AntivirusEnabled": False, "RealTimeProtectionEnabled": False},
    "firewall": [{"Name": "Domain", "Enabled": False}, {"Name": "Public", "Enabled": True}],
    "smb": {"EnableSMB1Protocol": True, "RequireSecuritySignature": False},
    "rdp": {"fDenyTSConnections": 0},
    "rdp_nla": {"UserAuthentication": 0},
    "uac": {"EnableLUA": 0},
    "autologon": {"AutoAdminLogon": "1", "DefaultUserName": "admin", "DefaultDomainName": "CORP"},
    "always_install": {"AlwaysInstallElevated": 1},
    "winrm": [{"Name": "Basic", "Value": True}],
    "ps_logging": {"EnableScriptBlockLogging": 0},
    "unquoted": [
        {"Name": "svc", "PathName": "C:\\Program Files\\x\\svc.exe", "StartMode": "Auto"}
    ],
    "password_policy": "Minimum password length                                0",
}


def test_parse_linux_output_and_findings():
    inventory = parse_linux_output(LINUX_OUTPUT)
    assert inventory["os_release"]["ID"] == "ubuntu"
    assert inventory["kernel"] == "5.4.0-1"
    assert inventory["packages"] == [("openssl", "1.1.1f-1ubuntu2"), ("bash", "5.0-6ubuntu1")]
    assert inventory["updates"] == ["openssl", "bash"]
    assert inventory["reboot_required"] is False
    assert inventory["firewall"] is False
    assert {item["port"] for item in inventory["ports"]} == {22, 6379, 8080}
    assert "toor" in [user["name"] for user in inventory["users"]]

    result = ScanResult()
    ctx = DummyContext()
    _add_linux_findings(result, ctx, "192.0.2.10", inventory)
    keys = {finding["key"] for finding in result.normalized()}
    assert "auth-os-eol:192.0.2.10" in keys
    assert "auth-updates:192.0.2.10" in keys
    assert "auth-uid0:192.0.2.10:toor" in keys
    assert "auth-empty-password:192.0.2.10:guest" in keys
    assert "auth-ssh-root:192.0.2.10" in keys
    assert "auth-ssh-password:192.0.2.10" in keys
    assert "auth-firewall:192.0.2.10" in keys
    assert "auth-risky-port:192.0.2.10:6379" in keys
    # Loopback-only services are not reported as exposed.
    assert "auth-risky-port:192.0.2.10:8080" not in keys
    assert result.metadata["host_inventory"][0]["method"] == "ssh"


def test_parse_windows_output_and_findings():
    inventory = parse_windows_output(json.dumps(WINDOWS_PAYLOAD))
    assert inventory["os"]["build"] == "9600"
    assert inventory["os"]["install_date"].startswith("2020-09")
    assert inventory["hotfixes"][0]["id"] == "KB5000001"
    assert len(inventory["software"]) == 1
    assert inventory["ports"][0] == {"address": "0.0.0.0", "port": 3389, "protocol": "tcp"}
    assert inventory["firewall"] == {"Domain": False, "Public": True}
    assert inventory["password_policy"]["min_length"] == 0
    assert inventory["computer"]["part_of_domain"] is True

    inventory["winrm_port"] = 5985
    inventory["winrm_https"] = False
    result = ScanResult()
    _add_windows_findings(result, DummyContext(), "192.0.2.20", inventory)
    keys = {finding["key"] for finding in result.normalized()}
    for key in (
        "auth-os-eol:192.0.2.20",
        "auth-patch-stale:192.0.2.20",
        "auth-guest:192.0.2.20",
        "auth-defender:192.0.2.20",
        "auth-firewall:192.0.2.20",
        "auth-smb1:192.0.2.20",
        "auth-smb-signing:192.0.2.20",
        "auth-rdp-nla:192.0.2.20",
        "auth-uac:192.0.2.20",
        "auth-autologon:192.0.2.20",
        "auth-always-install:192.0.2.20",
        "auth-ps-logging:192.0.2.20",
        "auth-unquoted:192.0.2.20:svc",
        "auth-winrm-http:192.0.2.20",
        "auth-winrm-basic:192.0.2.20",
        "auth-password-length:192.0.2.20",
        "auth-local-admins:192.0.2.20",
    ):
        assert key in keys, key
    assert any("Adobe Flash" in finding["title"] for finding in result.normalized())


def test_windows_eol_detection():
    result = ScanResult()
    _windows_eol(result, "192.0.2.20", "Windows Server 2008 R2 Standard", "7601")
    assert result.normalized()[0]["severity"] == "critical"

    current = ScanResult()
    _windows_eol(current, "192.0.2.21", "Windows 11 Pro", "22631")
    assert current.findings == []


def test_parse_windows_output_rejects_garbage():
    from app.scanners.authenticated import ConnectionFailed

    with pytest.raises(ConnectionFailed):
        parse_windows_output("")
    with pytest.raises(ConnectionFailed):
        parse_windows_output("not json")


def test_select_target_os_prefers_indicators():
    linux_ports = [PortResult("192.0.2.10", 22, "SSH-2.0-OpenSSH_9.6")]
    windows_ports = [
        PortResult("192.0.2.11", 3389, ""),
        PortResult("192.0.2.11", 22, "SSH-2.0-OpenSSH_for_Windows_8.1"),
    ]
    assert select_target_os(linux_ports, "auto", {"linux"}) == "linux"
    assert select_target_os(windows_ports, "auto", {"windows"}) == "windows"
    assert select_target_os(windows_ports, "linux", {"linux"}) == "linux"
    assert select_target_os(linux_ports, "windows", {"linux"}) is None


def test_authenticated_scan_attempts_each_host_once(monkeypatch):
    calls: list[str] = []

    def resolve(scan_id, os_name):
        return {"username": "svc", "secret": "pw", "auth_type": "password", "source": "scan"} if os_name == "linux" else None

    monkeypatch.setattr(authenticated, "resolve_for_scan", resolve)
    monkeypatch.setattr(authenticated, "_attempt_host", lambda *args, **kwargs: calls.append(args[2]))
    ctx = DummyContext({"authenticated": True, "target_os": "linux", "max_auth_hosts": 10})
    result = ScanResult()
    authenticated_scan(
        result,
        ctx,
        {
            "192.0.2.10": [PortResult("192.0.2.10", 22)],
            "192.0.2.11": [PortResult("192.0.2.11", 22)],
        },
    )
    assert calls == ["192.0.2.10", "192.0.2.11"]


def test_authenticated_scan_respects_host_limit(monkeypatch):
    calls: list[str] = []

    def resolve(scan_id, os_name):
        return {"username": "svc", "secret": "pw", "auth_type": "password"} if os_name == "linux" else None

    monkeypatch.setattr(authenticated, "resolve_for_scan", resolve)
    monkeypatch.setattr(authenticated, "_attempt_host", lambda *args, **kwargs: calls.append(args[2]))
    ctx = DummyContext({"authenticated": True, "max_auth_hosts": 1})
    authenticated_scan(
        ScanResult(),
        ctx,
        {
            "192.0.2.10": [PortResult("192.0.2.10", 22)],
            "192.0.2.11": [PortResult("192.0.2.11", 22)],
        },
    )
    assert calls == ["192.0.2.10"]
    assert any("limited to 1 host" in message for _level, message in ctx.logs)


def test_authentication_failure_is_reported_without_retry(monkeypatch):
    attempts: list[int] = []

    def fail(*args, **kwargs):
        attempts.append(1)
        raise AuthFailed("rejected")

    monkeypatch.setattr(authenticated, "collect_linux", fail)
    result = ScanResult()
    ctx = DummyContext()
    _attempt_host(
        result,
        ctx,
        "192.0.2.10",
        [PortResult("192.0.2.10", 22)],
        "linux",
        {"username": "svc", "secret": "pw", "auth_type": "password", "source": "scan"},
        5.0,
    )
    assert len(attempts) == 1
    findings = result.normalized()
    assert [finding["key"] for finding in findings] == ["auth-failed:192.0.2.10:linux"]
    assert "rejected" in findings[0]["evidence"]
    assert result.metadata["authenticated"][0]["authenticated"] is False
    assert "pw" not in findings[0]["evidence"]


def test_winrm_invalid_credentials_maps_to_auth_failure(monkeypatch):
    class InvalidCredentialsError(Exception):
        pass

    class FakeSession:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def run_ps(self, _script):
            raise InvalidCredentialsError("401 Unauthorized")

    monkeypatch.setattr(authenticated, "_winrm", lambda: types.SimpleNamespace(Session=FakeSession))
    with pytest.raises(AuthFailed):
        authenticated.collect_windows(
            "192.0.2.20",
            {"username": "svc", "secret": "pw", "auth_type": "password"},
            5.0,
            DummyContext(),
        )


def test_winrm_endpoint_uses_domain_and_https_options(monkeypatch):
    captured = {}

    class FakeSession:
        def __init__(self, endpoint, **kwargs):
            captured["endpoint"] = endpoint
            captured["kwargs"] = kwargs

        def run_ps(self, _script):
            return types.SimpleNamespace(status_code=0, std_out=json.dumps(WINDOWS_PAYLOAD).encode(), std_err=b"")

    monkeypatch.setattr(authenticated, "_winrm", lambda: types.SimpleNamespace(Session=FakeSession))
    ctx = DummyContext({"winrm_https": True, "winrm_port": 5986, "winrm_transport": "ntlm"})
    inventory = authenticated.collect_windows(
        "192.0.2.20",
        {"username": "svc", "domain": "CORP", "account_type": "domain", "secret": "pw"},
        5.0,
        ctx,
    )
    assert captured["endpoint"] == "https://192.0.2.20:5986/wsman"
    assert captured["kwargs"]["auth"] == ("CORP\\svc", "pw")
    assert captured["kwargs"]["server_cert_validation"] == "ignore"
    assert inventory["winrm_https"] is True
