import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

AGENT_PATH = Path(__file__).resolve().parent.parent / "agent" / "vulnscanner_agent.py"
POWERSHELL_AGENT_PATH = AGENT_PATH.parent / "VulnScannerAgent.ps1"
POWERSHELL_INSTALLER_PATH = AGENT_PATH.parent / "install-windows-agent.ps1"


def _load_agent():
    spec = importlib.util.spec_from_file_location("vulnscanner_agent_test", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def agent():
    return _load_agent()


def test_agent_capabilities(agent):
    capabilities = agent.capabilities()
    assert {"system", "packages", "ports", "network", "secrets", "repo"}.issubset(capabilities)
    if sys.platform == "win32":
        assert "ad" in capabilities
    else:
        assert "ad" not in capabilities


def test_agent_redaction_and_entropy(agent):
    secret = "AKIAIOSFODNN7EXAMPLE"
    redacted = agent._redact(secret)
    assert secret not in redacted
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert agent._redact("tiny") == "****"
    assert agent._entropy("") == 0.0
    assert agent._entropy("aaaaaaaa") == 0.0
    assert agent._entropy("aB3dE5fG7hJ9") > 3.5


@pytest.mark.parametrize(
    "name, text, expected",
    [
        ("requirements.txt", "requests==2.31.0\nrich>=13\n", [("requests", "2.31.0", "PyPI")]),
        (
            "package.json",
            json.dumps({"dependencies": {"express": "^4.18.2"}}),
            [("express", "4.18.2", "npm")],
        ),
        (
            "package-lock.json",
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}}),
            [("lodash", "4.17.21", "npm")],
        ),
        (
            "pyproject.toml",
            '[project]\ndependencies = ["requests==2.31.0"]\n',
            [("requests", "2.31.0", "PyPI")],
        ),
        ("go.mod", "module x\nrequire github.com/gin-gonic/gin v1.9.1\n", [("github.com/gin-gonic/gin", "v1.9.1", "Go")]),
        (
            "composer.lock",
            json.dumps({"packages": [{"name": "monolog/monolog", "version": "v3.5.0"}]}),
            [("monolog/monolog", "3.5.0", "Packagist")],
        ),
        (
            "Gemfile.lock",
            "specs:\n    rails (7.1.2)\n",
            [("rails", "7.1.2", "RubyGems")],
        ),
        (
            "Cargo.lock",
            '[[package]]\nname = "serde"\nversion = "1.0.190"\n',
            [("serde", "1.0.190", "crates.io")],
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId>"
            "<artifactId>demo</artifactId><version>1.2.3</version></dependency></dependencies></project>",
            [("org.example:demo", "1.2.3", "Maven")],
        ),
        (
            "App.csproj",
            '<Project><ItemGroup><PackageReference Include="Serilog" Version="3.1.1" /></ItemGroup></Project>',
            [("Serilog", "3.1.1", "NuGet")],
        ),
    ],
)
def test_agent_manifest_parsing(agent, name, text, expected):
    packages = agent._parse_manifest_text(name, text)
    assert [(p["name"], p["version"], p["ecosystem"]) for p in packages] == expected


def test_agent_secret_scanning(tmp_path, agent):
    (tmp_path / "config.py").write_text(
        'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    (tmp_path / "normal.txt").write_text("nothing to see here\n", encoding="utf-8")
    findings, errors, files = agent.scan_secret_files([str(tmp_path)])
    assert errors == []
    assert files >= 2
    assert any(finding["raw"]["rule"] == "aws-access-key" for finding in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in finding["evidence"] for finding in findings)


def test_agent_manifest_paths(tmp_path, agent):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    packages, errors = agent.collect_manifest_packages([str(tmp_path)])
    assert errors == []
    assert [(p["name"], p["version"]) for p in packages] == [("requests", "2.31.0")]


def test_agent_collect_job_handles_missing_paths(agent):
    result = agent.collect_job(
        {"payload": {"modules": ["secrets", "repo"], "paths": [], "options": {}}}
    )
    assert result["modules"] == ["secrets", "repo"]
    assert any("without paths" in warning for warning in result["warnings"])
    assert result["secrets"] == []


def test_agent_network_port_and_target_parsing(agent):
    assert agent.agent_parse_ports("80,22-24") == [22, 23, 24, 80]
    assert 80 in agent.agent_parse_ports(None, "web")
    assert 443 in agent.agent_parse_ports("web")
    with pytest.raises(ValueError, match="5000"):
        agent.agent_parse_ports("1-6000")
    with pytest.raises(ValueError, match="Invalid port"):
        agent.agent_parse_ports("70000")
    assert agent.agent_expand_targets("192.0.2.0/30") == ["192.0.2.1", "192.0.2.2"]
    assert agent.agent_expand_targets("192.0.2.10") == ["192.0.2.10"]
    with pytest.raises(ValueError, match="limit is 256"):
        agent.agent_expand_targets("10.0.0.0/23")


def test_agent_collect_network(agent, monkeypatch):
    calls = []

    def fake_probe(host, port, timeout):
        calls.append((host, port))
        if port == 80:
            return {"host": host, "port": port, "service": "http", "banner": ""}
        return None

    monkeypatch.setattr(agent, "_probe_network_port", fake_probe)
    result = agent.collect_network(
        "192.0.2.10", {"ports": "22,80", "workers": 10, "connect_timeout": 0.1}
    )
    assert result["host_count"] == 1
    assert result["ports_scanned"] == 2
    assert [item["port"] for item in result["open_ports"]] == [80]
    assert {call[1] for call in calls} == {22, 80}
    assert result["started_at"] and result["finished_at"]


def test_agent_configure_command(tmp_path, agent):
    from types import SimpleNamespace

    config_path = tmp_path / "agent.json"
    args = SimpleNamespace(
        config=str(config_path),
        server="https://scanner.example.com/",
        name="web01",
        token="vs_agent_example",
        poll_interval=45,
        insecure=False,
        verify_tls=True,
    )
    assert agent.command_configure(args) == 0
    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert data["server"] == "https://scanner.example.com"
    assert data["name"] == "web01"
    assert data["token"] == "vs_agent_example"
    assert data["poll_interval"] == 45
    assert data["verify_tls"] is True


def test_powershell_scripts_parse():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is not available")
    parser = (
        "$errors = $null; $tokens = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "'" + "{path}" + "', [ref]$tokens, [ref]$errors); "
        "if ($errors) { $errors | ForEach-Object { $_.Message }; exit 1 }"
    )
    for path in (POWERSHELL_AGENT_PATH, POWERSHELL_INSTALLER_PATH):
        escaped = str(path).replace("'", "''")
        command = parser.replace("{path}", escaped)
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"{path.name}: {result.stdout} {result.stderr}"


def test_windows_agent_and_installer_contents():
    agent_text = POWERSHELL_AGENT_PATH.read_text(encoding="utf-8")
    installer_text = POWERSHELL_INSTALLER_PATH.read_text(encoding="utf-8")
    assert "[ValidateSet(\"Enroll\", \"Configure\", \"Run\", \"Status\", \"Scan\")]" in agent_text
    assert "network" in agent_text
    assert "pending-result.json" in agent_text
    assert "-Configure" in installer_text
    assert "ServiceAccount" in installer_text
    assert "Register-ScheduledTask" in installer_text
    assert "VulnScanner Agent" in installer_text
    assert "icacls" in installer_text
