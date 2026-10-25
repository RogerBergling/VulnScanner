import importlib.util
import json
import sys
from pathlib import Path

import pytest

AGENT_PATH = Path(__file__).resolve().parent.parent / "agent" / "vulnscanner_agent.py"


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
    assert {"system", "packages", "ports", "secrets", "repo"}.issubset(capabilities)
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
