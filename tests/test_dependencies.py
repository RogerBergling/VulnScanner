import json
import subprocess

from app.scanners import osv
from app.scanners.base import ScanResult
from app.scanners.dependencies import (
    PackageRef,
    discover_and_parse,
    findings_from_osv,
    parse_manifest,
    scan_dependencies,
)
from tests.helpers import DummyContext


def test_requirements_parsing(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        "# comment\n"
        "Requests==2.31.0\n"
        "Django[argon2]>=4.2\n"
        "flask===3.0.1  # pinned\n"
        "-r other.txt\n"
        "git+https://example.com/a.git\n",
        encoding="utf-8",
    )
    packages = parse_manifest(path)
    assert [(p.name, p.version) for p in packages] == [
        ("requests", "2.31.0"),
        ("flask", "3.0.1"),
    ]


def test_package_lock_and_package_json(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "app"},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/dev-only": {"version": "1.0.0", "dev": True},
                    "node_modules/link": {"link": True, "version": "1.0.0"},
                }
            }
        ),
        encoding="utf-8",
    )
    packages = parse_manifest(lock)
    assert {(p.name, p.version, p.dev) for p in packages} == {
        ("lodash", "4.17.20", False),
        ("dev-only", "1.0.0", True),
    }

    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {"express": "^4.18.2", "range-only": ">=1.0"},
                "devDependencies": {"jest": "~29.7.0"},
            }
        ),
        encoding="utf-8",
    )
    packages = parse_manifest(manifest)
    assert {(p.name, p.version) for p in packages} == {
        ("express", "4.18.2"),
        ("jest", "29.7.0"),
    }


def test_pyproject_poetry_and_pipfile(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["requests==2.31.0", "rich>=13"]
[project.optional-dependencies]
dev = ["pytest==8.0.0"]
[tool.poetry.dependencies]
python = "^3.11"
click = "8.1.7"
""",
        encoding="utf-8",
    )
    packages = parse_manifest(pyproject)
    assert {(p.name, p.version, p.dev) for p in packages} == {
        ("requests", "2.31.0", False),
        ("pytest", "8.0.0", True),
        ("click", "8.1.7", False),
    }

    poetry = tmp_path / "poetry.lock"
    poetry.write_text(
        '[[package]]\nname = "Urllib3"\nversion = "2.0.7"\n', encoding="utf-8"
    )
    assert [(p.name, p.version) for p in parse_manifest(poetry)] == [("urllib3", "2.0.7")]

    pipfile = tmp_path / "Pipfile.lock"
    pipfile.write_text(
        json.dumps(
            {
                "default": {"requests": {"version": "==2.31.0"}},
                "develop": {"pytest": {"version": "==8.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    assert {(p.name, p.version, p.dev) for p in parse_manifest(pipfile)} == {
        ("requests", "2.31.0", False),
        ("pytest", "8.0.0", True),
    }


def _run_osv_scanner_supplement(monkeypatch, data_dir, tmp_path, payload, existing=None):
    from app.scanners import dependencies

    result = ScanResult()
    for item in existing or []:
        result.add(item)
    monkeypatch.setattr(dependencies, "ENABLE_EXTERNAL_APIS", True)
    monkeypatch.setattr(dependencies, "tool_path", lambda name: "/usr/bin/osv-scanner")
    monkeypatch.setattr(
        dependencies,
        "run_tool",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, json.dumps(payload), ""),
    )
    return dependencies._run_osv_scanner(DummyContext({"external_tools": True}), tmp_path, result), result


def test_osv_scanner_supplement_parses_and_deduplicates(monkeypatch, data_dir, tmp_path):
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-test",
                                "aliases": ["CVE-2026-0001"],
                                "summary": "Test advisory",
                                "affected": [
                                    {"ranges": [{"events": [{"fixed": "2.32.0"}]}]}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    existing = {
        "severity": "high",
        "title": "Already found",
        "category": "dependency",
        "raw": {
            "osv_id": "GHSA-test",
            "package": "requests",
            "version": "2.31.0",
        },
    }
    count, result = _run_osv_scanner_supplement(
        monkeypatch, data_dir, tmp_path, payload, existing=[existing]
    )
    assert count == 0
    assert len(result.findings) == 1

    count, result = _run_osv_scanner_supplement(monkeypatch, data_dir, tmp_path, payload)
    assert count == 1
    finding = result.findings[0]
    assert finding.cve == "CVE-2026-0001"
    assert finding.raw["detected_by"] == "osv-scanner"
    assert finding.resource == "requests@2.31.0"

    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/app\nrequire github.com/gin-gonic/gin v1.9.1\n", encoding="utf-8"
    )
    assert [(p.name, p.version, p.ecosystem) for p in parse_manifest(go_mod)] == [
        ("github.com/gin-gonic/gin", "v1.9.1", "Go")
    ]

    composer = tmp_path / "composer.lock"
    composer.write_text(
        json.dumps({"packages": [{"name": "monolog/monolog", "version": "v3.5.0"}]}),
        encoding="utf-8",
    )
    assert [(p.name, p.version) for p in parse_manifest(composer)] == [("monolog/monolog", "3.5.0")]

    gemfile = tmp_path / "Gemfile.lock"
    gemfile.write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.2)\n    rake (13.0.6)\n\nPLATFORMS\n",
        encoding="utf-8",
    )
    assert [(p.name, p.version) for p in parse_manifest(gemfile)] == [
        ("rails", "7.1.2"),
        ("rake", "13.0.6"),
    ]

    cargo = tmp_path / "Cargo.lock"
    cargo.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.190"\n', encoding="utf-8"
    )
    assert [(p.name, p.version, p.ecosystem) for p in parse_manifest(cargo)] == [
        ("serde", "1.0.190", "crates.io")
    ]


def test_maven_gradle_and_nuget_manifests(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
<dependencies><dependency><groupId>org.example</groupId>
<artifactId>demo</artifactId><version>1.2.3</version></dependency>
<dependency><groupId>bad</groupId><artifactId>prop</artifactId><version>${x}</version></dependency>
</dependencies></project>""",
        encoding="utf-8",
    )
    assert [(p.name, p.version, p.ecosystem) for p in parse_manifest(pom)] == [
        ("org.example:demo", "1.2.3", "Maven")
    ]

    gradle = tmp_path / "build.gradle"
    gradle.write_text(
        "dependencies {\n  implementation 'com.google.guava:guava:32.1.2-jre'\n}\n",
        encoding="utf-8",
    )
    assert [(p.name, p.version) for p in parse_manifest(gradle)] == [
        ("com.google.guava:guava", "32.1.2-jre")
    ]

    nuget = tmp_path / "packages.config"
    nuget.write_text(
        '<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>',
        encoding="utf-8",
    )
    assert [(p.name, p.version, p.ecosystem) for p in parse_manifest(nuget)] == [
        ("Newtonsoft.Json", "13.0.3", "NuGet")
    ]

    csproj = tmp_path / "App.csproj"
    csproj.write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" Version="3.1.1" />'
        '<PackageReference Include="Ignored" Version="$(Version)" /></ItemGroup></Project>',
        encoding="utf-8",
    )
    assert [(p.name, p.version) for p in parse_manifest(csproj)] == [("Serilog", "3.1.1")]


def test_yarn_pnpm_parsing(tmp_path):
    yarn = tmp_path / "yarn.lock"
    yarn.write_text(
        'lodash@^4.17.20:\n  version "4.17.21"\n\n"@scope/pkg@^1.0.0":\n  version "1.2.3"\n',
        encoding="utf-8",
    )
    assert {(p.name, p.version) for p in parse_manifest(yarn)} == {
        ("lodash", "4.17.21"),
        ("@scope/pkg", "1.2.3"),
    }

    pnpm = tmp_path / "pnpm-lock.yaml"
    pnpm.write_text("  /lodash@4.17.21:\n  /@scope/pkg@1.2.3:\n", encoding="utf-8")
    assert {(p.name, p.version) for p in parse_manifest(pnpm)} == {
        ("lodash", "4.17.21"),
        ("@scope/pkg", "1.2.3"),
    }


def test_discover_dedupes_and_skips_binary_directories(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    sub = tmp_path / "service"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text(
        '{"dependencies":{"evil":"1.0.0"}}', encoding="utf-8"
    )
    packages = discover_and_parse(tmp_path)
    assert [(p.name, p.version) for p in packages] == [("requests", "2.31.0")]
    assert packages[0].source == "requirements.txt"


def test_findings_from_osv_maps_advisory_to_finding():
    packages = [PackageRef("lodash", "4.17.20", "npm", "package-lock.json")]
    matches = {
        0: [
            {
                "id": "GHSA-test-0001",
                "aliases": ["CVE-2026-1234"],
                "summary": "Prototype pollution in lodash",
                "details": "A detailed advisory.",
                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [
                    {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
                ],
                "references": [{"url": "https://example.test/advisory"}],
            }
        ]
    }
    result = ScanResult()
    count = findings_from_osv(packages, matches, result)
    finding = result.normalized()[0]
    assert count == 1
    assert finding["severity"] == "critical"
    assert finding["cvss"] == 9.8
    assert finding["cve"] == "CVE-2026-1234"
    assert "Upgrade lodash to 4.17.21" in finding["remediation"]
    assert finding["raw"]["fixed_versions"] == ["4.17.21"]


def test_query_packages_uses_cache_and_skips_without_external_access(data_dir, monkeypatch):
    packages = [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}]
    assert osv.query_packages(packages) == {}

    monkeypatch.setattr(osv, "ENABLE_EXTERNAL_APIS", True)
    monkeypatch.setattr(osv, "get_setting", lambda *_args, **_kwargs: "true")
    calls = {"batch": 0, "detail": 0}

    def fake_batch(payload):
        calls["batch"] += 1
        assert payload["queries"][0]["package"]["name"] == "requests"
        return {"results": [{"vulns": [{"id": "PYSEC-2026-1"}]}]}

    def fake_detail(vuln_id, allow_offline=False):
        calls["detail"] += 1
        return {"id": vuln_id, "summary": "Test advisory", "severity": [{"score": 8.0}]}

    monkeypatch.setattr(osv, "_post_batch", fake_batch)
    monkeypatch.setattr(osv, "_get_vuln", fake_detail)
    first = osv.query_packages(packages)
    assert first[0][0]["id"] == "PYSEC-2026-1"
    assert calls == {"batch": 1, "detail": 1}

    monkeypatch.setattr(osv, "_post_batch", lambda *_args: (_ for _ in ()).throw(AssertionError("cache miss")))
    second = osv.query_packages(packages)
    assert second[0][0]["id"] == "PYSEC-2026-1"


def test_scan_dependencies_survives_osv_failure(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.scanners.dependencies.enrich_packages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    ctx = DummyContext()
    result = scan_dependencies(ctx, tmp_path)
    assert result.metadata["packages_found"] == 1
    assert "offline" in result.metadata["osv_error"]
    assert any("Dependency lookup failed" in message for _level, message in ctx.logs)
