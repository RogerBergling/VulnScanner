"""Software composition analysis using local lockfiles and OSV.dev."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import ENABLE_EXTERNAL_APIS
from ..database import get_setting
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult
from .cvss import osv_severity
from .filesystem import iter_files, read_text_file, relative_path
from .osv import OsvUnavailable, query_packages
from .tools import run_tool, tool_path

MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "poetry.lock",
    "pyproject.toml", "go.mod", "composer.lock", "Gemfile.lock", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "packages.config",
    "pubspec.lock",
}
MANIFEST_SUFFIXES = {".csproj"}
MAX_PACKAGES = 6000


@dataclass
class PackageRef:
    name: str
    version: str
    ecosystem: str
    source: str = ""
    dev: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def as_query(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
        }


def _normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _exact_pep508(spec: str) -> str | None:
    match = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)",
        spec.strip(),
    )
    return f"{_normalize_pypi(match.group(1))}=={match.group(2)}" if match else None


def _parse_requirements(path: Path) -> list[PackageRef]:
    packages = []
    for raw in read_text_file(path).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", "file:")):
            continue
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)",
            line,
        )
        if match:
            packages.append(
                PackageRef(
                    _normalize_pypi(match.group(1)),
                    match.group(2),
                    "PyPI",
                    path.name,
                )
            )
    return packages


def _parse_package_lock(path: Path) -> list[PackageRef]:
    data = json.loads(read_text_file(path))
    packages: list[PackageRef] = []
    entries = data.get("packages")
    if isinstance(entries, dict):
        for key, item in entries.items():
            if not isinstance(item, dict) or item.get("link"):
                continue
            version = item.get("version")
            if not version:
                continue
            if key == "":
                continue
            name = item.get("name")
            if not name:
                name = key.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            packages.append(
                PackageRef(
                    str(name),
                    str(version),
                    "npm",
                    path.name,
                    bool(item.get("dev")),
                )
            )
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps: dict[str, Any]) -> None:
            for name, item in deps.items():
                if not isinstance(item, dict):
                    continue
                version = item.get("version")
                if version:
                    packages.append(PackageRef(name, str(version), "npm", path.name))
                if isinstance(item.get("dependencies"), dict):
                    walk(item["dependencies"])

        walk(data["dependencies"])
    return packages


def _parse_package_json(path: Path) -> list[PackageRef]:
    data = json.loads(read_text_file(path))
    packages: list[PackageRef] = []
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        for name, version in (data.get(section) or {}).items():
            value = str(version).lstrip("=~^<> ")
            # Only report caret/tilde specs that still name a concrete
            # version; open ranges such as ">=1.0" do not identify an
            # installed release and would produce false OSV matches.
            if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", value):
                packages.append(PackageRef(name, value, "npm", path.name, dev))
    return packages


def _parse_yarn_lock(path: Path) -> list[PackageRef]:
    text = read_text_file(path)
    packages: list[PackageRef] = []
    if "__metadata:" in text:
        return packages
    blocks = re.split(r"\n\s*\n", text)
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        header = lines[0].strip().rstrip(":")
        first = header.split(",")[0].strip().strip('"')
        name_match = re.match(r"^((?:@[^/]+/)?[^@]+)@", first)
        version_match = re.search(r"^\s+version\s+\"?([^\"\s]+)\"?", block, re.M)
        if name_match and version_match:
            packages.append(
                PackageRef(name_match.group(1), version_match.group(1), "npm", path.name)
            )
    return packages


def _parse_pnpm_lock(path: Path) -> list[PackageRef]:
    packages = []
    for line in read_text_file(path).splitlines():
        match = re.match(r"^\s{2}/?((?:@[^/]+/)?[^@\s]+)@([^:\s]+):\s*$", line)
        if match:
            packages.append(PackageRef(match.group(1), match.group(2), "npm", path.name))
    return packages


def _parse_pyproject(path: Path) -> list[PackageRef]:
    data = tomllib.loads(read_text_file(path))
    specs: list[tuple[str, bool]] = []
    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        specs.append((str(spec), False))
    for group in (project.get("optional-dependencies") or {}).values():
        for spec in group or []:
            specs.append((str(spec), True))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for section in ("dependencies", "dev-dependencies"):
        for name, version in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            if isinstance(version, str):
                cleaned = version.lstrip("^~>=< ")
                if re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?", cleaned):
                    specs.append((f"{name}=={cleaned}", section == "dev-dependencies"))
            elif isinstance(version, dict) and version.get("version"):
                cleaned = str(version["version"]).lstrip("^~>=< ")
                if re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?", cleaned):
                    specs.append((f"{name}=={cleaned}", section == "dev-dependencies"))
    packages = []
    for spec, dev in specs:
        exact = _exact_pep508(spec)
        if exact:
            name, version = exact.split("==", 1)
            packages.append(PackageRef(name, version, "PyPI", path.name, dev))
    return packages


def _parse_pipfile_lock(path: Path) -> list[PackageRef]:
    data = json.loads(read_text_file(path))
    packages = []
    for section, dev in (("default", False), ("develop", True)):
        for name, item in (data.get(section) or {}).items():
            if not isinstance(item, dict):
                continue
            version = str(item.get("version") or "").lstrip("= ")
            if version and re.fullmatch(r"[\w.+-]+", version):
                packages.append(PackageRef(_normalize_pypi(name), version, "PyPI", path.name, dev))
    return packages


def _parse_poetry_lock(path: Path) -> list[PackageRef]:
    data = tomllib.loads(read_text_file(path))
    packages = []
    for item in data.get("package") or []:
        name = item.get("name")
        version = item.get("version")
        if name and version:
            packages.append(
                PackageRef(_normalize_pypi(str(name)), str(version), "PyPI", path.name)
            )
    return packages


def _parse_go_mod(path: Path) -> list[PackageRef]:
    packages = []
    for line in read_text_file(path).splitlines():
        line = line.split("//", 1)[0].strip()
        match = re.match(r"^(?:require\s+)?([\w.\-/]+)\s+(v[\w.+-]+)$", line)
        if match:
            packages.append(PackageRef(match.group(1), match.group(2), "Go", path.name))
    return packages


def _parse_composer_lock(path: Path) -> list[PackageRef]:
    data = json.loads(read_text_file(path))
    packages = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for item in data.get(section) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            version = str(item.get("version") or "").lstrip("v")
            if name and version:
                packages.append(PackageRef(name, version, "Packagist", path.name, dev))
    return packages


def _parse_gemfile_lock(path: Path) -> list[PackageRef]:
    packages = []
    in_specs = False
    for line in read_text_file(path).splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
        if match:
            packages.append(PackageRef(match.group(1), match.group(2), "RubyGems", path.name))
    return packages


def _parse_cargo_lock(path: Path) -> list[PackageRef]:
    data = tomllib.loads(read_text_file(path))
    return [
        PackageRef(str(item["name"]), str(item["version"]), "crates.io", path.name)
        for item in data.get("package") or []
        if item.get("name") and item.get("version")
    ]


def _parse_pom(path: Path) -> list[PackageRef]:
    packages = []
    try:
        root = ET.fromstring(read_text_file(path))
    except ET.ParseError:
        return packages
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"
    for dep in root.iter(f"{namespace}dependency"):
        group = dep.findtext(f"{namespace}groupId") or ""
        artifact = dep.findtext(f"{namespace}artifactId") or ""
        version = (dep.findtext(f"{namespace}version") or "").strip()
        if group and artifact and version and "${" not in version:
            packages.append(
                PackageRef(f"{group}:{artifact}", version, "Maven", path.name)
            )
    return packages


def _parse_gradle(path: Path) -> list[PackageRef]:
    packages = []
    pattern = re.compile(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[(\s]\s*['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]"
    )
    for match in pattern.finditer(read_text_file(path)):
        packages.append(
            PackageRef(f"{match.group(1)}:{match.group(2)}", match.group(3), "Maven", path.name)
        )
    return packages


def _parse_nuget(path: Path) -> list[PackageRef]:
    packages = []
    try:
        root = ET.fromstring(read_text_file(path))
    except ET.ParseError:
        return packages
    for package in root.iter("package"):
        name = package.attrib.get("id")
        version = package.attrib.get("version")
        if name and version:
            packages.append(PackageRef(name, version, "NuGet", path.name))
    for package in root.iter():
        if package.tag.endswith("PackageReference"):
            name = package.attrib.get("Include")
            version = package.attrib.get("Version")
            if not version:
                node = package.find("Version")
                version = node.text if node is not None else None
            if name and version and "$(" not in version:
                packages.append(PackageRef(name, version, "NuGet", path.name))
    return packages


def parse_manifest(path: Path) -> list[PackageRef]:
    name = path.name.lower()
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _parse_package_lock(path)
    if name == "package.json":
        return _parse_package_json(path)
    if name == "yarn.lock":
        return _parse_yarn_lock(path)
    if name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path)
    if name == "requirements.txt":
        return _parse_requirements(path)
    if name == "pyproject.toml":
        return _parse_pyproject(path)
    if name == "pipfile.lock":
        return _parse_pipfile_lock(path)
    if name == "poetry.lock":
        return _parse_poetry_lock(path)
    if name == "go.mod":
        return _parse_go_mod(path)
    if name == "composer.lock":
        return _parse_composer_lock(path)
    if name == "gemfile.lock":
        return _parse_gemfile_lock(path)
    if name == "cargo.lock":
        return _parse_cargo_lock(path)
    if name == "pom.xml":
        return _parse_pom(path)
    if name.startswith("build.gradle"):
        return _parse_gradle(path)
    if name == "packages.config" or path.suffix.lower() == ".csproj":
        return _parse_nuget(path)
    return []


def discover_and_parse(root: Path, log: Callable[[str], None] | None = None) -> list[PackageRef]:
    packages: list[PackageRef] = []
    manifest_count = 0
    for path in iter_files(root, max_files=10000, max_size=8 * 1024 * 1024):
        if path.name not in MANIFEST_NAMES and path.suffix.lower() not in MANIFEST_SUFFIXES:
            continue
        manifest_count += 1
        try:
            parsed = parse_manifest(path)
        except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
            if log:
                log(f"Could not parse {relative_path(path, root)}: {exc}")
            continue
        relative = relative_path(path, root)
        for package in parsed:
            package.source = relative
            packages.append(package)
    # Package manifests are only a fallback; if a lockfile exists, avoid
    # duplicate entries for the same resolved package.
    deduped: dict[tuple[str, str, str], PackageRef] = {}
    for package in packages:
        key = (package.ecosystem, package.name, package.version)
        deduped.setdefault(key, package)
    result = list(deduped.values())[:MAX_PACKAGES]
    if log:
        log(
            f"Parsed {manifest_count} manifest(s): {len(result)} unique package version(s)"
        )
    return result


def findings_from_osv(
    packages: list[PackageRef],
    matches: dict[int, list[dict[str, Any]]],
    result: ScanResult,
    log: Callable[[str], None] | None = None,
) -> int:
    count = 0
    for index, vulns in matches.items():
        package = packages[index]
        for vuln in vulns:
            vuln_id = str(vuln.get("id") or "")
            aliases = [str(x) for x in vuln.get("aliases") or []]
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
            result.add(
                Finding(
                    severity=severity,
                    title=f"Vulnerable dependency: {package.name} {package.version} ({vuln_id})",
                    category="dependency",
                    description=truncate((summary + "\n\n" + details).strip(), 7000),
                    evidence=(
                        f"Package: {package.name}@{package.version}\n"
                        f"Ecosystem: {package.ecosystem}\n"
                        f"Manifest: {package.source}\n"
                        f"Advisory: {vuln_id}\n"
                        f"Aliases: {', '.join(aliases) or 'none'}\n"
                        f"Fixed versions: {fixed_text or 'not specified'}"
                    ),
                    remediation=remediation,
                    cve=",".join(cves),
                    cvss=cvss,
                    location=package.source,
                    resource=f"{package.name}@{package.version}",
                    key=f"osv:{package.ecosystem}:{package.name}:{vuln_id}",
                    raw={
                        "osv_id": vuln_id,
                        "aliases": aliases,
                        "ecosystem": package.ecosystem,
                        "package": package.name,
                        "version": package.version,
                        "fixed_versions": sorted(set(fixed_versions)),
                        "references": [ref.get("url") for ref in vuln.get("references") or [] if ref.get("url")],
                        "dev": package.dev,
                    },
                )
            )
            count += 1
    return count


def enrich_packages(
    packages: list[PackageRef],
    ctx: ScanContext,
    result: ScanResult,
) -> int:
    if not packages:
        ctx.log("No supported package manifests found")
        return 0
    ctx.log(f"Querying OSV.dev for {len(packages)} package version(s)")
    matches = query_packages(
        [package.as_query() for package in packages],
        log=lambda message: ctx.log(message, "warning") if "unavailable" in message.lower() else ctx.log(message),
    )
    found = findings_from_osv(packages, matches, result, log=ctx.log)
    ctx.log(f"OSV matched {found} advisories across {len(matches)} package(s)")
    return found


def _existing_osv_identities(result: ScanResult) -> set[tuple[str, str, str]]:
    identities: set[tuple[str, str, str]] = set()
    for item in result.findings:
        raw = item.raw if isinstance(item, Finding) else (item.get("raw") if isinstance(item, dict) else {})
        if not isinstance(raw, dict) or not raw.get("osv_id"):
            continue
        identities.add(
            (
                str(raw.get("osv_id") or ""),
                str(raw.get("package") or ""),
                str(raw.get("version") or ""),
            )
        )
    return identities


def _osv_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return sorted(set(fixed))


def _run_osv_scanner(ctx: ScanContext, root: Path, result: ScanResult) -> int:
    """Supplement the built-in OSV client with Google's osv-scanner CLI."""
    if not ctx.option_bool("external_tools", False):
        return 0
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        ctx.log("osv-scanner skipped because external APIs are disabled", "warning")
        return 0
    path = tool_path("osv-scanner")
    if not path:
        return 0
    ctx.log("Running osv-scanner for supplemental dependency analysis")
    commands = [
        [path, "scan", "--recursive", "--format", "json", str(root)],
        [path, "--recursive", "--format", "json", str(root)],
    ]
    data: dict[str, Any] | None = None
    for command in commands:
        try:
            proc = run_tool(command, timeout=600)
        except Exception as exc:
            ctx.log(f"osv-scanner failed to run: {exc}", "warning")
            return 0
        output = (proc.stdout or "").strip()
        if output.startswith("{"):
            try:
                parsed = json.loads(output)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                data = parsed
                break
    if data is None:
        ctx.log("osv-scanner did not return a usable JSON report", "warning")
        return 0

    existing = _existing_osv_identities(result)
    count = 0
    for source in data.get("results") or []:
        if not isinstance(source, dict):
            continue
        source_path = str((source.get("source") or {}).get("path") or "")
        for wrapper in source.get("packages") or []:
            if not isinstance(wrapper, dict):
                continue
            package = wrapper.get("package") if isinstance(wrapper.get("package"), dict) else wrapper
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            ecosystem = str(package.get("ecosystem") or "")
            for vuln in wrapper.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "")
                if not vuln_id or (vuln_id, name, version) in existing:
                    continue
                aliases = [str(alias) for alias in vuln.get("aliases") or []]
                cves = ",".join(alias for alias in aliases if alias.startswith("CVE-"))
                fixed = _osv_fixed_versions(vuln)
                cvss, severity = osv_severity(vuln)
                summary = str(vuln.get("summary") or "").strip()
                details = str(vuln.get("details") or "").strip()
                result.add(
                    Finding(
                        severity=severity,
                        title=f"Vulnerable dependency: {name} {version} ({vuln_id})",
                        category="dependency",
                        description=truncate((summary + "\n\n" + details).strip(), 7000),
                        evidence=(
                            f"Package: {name}@{version}\n"
                            f"Ecosystem: {ecosystem or 'unknown'}\n"
                            f"Manifest: {source_path or 'unknown'}\n"
                            f"Advisory: {vuln_id}\n"
                            f"Detected by: osv-scanner"
                        ),
                        remediation=(
                            f"Upgrade {name} to {', '.join(fixed[:5])} or later."
                            if fixed
                            else "Apply the vendor advisory or upgrade to a supported, patched release."
                        ),
                        cve=cves,
                        cvss=cvss,
                        location=source_path,
                        resource=f"{name}@{version}",
                        key=f"osv-scanner:{ecosystem}:{name}:{vuln_id}",
                        raw={
                            "osv_id": vuln_id,
                            "aliases": aliases,
                            "ecosystem": ecosystem,
                            "package": name,
                            "version": version,
                            "fixed_versions": fixed,
                            "detected_by": "osv-scanner",
                        },
                    )
                )
                existing.add((vuln_id, name, version))
                count += 1
    ctx.log(f"osv-scanner reported {count} supplemental finding(s)")
    return count


def scan_dependencies(ctx: ScanContext, root: Path) -> ScanResult:
    result = ScanResult()
    ctx.progress(12, "Parsing dependency manifests")
    packages = discover_and_parse(root, log=ctx.log)
    result.metadata["packages_found"] = len(packages)
    result.metadata["manifests"] = sorted(
        {package.source for package in packages if package.source}
    )[:200]
    ctx.progress(32, "Querying OSV.dev")
    try:
        enrich_packages(packages, ctx, result)
    except OsvUnavailable as exc:
        ctx.log(f"OSV lookup failed: {exc}", "warning")
        result.metadata["osv_error"] = str(exc)
    except Exception as exc:
        ctx.log(f"Dependency lookup failed: {exc}", "warning")
        result.metadata["osv_error"] = str(exc)
    result.metadata["osv_scanner_findings"] = _run_osv_scanner(ctx, root, result)
    return result
