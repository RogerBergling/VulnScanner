"""Optional Trivy integration for filesystem, IaC and secret coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import ENABLE_EXTERNAL_APIS, data_dir
from ..database import get_setting
from ..utils import normalize_severity, redact_secret, truncate
from .base import Finding, ScanContext, ScanResult
from .tools import run_tool, tool_path

MAX_TRIVY_FINDINGS = 1500


def _raw(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, Finding):
        return finding.raw or {}
    return finding.get("raw") if isinstance(finding.get("raw"), dict) else {}


def _existing_vulnerabilities(result: ScanResult) -> set[tuple[str, str, str]]:
    known: set[tuple[str, str, str]] = set()
    for finding in result.findings:
        raw = _raw(finding)
        name = str(raw.get("package") or "")
        version = str(raw.get("version") or "")
        if not name or not version:
            continue
        for key in ("osv_id", "vuln_id"):
            identifier = str(raw.get(key) or "")
            if identifier:
                known.add((identifier, name, version))
        cve = _raw(finding).get("cve") or (
            finding.cve if isinstance(finding, Finding) else finding.get("cve", "")
        )
        for identifier in str(cve or "").split(","):
            identifier = identifier.strip()
            if identifier:
                known.add((identifier, name, version))
    return known


def _cvss(payload: Any) -> float | None:
    if not isinstance(payload, dict):
        return None
    scores: list[float] = []
    for item in payload.values():
        if not isinstance(item, dict):
            continue
        for key in ("V3Score", "V2Score"):
            try:
                scores.append(float(item[key]))
            except (KeyError, TypeError, ValueError):
                pass
    return max(scores) if scores else None


def _join(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value if item)
    return str(value or "")


def _vulnerability_findings(
    results: list[Any],
    known: set[tuple[str, str, str]],
    result: ScanResult,
) -> int:
    count = 0
    for source in results:
        if not isinstance(source, dict):
            continue
        target = str(source.get("Target") or "")
        ecosystem = str(source.get("Type") or source.get("Class") or "")
        for item in source.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("VulnerabilityID") or "").strip()
            name = str(item.get("PkgName") or "").strip()
            version = str(item.get("InstalledVersion") or "").strip()
            if not identifier or not name or (identifier, name, version) in known:
                continue
            fixed = str(item.get("FixedVersion") or "").strip()
            cve_values = [identifier] if identifier.startswith("CVE-") else []
            cve_values.extend(
                str(alias)
                for alias in item.get("Aliases") or []
                if str(alias).startswith("CVE-")
            )
            cve = ",".join(dict.fromkeys(cve_values))
            severity = normalize_severity(str(item.get("Severity") or "UNKNOWN"), "info")
            result.add(
                Finding(
                    severity=severity,
                    title=f"Vulnerable dependency: {name} {version} ({identifier})",
                    category="dependency",
                    description=truncate(
                        f"{item.get('Title') or ''}\n\n{item.get('Description') or ''}".strip(),
                        7000,
                    ),
                    evidence=(
                        f"Package: {name}@{version}\n"
                        f"Ecosystem: {ecosystem or 'unknown'}\n"
                        f"Target: {target or 'unknown'}\n"
                        f"Advisory: {identifier}\n"
                        f"Fixed version: {fixed or 'not published'}\n"
                        f"Detected by: Trivy"
                    ),
                    remediation=(
                        f"Upgrade {name} to {fixed} or later."
                        if fixed
                        else "Apply the vendor advisory or upgrade to a supported, patched release."
                    ),
                    cve=cve,
                    cwe=_join(item.get("CweIDs")),
                    cvss=_cvss(item.get("CVSS")),
                    location=target,
                    resource=f"{name}@{version}",
                    key=f"trivy-vuln:{ecosystem}:{name}:{identifier}",
                    raw={
                        "vuln_id": identifier,
                        "cve": cve,
                        "package": name,
                        "version": version,
                        "fixed_version": fixed,
                        "ecosystem": ecosystem,
                        "detected_by": "trivy",
                    },
                )
            )
            known.add((identifier, name, version))
            count += 1
    return count


def _misconfiguration_findings(results: list[Any], result: ScanResult) -> int:
    count = 0
    for source in results:
        if not isinstance(source, dict):
            continue
        target = str(source.get("Target") or "")
        for item in source.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("ID") or item.get("AVDID") or "").strip()
            if not identifier:
                continue
            severity = normalize_severity(str(item.get("Severity") or "UNKNOWN"), "medium")
            cause = item.get("CauseMetadata") if isinstance(item.get("CauseMetadata"), dict) else {}
            line = cause.get("StartLine") or ""
            result.add(
                Finding(
                    severity=severity,
                    title=f"IaC misconfiguration: {item.get('Title') or identifier}",
                    category="misconfiguration",
                    description=truncate(
                        f"{item.get('Description') or ''}\n\n{item.get('Message') or ''}".strip(),
                        7000,
                    ),
                    evidence=truncate(
                        f"Check: {identifier}\nTarget: {target}"
                        + (f"\nLine: {line}" if line else "")
                        + f"\nDetected by: Trivy ({item.get('Type') or 'config'})",
                        3000,
                    ),
                    remediation=str(
                        item.get("Resolution")
                        or "Review the infrastructure-as-code definition and apply the recommended setting."
                    ),
                    cwe=_join(item.get("CweIDs")),
                    location=target,
                    resource=f"trivy-misconfig:{identifier}",
                    key=f"trivy-misconfig:{identifier}:{target}:{line}",
                    raw={
                        "check": identifier,
                        "avd_id": item.get("AVDID") or "",
                        "type": item.get("Type") or "",
                        "detected_by": "trivy",
                    },
                )
            )
            count += 1
    return count


def _secret_findings(results: list[Any], result: ScanResult) -> int:
    count = 0
    for source in results:
        if not isinstance(source, dict):
            continue
        target = str(source.get("Target") or "")
        for item in source.get("Secrets") or []:
            if not isinstance(item, dict):
                continue
            rule = str(item.get("RuleID") or item.get("Category") or "").strip()
            title = str(item.get("Title") or rule or "Secret detected")
            line = item.get("StartLine") or ""
            matched = truncate(str(item.get("Match") or ""), 200)
            result.add(
                Finding(
                    severity=normalize_severity(str(item.get("Severity") or "HIGH"), "high"),
                    title=f"Secret detected: {title}",
                    category="secret",
                    description=(
                        "Trivy matched a credential-like value in the scanned files. "
                        "Remove it from source control and rotate the credential."
                    ),
                    evidence=truncate(
                        f"Rule: {rule}\nTarget: {target}"
                        + (f"\nLine: {line}" if line else "")
                        + (f"\nMatch: {redact_secret(matched)}" if matched else "")
                        + "\nDetected by: Trivy",
                        3000,
                    ),
                    remediation=(
                        "Revoke and rotate the exposed credential, remove it from the "
                        "repository and history, and load secrets from a managed store."
                    ),
                    location=target,
                    resource=f"trivy-secret:{rule}",
                    key=f"trivy-secret:{rule}:{target}:{line}",
                    raw={
                        "rule_id": rule,
                        "category": item.get("Category") or "",
                        "detected_by": "trivy",
                    },
                )
            )
            count += 1
    return count


def scan_trivy(ctx: ScanContext, root: Path, result: ScanResult) -> int:
    """Run Trivy against a repository and merge its findings into ``result``."""
    if not ctx.option_bool("external_tools", False) or not ctx.option_bool("trivy", False):
        return 0
    if get_setting("trivy_enabled", "true") != "true":
        return 0
    path = tool_path("trivy")
    if not path:
        ctx.log("Trivy not installed; using built-in dependency, IaC and secret checks", "warning")
        return 0

    cache_dir = data_dir() / "trivy-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    command = [
        path,
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig,secret",
        "--exit-code",
        "0",
        "--no-progress",
        "--quiet",
        "--cache-dir",
        str(cache_dir),
    ]
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        command.append("--skip-db-update")
        ctx.log("Trivy database updates are disabled because external APIs are off")
    command.append(str(root))
    ctx.log("Running Trivy filesystem, IaC and secret checks")
    try:
        proc = run_tool(command, timeout=900)
    except Exception as exc:
        ctx.log(f"Trivy failed to run: {exc}", "warning")
        return 0
    output = (proc.stdout or "").strip()
    if not output.startswith("{"):
        ctx.log(
            f"Trivy did not return a usable JSON report: "
            f"{truncate(proc.stderr or output, 300)}",
            "warning",
        )
        return 0
    try:
        payload = json.loads(output)
    except ValueError:
        ctx.log("Trivy returned malformed JSON", "warning")
        return 0
    results = payload.get("Results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        ctx.log("Trivy JSON report did not contain results", "warning")
        return 0

    known = _existing_vulnerabilities(result)
    before = len(result.findings)
    _vulnerability_findings(results, known, result)
    _misconfiguration_findings(results, result)
    _secret_findings(results, result)
    added = len(result.findings) - before
    if added > MAX_TRIVY_FINDINGS:
        result.findings = result.findings[: before + MAX_TRIVY_FINDINGS]
        added = MAX_TRIVY_FINDINGS
    ctx.log(f"Trivy reported {added} finding(s)")
    return added
