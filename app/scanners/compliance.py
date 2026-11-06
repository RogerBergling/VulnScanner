"""Compliance mapping: findings to control frameworks.

Maps findings onto curated subsets of PCI DSS 4.0, ISO/IEC 27001:2022 and
CIS Controls v8 using severity, category, CWE and finding content. The
mapping is a pragmatic reporting aid — it shows which controls a scan's
findings touch — not a certification-grade evidence module.
"""

from __future__ import annotations

from typing import Any, Callable

Rule = Callable[[dict[str, Any]], bool]


def _has_category(category: str) -> Rule:
    return lambda f: str(f.get("category") or "") == category


def _any_category(*categories: str) -> Rule:
    return lambda f: str(f.get("category") or "") in categories


def _has_cwe(*cwes: str) -> Rule:
    wanted = {cwe.upper() for cwe in cwes}
    def rule(finding: dict[str, Any]) -> bool:
        found = {c.strip().upper() for c in str(finding.get("cwe") or "").split(",") if c.strip()}
        return bool(found & wanted)
    return rule


def _has_cve() -> Rule:
    return lambda f: bool((f.get("cve") or "").strip())


def _severity_ge(severity: str) -> Rule:
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    floor = rank.get(severity, 0)
    return lambda f: rank.get(str(f.get("severity") or "info"), 0) >= floor


def _key_contains(*tokens: str) -> Rule:
    lowered = [token.lower() for token in tokens]
    return lambda f: any(token in str(f.get("key") or "").lower() for token in lowered)


def _title_contains(*tokens: str) -> Rule:
    lowered = [token.lower() for token in tokens]
    return lambda f: any(token in str(f.get("title") or "").lower() for token in lowered)


def _any_of(*rules: Rule) -> Rule:
    def rule(finding: dict[str, Any]) -> bool:
        return any(item(finding) for item in rules)
    return rule


def _all_of(*rules: Rule) -> Rule:
    def rule(finding: dict[str, Any]) -> bool:
        return all(item(finding) for item in rules)
    return rule


# Rules that capture "exposed or dangerous network surface".
NETWORK_EXPOSURE = _any_of(
    _key_contains("risky-port", "open-port", "smb-signing", "smb1", "snmp-",
                  "redis-unauth", "mongo-unauth", "elastic-unauth", "docker-unauth",
                  "memcached-open", "vnc-noauth", "rdp-"),
    _has_category("network"),
)
WEB_SECURITY = _any_of(
    _has_category("web"),
    _has_cwe("CWE-89", "CWE-79", "CWE-22", "CWE-693", "CWE-538", "CWE-319", "CWE-326"),
    _key_contains("nuclei"),
)
VULN_MANAGEMENT = _any_of(_has_cve(), _has_category("dependency"), _severity_ge("critical"))
IDENTITY = _any_of(
    _has_category("ad"),
    _has_cwe("CWE-521", "CWE-307", "CWE-798", "CWE-287", "CWE-269", "CWE-522", "CWE-263"),
)
SECRETS_EXPOSURE = _any_of(_has_category("secrets"), _has_cwe("CWE-538", "CWE-200"))

FRAMEWORKS: dict[str, list[dict[str, Any]]] = {
    "PCI DSS 4.0": [
        {"id": "1.2", "title": "Network security controls (NSCs) are configured and maintained",
         "rule": NETWORK_EXPOSURE,
         "guidance": "Restrict inbound traffic to documented business needs and review NSC rules regularly."},
        {"id": "2.2", "title": "System components are configured and managed securely",
         "rule": _any_of(WEB_SECURITY, _has_cwe("CWE-326", "CWE-327")),
         "guidance": "Apply vendor hardening standards and disable unnecessary services and functions."},
        {"id": "6.3", "title": "Security vulnerabilities are identified and managed",
         "rule": VULN_MANAGEMENT,
         "guidance": "Prioritise vulnerabilities by exploitability (KEV/EPSS) and patch within policy timelines."},
        {"id": "8.2", "title": "User identity is verified before access to system components",
         "rule": IDENTITY,
         "guidance": "Enforce strong authentication and remove default or weak credentials."},
        {"id": "3.2", "title": "Account data storage is minimized and protected",
         "rule": SECRETS_EXPOSURE,
         "guidance": "Remove exposed files, secrets and dumps that may contain cardholder data."},
    ],
    "ISO 27001:2022": [
        {"id": "A.8.8", "title": "Management of technical vulnerabilities",
         "rule": VULN_MANAGEMENT,
         "guidance": "Maintain a vulnerability management process with defined remediation timelines."},
        {"id": "A.8.20", "title": "Networks security",
         "rule": NETWORK_EXPOSURE,
         "guidance": "Segregate, restrict and monitor networks; control service exposure."},
        {"id": "A.8.21", "title": "Security of network services",
         "rule": _any_of(_key_contains("open-port", "risky-port", "snmp-"), _has_category("network")),
         "guidance": "Document, secure and monitor network services in service agreements."},
        {"id": "A.8.26", "title": "Application security requirements",
         "rule": WEB_SECURITY,
         "guidance": "Apply secure development practices and fix injection and configuration flaws."},
        {"id": "A.8.5", "title": "Secure authentication",
         "rule": IDENTITY,
         "guidance": "Enforce strong authentication, least privilege and review privileged access."},
        {"id": "A.8.12", "title": "Data leakage prevention",
         "rule": SECRETS_EXPOSURE,
         "guidance": "Prevent exposure of sensitive files, dumps and secrets."},
    ],
    "CIS Controls v8": [
        {"id": "4.1", "title": "Establish and maintain a secure configuration process",
         "rule": _any_of(WEB_SECURITY, _has_cwe("CWE-326", "CWE-327", "CWE-693")),
         "guidance": "Maintain secure configuration standards and remediate deviations."},
        {"id": "7.1", "title": "Establish and maintain a vulnerability management process",
         "rule": VULN_MANAGEMENT,
         "guidance": "Continuously identify, prioritise (EPSS/KEV) and remediate vulnerabilities."},
        {"id": "13.4", "title": "Perform traffic filtering between network segments",
         "rule": NETWORK_EXPOSURE,
         "guidance": "Limit network exposure with segmentation and host-based filtering."},
        {"id": "16.7", "title": "Use standard hardening configuration templates for application infrastructure",
         "rule": WEB_SECURITY,
         "guidance": "Harden web and application infrastructure against OWASP-class flaws."},
        {"id": "6.3", "title": "Require MFA for externally-exposed applications",
         "rule": IDENTITY,
         "guidance": "Require strong authentication, especially for privileged and exposed access."},
        {"id": "3.3", "title": "Configure data access control lists",
         "rule": SECRETS_EXPOSURE,
         "guidance": "Restrict access to files and secrets to authorised principals."},
    ],
}


def scan_compliance(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Map a scan's findings onto the curated framework subsets."""
    frameworks: list[dict[str, Any]] = []
    for framework_name, controls in FRAMEWORKS.items():
        framework_entry: dict[str, Any] = {"name": framework_name, "controls": []}
        for control in controls:
            matched = [finding for finding in findings if control["rule"](finding)]
            if not matched:
                continue
            severity_counts: dict[str, int] = {}
            for finding in matched:
                severity = str(finding.get("severity") or "info")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            framework_entry["controls"].append({
                "id": control["id"],
                "title": control["title"],
                "guidance": control["guidance"],
                "finding_count": len(matched),
                "severity": severity_counts,
                "findings": [
                    {"title": finding.get("title"), "severity": finding.get("severity"),
                     "cve": finding.get("cve") or "", "location": finding.get("location") or ""}
                    for finding in matched[:10]
                ],
            })
        if framework_entry["controls"]:
            frameworks.append(framework_entry)
    return {
        "frameworks": frameworks,
        "mapped_findings": sum(
            control["finding_count"]
            for framework in frameworks
            for control in framework["controls"]
        ),
    }
