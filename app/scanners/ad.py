"""Active Directory risk assessment.

The Windows agent (or the standalone PowerShell collector) performs read-only
LDAP/PowerShell queries and sends metrics to this module.  Findings are modelled
after the configuration checks popularised by PingCastle and Purple Knight.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..utils import risk_label, risk_score, severity_summary, truncate
from .base import Finding, ScanContext, ScanResult, normalize_finding


def _count(value: Any) -> int:
    if isinstance(value, dict):
        return int(value.get("count") or len(value.get("accounts") or value.get("privileged") or []))
    if isinstance(value, list):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _names(value: Any, limit: int = 12) -> list[str]:
    if isinstance(value, dict):
        value = value.get("accounts") or value.get("privileged") or value.get("sample") or []
    if not isinstance(value, list):
        return []
    names = []
    for item in value[:limit]:
        if isinstance(item, dict):
            names.append(str(item.get("name") or item.get("sam") or item.get("dn") or "unknown"))
        else:
            names.append(str(item))
    return names


def process_ad_report(report: dict[str, Any]) -> ScanResult:
    result = ScanResult()
    domain = report.get("domain") or {}
    if isinstance(domain, str):
        domain = {"name": domain}
    domain_name = domain.get("name") or report.get("domain_name") or "Unknown domain"
    policy = report.get("password_policy") or {}
    counts = report.get("counts") or {}
    privileged_groups = report.get("privileged_groups") or {}
    result.metadata = {
        "domain": domain_name,
        "forest": domain.get("forest") or report.get("forest") or "",
        "domain_controller": domain.get("domain_controller") or report.get("domain_controller") or "",
        "counts": counts,
        "collected_at": report.get("collected_at") or "",
        "collector": report.get("collector") or "VulnScanner AD audit",
    }
    krbtgt_age: int | None = None

    def add(
        severity: str,
        title: str,
        key: str,
        description: str,
        evidence: str,
        remediation: str,
        cwe: str = "",
        raw: dict[str, Any] | None = None,
    ) -> None:
        result.add(
            Finding(
                severity=severity,
                title=title,
                category="ad",
                description=description,
                evidence=evidence,
                remediation=remediation,
                cwe=cwe,
                location=domain_name,
                resource=str(domain_name),
                key=f"ad:{key}",
                raw=raw or {},
            )
        )

    if report.get("guest_enabled"):
        add(
            "high",
            "Active Directory Guest account is enabled",
            "guest-enabled",
            "The built-in Guest account is enabled and may provide unauthenticated access.",
            "Guest account Enabled = true",
            "Disable the Guest account and verify no applications depend on it.",
            "CWE-284",
        )

    min_length = policy.get("min_length") or policy.get("minimum_password_length")
    if min_length is not None:
        try:
            min_length = int(min_length)
        except (TypeError, ValueError):
            min_length = 0
        if min_length < 12:
            add(
                "high" if min_length < 8 else "medium",
                f"Domain minimum password length is too short ({min_length})",
                "password-length",
                "Short passwords are easier to brute force, especially without effective lockout.",
                f"Minimum password length: {min_length}",
                "Require a minimum of 14 characters (or a strong passphrase policy) for privileged and standard users.",
                "CWE-521",
            )

    if policy.get("complexity") is False or policy.get("complexity_enabled") is False:
        add(
            "medium",
            "Domain password complexity is disabled",
            "password-complexity",
            "The domain does not require complex passwords.",
            "Password complexity Enabled = false",
            "Enable complexity or, preferably, deploy a modern banned-password/entropy policy.",
            "CWE-521",
        )

    lockout = policy.get("lockout_threshold")
    if lockout is not None:
        try:
            lockout = int(lockout)
        except (TypeError, ValueError):
            lockout = 0
        if lockout == 0:
            add(
                "high",
                "Account lockout is not configured",
                "no-lockout",
                "Unlimited password guesses make online password spraying and brute force practical.",
                "Lockout threshold: 0 (never)",
                "Configure a lockout threshold (for example 5-10 attempts) with an appropriate observation window.",
                "CWE-307",
            )
        elif lockout > 10:
            add(
                "low",
                f"Account lockout threshold is high ({lockout})",
                "high-lockout",
                "A high lockout threshold gives attackers more password attempts per account.",
                f"Lockout threshold: {lockout}",
                "Tune the lockout threshold and pair it with detection for password spraying.",
                "CWE-307",
            )

    max_age = policy.get("max_age_days")
    if max_age is not None:
        try:
            max_age = int(max_age)
            if max_age > 365:
                add(
                    "low",
                    f"Maximum password age is very long ({max_age} days)",
                    "password-age",
                    "Long password lifetimes increase the window of exposure after a credential leak.",
                    f"Maximum password age: {max_age} days",
                    "Use risk-based password expiration and enforce strong credentials/MFA, or reduce the maximum age.",
                    "CWE-262",
                )
        except (TypeError, ValueError):
            pass

    krbtgt_age = report.get("krbtgt_password_age_days")
    if krbtgt_age is not None:
        try:
            krbtgt_age = int(krbtgt_age)
            if krbtgt_age > 365:
                add(
                    "high",
                    f"krbtgt password is {krbtgt_age} days old",
                    "krbtgt-age",
                    "A stale krbtgt password extends the usefulness of a stolen golden ticket. Microsoft guidance recommends regular rotation.",
                    f"krbtgt password last set: {krbtgt_age} days ago",
                    "Rotate the krbtgt password twice (with replication time between changes) following Microsoft guidance.",
                    "CWE-263",
                )
            elif krbtgt_age > 180:
                add(
                    "medium",
                    f"krbtgt password is {krbtgt_age} days old",
                    "krbtgt-age-medium",
                    "Periodic krbtgt rotation limits the lifetime of forged Kerberos tickets.",
                    f"krbtgt password last set: {krbtgt_age} days ago",
                    "Plan a double krbtgt password rotation and monitor replication.",
                    "CWE-263",
                )
        except (TypeError, ValueError):
            pass

    unconstrained = report.get("unconstrained_delegation") or {}
    unconstrained_count = _count(unconstrained)
    if unconstrained_count:
        names = _names(unconstrained)
        add(
            "critical",
            f"Unconstrained Kerberos delegation is enabled on {unconstrained_count} account(s)",
            "unconstrained-delegation",
            "An account with unconstrained delegation can impersonate users to any service. Compromise of that host can lead to domain-wide takeover.",
            "Accounts: " + (", ".join(names) if names else str(unconstrained_count)),
            "Remove unconstrained delegation, mark sensitive accounts as 'Account is sensitive and cannot be delegated', and use resource-based constrained delegation.",
            "CWE-269",
        )

    kerberoastable = report.get("kerberoastable") or {}
    kerbero_count = _count(kerberoastable)
    privileged_kerb = _count(kerberoastable.get("privileged")) if isinstance(kerberoastable, dict) else 0
    if kerbero_count:
        add(
            "high" if privileged_kerb else "medium",
            f"{kerbero_count} account(s) have service principal names and may be Kerberoastable",
            "kerberoastable",
            "Any authenticated user can request service tickets for accounts with SPNs. Offline cracking of weak service passwords can lead to privilege escalation.",
            f"Total: {kerbero_count}; privileged: {privileged_kerb}; sample: {', '.join(_names(kerberoastable)) or 'n/a'}",
            "Use managed service accounts/gMSA, set long random service passwords, remove unnecessary SPNs, and monitor risky ticket requests.",
            "CWE-522",
        )

    asrep = report.get("asrep_roastable") or {}
    asrep_count = _count(asrep)
    privileged_asrep = _count(asrep.get("privileged")) if isinstance(asrep, dict) else 0
    if asrep_count:
        add(
            "high" if privileged_asrep else "medium",
            f"{asrep_count} account(s) allow AS-REP roasting",
            "asrep-roastable",
            "Accounts without Kerberos pre-authentication can have their password hashes requested and cracked offline.",
            f"Total: {asrep_count}; privileged: {privileged_asrep}; sample: {', '.join(_names(asrep)) or 'n/a'}",
            "Enable Kerberos pre-authentication and reset affected account passwords.",
            "CWE-522",
        )

    stale_users = report.get("stale_users") or {}
    stale_count = _count(stale_users)
    stale_priv = _count(stale_users.get("privileged")) if isinstance(stale_users, dict) else 0
    if stale_count:
        add(
            "high" if stale_priv else "low",
            f"{stale_count} stale user account(s) detected",
            "stale-users",
            "Inactive enabled accounts expand the attack surface and may retain old credentials.",
            f"Total stale: {stale_count}; privileged: {stale_priv}; sample: {', '.join(_names(stale_users)) or 'n/a'}",
            "Disable or delete inactive accounts after an approved review. Give priority to privileged and service accounts.",
            "CWE-284",
        )

    never_expires = report.get("never_expires") or {}
    never_count = _count(never_expires)
    never_priv = _count(never_expires.get("privileged")) if isinstance(never_expires, dict) else 0
    if never_count:
        add(
            "medium" if never_priv or never_count > 10 else "low",
            f"{never_count} enabled account(s) have passwords that never expire",
            "never-expires",
            "Non-expiring passwords can remain valid indefinitely after an undetected compromise.",
            f"Total: {never_count}; privileged: {never_priv}",
            "Review non-expiring accounts and require strong unique credentials, MFA, and privileged access management.",
            "CWE-262",
        )

    admin_count = report.get("admin_count") or {}
    admin_nonpriv = _count(admin_count.get("non_privileged")) if isinstance(admin_count, dict) else 0
    if admin_nonpriv:
        add(
            "medium",
            f"{admin_nonpriv} account(s) retain AdminCount without current privileged group membership",
            "admin-count",
            "Orphaned AdminCount=1 objects may retain inherited access or indicate incomplete deprovisioning.",
            f"Non-privileged adminCount=1 accounts: {admin_nonpriv}; sample: {', '.join(_names(admin_count.get('non_privileged'))) or 'n/a'}",
            "Review AdminCount flags, remove unnecessary permissions, and reset AdminCount after removing privileged group membership.",
            "CWE-269",
        )

    for group_name, members in (privileged_groups.items() if isinstance(privileged_groups, dict) else []):
        try:
            member_count = _count(members)
        except Exception:
            member_count = 0
        if member_count > 5:
            add(
                "medium",
                f"Privileged group '{group_name}' has {member_count} members",
                f"privileged-group:{group_name}",
                "Large privileged groups increase the chance that one compromised account leads to domain compromise.",
                f"Group: {group_name}; members: {member_count}",
                "Minimize permanent privileged membership and use just-in-time access with approval and auditing.",
                "CWE-269",
            )

    stale_computers = _count(report.get("stale_computers"))
    if stale_computers:
        add(
            "low",
            f"{stale_computers} stale computer account(s) detected",
            "stale-computers",
            "Disabled or inactive computer objects can be repurposed by an attacker with domain rights.",
            f"Stale computer accounts: {stale_computers}",
            "Remove or disable stale computer objects after validating they are no longer in use.",
            "CWE-284",
        )

    quota = domain.get("machine_account_quota")
    if quota is not None:
        try:
            quota = int(quota)
            if quota > 0:
                add(
                    "low",
                    "Authenticated users may create domain-joined computers",
                    "machine-account-quota",
                    "A non-zero ms-DS-MachineAccountQuota lets any authenticated user create computer accounts, which can aid relay attacks.",
                    f"ms-DS-MachineAccountQuota: {quota}",
                    "Set the quota to 0 and delegate computer creation to approved administrators.",
                    "CWE-269",
                )
        except (TypeError, ValueError):
            pass

    if domain.get("recycle_bin_enabled") is False:
        add(
            "low",
            "Active Directory Recycle Bin is not enabled",
            "recycle-bin",
            "Without the Recycle Bin, accidentally or maliciously deleted objects are harder to recover.",
            "Recycle Bin Enabled = false",
            "Enable the Active Directory Recycle Bin (requires a suitable forest functional level).",
            "CWE-693",
        )

    functional_level = str(domain.get("functional_level") or "")
    if functional_level and any(year in functional_level for year in ("2000", "2003", "2008")):
        add(
            "low",
            f"Legacy domain functional level: {functional_level}",
            "functional-level",
            "Old functional levels prevent modern security controls and indicate an ageing directory.",
            f"Domain functional level: {functional_level}",
            "Plan an upgrade to a supported Windows Server functional level.",
            "CWE-1104",
        )

    for custom in report.get("findings") or []:
        if isinstance(custom, dict):
            finding = normalize_finding(custom)
            finding["category"] = "ad"
            finding["key"] = finding.get("key") or f"ad:{finding.get('title', '')}"
            result.findings.append(finding)

    normalized = result.normalized()
    summary = severity_summary(normalized)
    score = risk_score(summary)
    result.metadata["risk_score"] = score
    result.metadata["risk_label"] = risk_label(score)
    result.metadata["findings"] = summary
    result.metadata["metrics"] = {
        "krbtgt_password_age_days": krbtgt_age,
        "stale_users": stale_count,
        "stale_computers": stale_computers,
        "kerberoastable": kerbero_count,
        "asrep_roastable": asrep_count,
        "unconstrained_delegation": unconstrained_count,
        "never_expires": never_count,
    }
    return result


def scan_ad_report(ctx: ScanContext, report_path: str) -> ScanResult:
    path = Path(report_path).expanduser()
    if not path.is_file():
        raise ValueError(f"AD report file not found: {report_path}")
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("AD report is larger than 20 MiB")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read AD report JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("AD report must be a JSON object")
    ctx.log(f"Loaded Active Directory audit report from {path.name}")
    result = process_ad_report(report)
    ctx.progress(85, "Evaluating Active Directory risk")
    ctx.log(
        f"AD audit complete: {len(result.findings)} finding(s), "
        f"risk score {result.metadata.get('risk_score', 0)}"
    )
    return result
