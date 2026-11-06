"""PingCastle Healthcheck XML report parser.

Parses the native ``HealthcheckData`` XML produced by PingCastle
(``pingcastle.exe --healthcheck --xml``) into the shared VulnScanner finding
model. The risk rules map PingCastle's ``RiskId`` identifiers onto stable
titles, severities and remediation guidance; the rule's own ``Rationale`` is
kept as evidence so the imported scan stays faithful to the tool's analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..utils import risk_label, risk_score, safe_xml_fromstring, severity_summary
from .base import Finding, ScanContext, ScanResult

MAX_REPORT_BYTES = 20 * 1024 * 1024

FUNCTIONAL_LEVELS = {
    "0": "Windows 2000",
    "1": "Windows Server 2003",
    "2": "Windows Server 2008",
    "3": "Windows Server 2008 R2",
    "4": "Windows Server 2012",
    "5": "Windows Server 2012 R2",
    "6": "Windows Server 2016",
    "7": "Windows Server 2019",
    "8": "Windows Server 2025",
}

# PingCastle risk rules observed in engine 2.9.x. Unknown future RiskIds fall
# back to a points-based severity and a generic description, so a newer report
# never fails the import.
RISK_RULES: dict[str, dict[str, str]] = {
    "A-Krbtgt": {
        "severity": "critical",
        "title": "krbtgt password has not been changed for a very long time",
        "description": "The Kerberos krbtgt account password has not been rotated in years. A stolen krbtgt hash (golden ticket) remains valid until the password is rotated twice.",
        "remediation": "Rotate the krbtgt password twice following Microsoft guidance (with replication time between changes) and record the rotation in a schedule.",
        "cwe": "CWE-263",
    },
    "S-C-Inactive": {
        "severity": "medium",
        "title": "High ratio of inactive computer accounts",
        "description": "A large share of computer accounts are inactive. Stale computer objects can be repurposed by an attacker with domain rights.",
        "remediation": "Disable or delete inactive computer accounts after an approved review, starting with privileged systems.",
        "cwe": "CWE-284",
    },
    "P-Delegated": {
        "severity": "high",
        "title": "Admin accounts not protected against delegation",
        "description": "Administrative accounts lack the 'Account is sensitive and cannot be delegated' flag, so they can be impersonated through Kerberos delegation.",
        "remediation": "Mark all privileged accounts as sensitive and cannot be delegated, and reduce unconstrained delegation.",
        "cwe": "CWE-269",
    },
    "P-Inactive": {
        "severity": "high",
        "title": "Inactive administrator accounts present",
        "description": "A significant percentage of administrative accounts are inactive. Dormant privileged accounts are a common takeover path.",
        "remediation": "Disable or remove inactive administrator accounts and enforce periodic access review.",
        "cwe": "CWE-284",
    },
    "A-AdminSDHolder": {
        "severity": "medium",
        "title": "Suspicious admin activity detected on user accounts",
        "description": "PingCastle detected temporary or unexpected administrative activity on user accounts, which can indicate a compromised or misconfigured delegation of rights.",
        "remediation": "Review the affected accounts and audit AdminSDHolder changes and administrative group membership.",
        "cwe": "CWE-284",
    },
    "P-DelegationLoginScript": {
        "severity": "high",
        "title": "Login scripts can be modified by any user",
        "description": "Login scripts are writable by unprivileged users. Tampering with a login script executes code in the context of every user who logs on.",
        "remediation": "Restrict write access to login scripts and the NETLOGON share to domain administrators only.",
        "cwe": "CWE-732",
    },
    "P-UnkownDelegation": {
        "severity": "high",
        "title": "Unknown accounts hold delegation rights",
        "description": "Accounts that are not recognised by PingCastle's model hold delegation permissions, which may allow impersonation of users to services.",
        "remediation": "Identify the accounts, confirm their purpose and remove unnecessary delegation rights.",
        "cwe": "CWE-269",
    },
    "P-ExchangePrivEsc": {
        "severity": "high",
        "title": "Exchange Windows Permissions can modify the domain security descriptor",
        "description": "The Exchange Windows Permissions group can change the domain object's security descriptor, a documented privilege escalation path to Domain Admin.",
        "remediation": "Revoke the domain WriteDACL rights of the Exchange Windows Permissions group and follow Microsoft hardening guidance for Exchange deployments.",
        "cwe": "CWE-269",
    },
    "S-OS-2008": {
        "severity": "high",
        "title": "Obsolete Windows Server 2008 operating systems in the domain",
        "description": "Windows Server 2008 reached end of life in January 2020 and no longer receives security updates. Systems on unsupported operating systems are a primary compromise target.",
        "remediation": "Decommission or upgrade all Windows Server 2008 systems and remove their domain objects.",
        "cwe": "CWE-1104",
    },
    "S-PrimaryGroup": {
        "severity": "low",
        "title": "Users with an unexpected primary group",
        "description": "A user account has an unexpected primary group assignment, which can be abused to alter group memberships without full membership.",
        "remediation": "Review the affected account and restore the default primary group.",
        "cwe": "CWE-269",
    },
    "S-DC-NotUpdated": {
        "severity": "medium",
        "title": "Domain controllers are not up to date",
        "description": "PingCastle detected domain controllers that are missing security updates.",
        "remediation": "Apply the latest security updates to all domain controllers and enable a patch schedule.",
        "cwe": "CWE-1104",
    },
    "S-PwdNotRequired": {
        "severity": "medium",
        "title": "Accounts permitted to have an empty password",
        "description": "A number of accounts allow a blank password (PASSWD_NOTREQD), which can be exploited where group policy does not override it.",
        "remediation": "Reset the affected accounts and require strong passwords through policy.",
        "cwe": "CWE-521",
    },
    "A-LAPS-Not-Installed": {
        "severity": "medium",
        "title": "LAPS is not installed",
        "description": "The Local Administrator Password Solution is not deployed, so local administrator passwords are typically shared and static, enabling lateral movement after one host is compromised.",
        "remediation": "Deploy Windows LAPS and set unique, rotating local administrator passwords.",
        "cwe": "CWE-522",
    },
    "S-ADRegistration": {
        "severity": "low",
        "title": "Non-admin users can join computers to the domain",
        "description": "ms-DS-MachineAccountQuota allows authenticated users to create computer accounts, which can aid relay and resource-based delegation attacks.",
        "remediation": "Set ms-DS-MachineAccountQuota to 0 and delegate computer creation explicitly.",
        "cwe": "CWE-269",
    },
    "S-SMB-v1": {
        "severity": "medium",
        "title": "SMBv1 is enabled on domain controllers",
        "description": "SMBv1 is obsolete, has no modern security controls and was the transport for EternalBlue and similar attacks.",
        "remediation": "Disable SMBv1 on all domain controllers and clients and verify no legacy devices depend on it.",
        "cwe": "CWE-319",
    },
    "P-SchemaAdmin": {
        "severity": "medium",
        "title": "Schema Admins group is not empty",
        "description": "The Schema Admins group should be empty outside schema change windows; permanent members expand the attack surface of the directory.",
        "remediation": "Empty Schema Admins and add members only during an approved, monitored schema change.",
        "cwe": "CWE-269",
    },
    "S-DC-Inactive": {
        "severity": "low",
        "title": "Inactive domain controller accounts",
        "description": "Domain controller computer accounts have been inactive, which can indicate decommissioned DCs that were not cleaned up.",
        "remediation": "Verify the DCs are decommissioned and remove stale objects and metadata.",
        "cwe": "CWE-284",
    },
    "P-ProtectedUsers": {
        "severity": "medium",
        "title": "Administrators are not members of Protected Users",
        "description": "Most administrative accounts are not in the Protected Users group, leaving them exposed to credential theft attacks such as Kerberoasting and pass-the-hash.",
        "remediation": "Add eligible administrators to Protected Users after validating application compatibility.",
        "cwe": "CWE-269",
    },
    "P-RecycleBin": {
        "severity": "low",
        "title": "Active Directory Recycle Bin is not enabled",
        "description": "Without the Recycle Bin, maliciously or accidentally deleted objects cannot be restored quickly.",
        "remediation": "Enable the Active Directory Recycle Bin (requires a suitable forest functional level).",
        "cwe": "CWE-693",
    },
    "P-AdminPwdTooOld": {
        "severity": "medium",
        "title": "Administrator passwords are very old",
        "description": "Administrative account passwords have not been changed for more than three years, increasing the exposure window after an undetected leak.",
        "remediation": "Reset the affected administrator passwords and consider a regular privileged password rotation or PAM.",
        "cwe": "CWE-262",
    },
    "P-AdminNum": {
        "severity": "low",
        "title": "Members present in administrative groups",
        "description": "Users are members of administrative groups; permanent membership should be kept minimal.",
        "remediation": "Minimise permanent administrative group membership and use just-in-time access.",
        "cwe": "CWE-269",
    },
    "A-DC-Spooler": {
        "severity": "high",
        "title": "Print spooler service is remotely accessible on a domain controller",
        "description": "The spooler service accepts remote connections on a domain controller, a known vector for privilege escalation (PrintNightmare class) and credential attacks.",
        "remediation": "Disable the print spooler service on domain controllers or block remote spooler access.",
        "cwe": "CWE-284",
    },
    "A-AuditDC": {
        "severity": "medium",
        "title": "Audit policy on domain controllers is incomplete",
        "description": "Key security events are not collected on domain controllers, weakening detection and incident response.",
        "remediation": "Enable the recommended advanced audit policy on domain controllers and ship events to a SIEM.",
        "cwe": "CWE-778",
    },
    "S-DC-2008": {
        "severity": "high",
        "title": "Windows Server 2008 domain controllers present",
        "description": "Domain controllers still run Windows Server 2008, which is end of life and no longer patched.",
        "remediation": "Upgrade or decommission the affected domain controllers before they are compromised.",
        "cwe": "CWE-1104",
    },
    "P-UnconstrainedDelegation": {
        "severity": "high",
        "title": "Unconstrained Kerberos delegation configured",
        "description": "Accounts with unconstrained delegation can impersonate any user to any service; compromise of the hosting system can lead to domain takeover.",
        "remediation": "Remove unconstrained delegation, use resource-based constrained delegation, and mark sensitive accounts as non-delegable.",
        "cwe": "CWE-269",
    },
    "P-DNSAdmin": {
        "severity": "medium",
        "title": "Large membership in DnsAdmins",
        "description": "The DnsAdmins group can load arbitrary DLLs into the DNS service on domain controllers, a documented privilege escalation path.",
        "remediation": "Reduce DnsAdmins membership to the minimum and audit changes to it.",
        "cwe": "CWE-269",
    },
    "A-LMHashAuthorized": {
        "severity": "medium",
        "title": "LM hash storage permitted by policy",
        "description": "At least one policy still permits storing LM hashes, which are trivially crackable and enable pass-the-hash.",
        "remediation": "Enforce 'Network security: Do not store LAN Manager hash value on next password change' domain-wide.",
        "cwe": "CWE-522",
    },
    "S-OS-Win7": {
        "severity": "high",
        "title": "Obsolete Windows 7 clients in the domain",
        "description": "Windows 7 reached end of life in January 2020 and no longer receives security updates.",
        "remediation": "Upgrade or decommission the remaining Windows 7 systems.",
        "cwe": "CWE-1104",
    },
    "S-PwdLastSet-45": {
        "severity": "low",
        "title": "Computer accounts without recent password change",
        "description": "Computer account passwords have not been rotated for a long time, which can indicate orphaned or neglected systems.",
        "remediation": "Verify the affected computers are active and force a password reset.",
        "cwe": "CWE-262",
    },
    "S-DC-SubnetMissing": {
        "severity": "low",
        "title": "Domain controller subnets are not declared",
        "description": "Some domain controller addresses are missing from the declared site subnets, which can impair authentication routing and site-aware security policy.",
        "remediation": "Declare all subnets in Active Directory Sites and Services.",
        "cwe": "CWE-693",
    },
    "A-NTFRSOnSysvol": {
        "severity": "medium",
        "title": "SYSVOL still replicated with NTFRS",
        "description": "NTFRS is deprecated and insecure; SYSVOL should be replicated with DFS-R.",
        "remediation": "Migrate SYSVOL replication from FRS to DFS-R and raise the functional level.",
        "cwe": "CWE-319",
    },
    "P-ControlPathIndirectMany": {
        "severity": "medium",
        "title": "Many indirect control paths to key domain objects",
        "description": "A large number of users or computers can take control of a key domain object through chained permissions.",
        "remediation": "Review ACLs on domain and policy objects and remove indirect control paths.",
        "cwe": "CWE-269",
    },
    "P-Kerberoasting": {
        "severity": "high",
        "title": "Administrator accounts are vulnerable to Kerberoasting",
        "description": "A member of an administrative group has a service principal name with a weak or crackable password; any authenticated user can request its ticket and crack it offline.",
        "remediation": "Use group managed service accounts, set long random service passwords and remove unnecessary SPNs from admin accounts.",
        "cwe": "CWE-522",
    },
    "P-DelegationFileDeployed": {
        "severity": "medium",
        "title": "GPO deploys a file that everyone can modify",
        "description": "A group policy deploys a file writable by all users; replacing it can execute code on every affected machine.",
        "remediation": "Move the deployed file to a location writable only by administrators and re-link the GPO.",
        "cwe": "CWE-732",
    },
    "P-DelegationKeyAdmin": {
        "severity": "medium",
        "title": "Enterprise Key Admins granted excessive rights",
        "description": "An incorrect delegation has granted the Enterprise Key Admins group excessive rights, which can allow credential theft against the directory.",
        "remediation": "Review and correct the Enterprise Key Admins ACLs.",
        "cwe": "CWE-269",
    },
    "A-PreWin2000Anonymous": {
        "severity": "high",
        "title": "Everyone/Anonymous present in the Pre-Windows 2000 Compatible Access group",
        "description": "The Pre-Windows 2000 Compatible Access group grants anonymous read access to directory data, enabling null-session enumeration of users and groups.",
        "remediation": "Remove Everyone and Anonymous Logon from the Pre-Windows 2000 Compatible Access group and re-evaluate legacy application access.",
        "cwe": "CWE-200",
    },
    "A-PreWin2000Other": {
        "severity": "medium",
        "title": "Additional members in the Pre-Windows 2000 Compatible Access group",
        "description": "Specific users or groups were granted the broad read access of the Pre-Windows 2000 Compatible Access group.",
        "remediation": "Remove non-essential members from the group and use targeted delegation instead.",
        "cwe": "CWE-200",
    },
    "S-PwdNeverExpires": {
        "severity": "low",
        "title": "Accounts with passwords that never expire",
        "description": "Many accounts have DONT_EXPIRE_PASSWORD set, so compromised credentials can remain valid indefinitely.",
        "remediation": "Review non-expiring accounts and enforce risk-based password management with MFA.",
        "cwe": "CWE-262",
    },
    "P-LogonDenied": {
        "severity": "low",
        "title": "No policy preventing administrator logon to workstations",
        "description": "No group policy restricts administrators from logging on interactively to ordinary workstations, aiding credential theft.",
        "remediation": "Restrict interactive logon for privileged accounts with a tiered administration model.",
        "cwe": "CWE-284",
    },
    "A-DnsZoneUpdate2": {
        "severity": "low",
        "title": "DNS zone configured with unsecure dynamic updates",
        "description": "A DNS zone accepts unauthenticated dynamic updates, allowing DNS poisoning of records.",
        "remediation": "Set DNS dynamic updates to Secure only for AD-integrated zones.",
        "cwe": "CWE-345",
    },
    "A-NoServicePolicy": {
        "severity": "info",
        "title": "No strong password policy for service accounts",
        "description": "No policy enforces a strong minimum password length for service accounts.",
        "remediation": "Apply a dedicated password policy for service accounts (minimum 20 characters or gMSA).",
        "cwe": "CWE-521",
    },
    "A-AuditPowershell": {
        "severity": "info",
        "title": "PowerShell auditing is not fully enabled",
        "description": "PowerShell script block logging and transcription are not fully enabled, limiting detection of malicious activity.",
        "remediation": "Enable PowerShell script block logging, module logging and transcription domain-wide.",
        "cwe": "CWE-778",
    },
    "A-NoGPOLLMNR": {
        "severity": "low",
        "title": "LLMNR is not disabled by policy",
        "description": "LLMNR is not disabled, so attackers on the network can poison name resolution and capture credentials.",
        "remediation": "Disable LLMNR and NetBIOS name resolution through group policy or endpoint hardening.",
        "cwe": "CWE-311",
    },
    "P-OperatorsEmpty": {
        "severity": "low",
        "title": "Operator groups are not empty",
        "description": "Members are present in operator groups that are expected to remain empty.",
        "remediation": "Empty the operator groups and use delegated administration instead.",
        "cwe": "CWE-269",
    },
    "A-NoNetSessionHardening": {
        "severity": "low",
        "title": "NetCease (session hardening) is not implemented",
        "description": "No group policy implements NetCease, so administrative sessions remain vulnerable to token theft from remote hosts.",
        "remediation": "Apply the NetCease hardening policy to prevent remote credential theft from privileged sessions.",
        "cwe": "CWE-522",
    },
    "A-SHA1RootCert": {
        "severity": "low",
        "title": "Trusted root certificate signed with SHA1",
        "description": "At least one trusted root certificate in the domain uses a SHA1 signature, which is cryptographically weak.",
        "remediation": "Remove or re-issue the SHA1-signed root certificate.",
        "cwe": "CWE-327",
    },
}


def _points_severity(points: int) -> str:
    if points >= 50:
        return "critical"
    if points >= 30:
        return "high"
    if points >= 20:
        return "high"
    if points >= 15:
        return "medium"
    if points >= 10:
        return "medium"
    if points >= 5:
        return "low"
    if points >= 2:
        return "low"
    return "info"


def _text(node: Any, name: str) -> str:
    child = node.find(name) if node is not None else None
    if child is None:
        return ""
    text = child.text
    return "" if text is None else str(text).strip()


def _int_text(node: Any, name: str) -> int | None:
    value = _text(node, name)
    try:
        return int(value)
    except ValueError:
        return None


def _strings(node: Any, name: str) -> list[str]:
    child = node.find(name) if node is not None else None
    if child is None:
        return []
    return [
        str(item.text).strip()
        for item in child.findall("string")
        if item.text and str(item.text).strip()
    ]


def parse_pingcastle_xml(xml_text: str) -> ScanResult:
    root = safe_xml_fromstring(xml_text)
    if root.tag != "HealthcheckData":
        raise ValueError("Not a PingCastle HealthcheckData XML report")
    domain_name = _text(root, "DomainFQDN") or _text(root, "NetBIOSName") or "Unknown domain"
    result = ScanResult()

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
                resource=domain_name,
                key=f"ad:pingcastle:{key}",
                raw=raw or {},
            )
        )

    # --- Structural findings -------------------------------------------------
    if (_text(root, "PreWindows2000AnonymousAccess") or "").lower() == "true":
        add(
            "high",
            "Anonymous access enabled in the Pre-Windows 2000 Compatible Access group",
            "prewin2000-anonymous",
            "The Pre-Windows 2000 Compatible Access group includes Everyone/Anonymous, allowing unauthenticated enumeration of directory data over null sessions.",
            "PreWindows2000AnonymousAccess = true",
            "Remove Everyone and Anonymous Logon from the Pre-Windows 2000 Compatible Access group.",
            "CWE-200",
        )

    if (_text(root, "IsRecycleBinEnabled") or "").lower() == "false":
        add(
            "low",
            "Active Directory Recycle Bin is not enabled",
            "recycle-bin",
            "Deleted objects cannot be restored easily without the Recycle Bin.",
            "IsRecycleBinEnabled = false",
            "Enable the Active Directory Recycle Bin at a suitable forest functional level.",
            "CWE-693",
        )

    if (_text(root, "UsingNTFRSForSYSVOL") or "").lower() == "true":
        add(
            "medium",
            "SYSVOL is still replicated with the deprecated NTFRS protocol",
            "ntfrs-sysvol",
            "NTFRS replication is deprecated and should be replaced by DFS-R.",
            "UsingNTFRSForSYSVOL = true",
            "Migrate SYSVOL replication from FRS to DFS-R.",
            "CWE-319",
        )

    functional_level = _text(root, "DomainFunctionalLevel")
    functional_name = FUNCTIONAL_LEVELS.get(functional_level, functional_level)
    legacy_levels = ("2000", "2003", "2008", "2008 R2")
    if any(year in functional_name for year in legacy_levels):
        add(
            "low",
            f"Legacy domain functional level: {functional_name}",
            "functional-level",
            "The domain functional level prevents modern security controls and indicates an ageing directory.",
            f"Domain functional level: {functional_name}",
            "Plan an upgrade to a supported Windows Server functional level.",
            "CWE-1104",
        )

    user_data = root.find("UserAccountData")
    no_preauth = _int_text(user_data, "NumberNoPreAuth") if user_data is not None else None
    if no_preauth:
        add(
            "high",
            f"{no_preauth} account(s) without Kerberos pre-authentication (AS-REP roastable)",
            "no-preauth",
            "Accounts without Kerberos pre-authentication can have their password hashes requested by any attacker and cracked offline.",
            f"NumberNoPreAuth = {no_preauth}",
            "Enable Kerberos pre-authentication and reset the passwords of the affected accounts.",
            "CWE-522",
        )
    des_enabled = _int_text(user_data, "NumberDesEnabled") if user_data is not None else None
    if des_enabled:
        add(
            "low",
            f"{des_enabled} account(s) still use legacy DES encryption",
            "des-enabled",
            "DES-based Kerberos encryption types are weak and can be cracked offline.",
            f"NumberDesEnabled = {des_enabled}",
            "Replace DES encryption types with AES for the affected accounts.",
            "CWE-327",
        )
    deleg_users = (
        _int_text(user_data, "NumberTrustedToAuthenticateForDelegation")
        if user_data is not None
        else None
    )
    if deleg_users:
        add(
            "high",
            f"{deleg_users} user account(s) trusted for unconstrained delegation",
            "user-unconstrained-delegation",
            "Accounts trusted for unconstrained delegation can impersonate any user to any service.",
            f"NumberTrustedToAuthenticateForDelegation = {deleg_users}",
            "Remove unconstrained delegation and mark sensitive accounts as non-delegable.",
            "CWE-269",
        )

    # --- Domain controller findings ------------------------------------------
    dcs = root.find("DomainControllers")
    dc_rows: list[dict[str, Any]] = []
    if dcs is not None:
        for dc in dcs.findall("HealthcheckDomainController"):
            name = _text(dc, "DCName") or "unknown DC"
            dc_rows.append(
                {
                    "name": name,
                    "operating_system": _text(dc, "OperatingSystem"),
                    "ip": _strings(dc, "IP"),
                    "fsmo": _strings(dc, "FSMO"),
                    "ldaps_protocols": _strings(dc, "LDAPSProtocols"),
                    "rodc": (_text(dc, "RODC") or "").lower() == "true",
                    "smb1": (_text(dc, "SupportSMB1") or "").lower() == "true",
                    "smb2_mode": _text(dc, "SMB2SecurityMode"),
                    "remote_spooler": (_text(dc, "RemoteSpoolerDetected") or "").lower() == "true",
                }
            )
            if (_text(dc, "RemoteSpoolerDetected") or "").lower() == "true":
                add(
                    "high",
                    f"Print spooler remotely accessible on domain controller {name}",
                    f"dc-spooler:{name}",
                    "The spooler service accepts remote connections on a domain controller, a known privilege escalation and credential theft vector.",
                    f"DC: {name}; RemoteSpoolerDetected = true",
                    "Disable the print spooler service on the domain controller or restrict remote spooler access.",
                    "CWE-284",
                )
            smb2_mode = _text(dc, "SMB2SecurityMode")
            if smb2_mode and "SmbSigningRequired" not in smb2_mode:
                add(
                    "medium",
                    f"SMB signing is not required on domain controller {name}",
                    f"smb-signing:{name}",
                    "SMB sessions to the domain controller are not protected against relay and tampering attacks when signing is optional.",
                    f"DC: {name}; SMB2SecurityMode = {smb2_mode}",
                    "Require SMB signing on the domain controller and its clients.",
                    "CWE-319",
                )
            ldaps = _strings(dc, "LDAPSProtocols")
            normalized_ldaps = {p.lower().replace(".", "").replace(" ", "") for p in ldaps}
            if ldaps and not normalized_ldaps.intersection({"tls12", "tls13"}):
                add(
                    "low",
                    f"LDAPS on domain controller {name} does not offer TLS 1.2+",
                    f"ldaps-protocols:{name}",
                    "The domain controller accepts LDAPS connections only with legacy TLS versions.",
                    f"DC: {name}; LDAPSProtocols = {', '.join(ldaps)}",
                    "Enable TLS 1.2 or 1.3 for LDAPS and disable legacy protocols.",
                    "CWE-326",
                )
            if (_text(dc, "SupportSMB1") or "").lower() == "true":
                add(
                    "medium",
                    f"SMBv1 enabled on domain controller {name}",
                    f"smb1:{name}",
                    "SMBv1 is obsolete and was the transport for EternalBlue-class attacks.",
                    f"DC: {name}; SupportSMB1 = true",
                    "Disable SMBv1 on the domain controller.",
                    "CWE-319",
                )

    # --- Risk rules -----------------------------------------------------------
    risk_rules = root.find("RiskRules")
    if risk_rules is not None:
        for rule in risk_rules.findall("HealthcheckRiskRule"):
            risk_id = _text(rule, "RiskId") or "UnknownRule"
            rationale = _text(rule, "Rationale")
            category = _text(rule, "Category")
            model = _text(rule, "Model")
            points = _int_text(rule, "Points")
            mapping = RISK_RULES.get(risk_id)
            if mapping:
                add(
                    mapping["severity"],
                    mapping["title"],
                    risk_id,
                    mapping["description"],
                    f"PingCastle rule {risk_id} ({model}): {rationale}",
                    mapping["remediation"],
                    mapping.get("cwe", ""),
                    raw={
                        "risk_id": risk_id,
                        "points": points,
                        "category": category,
                        "model": model,
                    },
                )
            else:
                add(
                    _points_severity(points or 0),
                    f"PingCastle rule {risk_id}",
                    risk_id,
                    "PingCastle reported this rule; the rule is not yet modelled in VulnScanner.",
                    f"Points: {points}; Model: {model}; Rationale: {rationale}",
                    "Review the rule in the PingCastle report and follow its guidance.",
                    raw={"risk_id": risk_id, "points": points, "category": category, "model": model},
                )

    normalized = result.normalized()
    summary = severity_summary(normalized)
    score = risk_score(summary)
    sites = root.find("Sites")
    site_names = (
        [_text(site, "SiteName") for site in sites.findall("HealthcheckSite")]
        if sites is not None
        else []
    )
    os_data = root.find("OperatingSystem")
    os_distribution = {}
    if os_data is not None:
        for entry in os_data.findall("HealthcheckOSData"):
            os_name = _text(entry, "OperatingSystem") or "unknown"
            os_distribution[os_name] = _int_text(entry, "NumberOfOccurence") or 0
    result.metadata = {
        "domain": domain_name,
        "forest": _text(root, "ForestFQDN"),
        "collector": f"PingCastle {_text(root, 'EngineVersion')}",
        "collected_at": _text(root, "GenerationDate"),
        "maturity_level": _text(root, "MaturityLevel"),
        "pingcastle_scores": {
            "global": _text(root, "GlobalScore"),
            "stale_objects": _text(root, "StaleObjectsScore"),
            "privileged_accounts": _text(root, "PrivilegiedGroupScore"),
            "trusts": _text(root, "TrustScore"),
            "anomalies": _text(root, "AnomalyScore"),
        },
        "domain_controllers": dc_rows,
        "sites": site_names,
        "os_distribution": os_distribution,
        "risk_score": score,
        "risk_label": risk_label(score),
        "findings": summary,
    }
    return result


def scan_pingcastle_report(ctx: ScanContext, report_path: str) -> ScanResult:
    path = Path(report_path).expanduser()
    if not path.is_file():
        raise ValueError(f"AD report file not found: {report_path}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("AD report is larger than 20 MiB")
    try:
        xml_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"Could not read AD report file: {exc}") from exc
    ctx.log(f"Parsing PingCastle Healthcheck report from {path.name}")
    result = parse_pingcastle_xml(xml_text)
    ctx.progress(85, "Evaluating PingCastle Active Directory risk")
    ctx.log(
        f"PingCastle report imported with {len(result.findings)} finding(s), "
        f"risk score {result.metadata.get('risk_score', 0)}"
    )
    return result
