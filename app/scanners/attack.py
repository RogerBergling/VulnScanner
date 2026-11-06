"""MITRE ATT&CK mapping for findings.

Maps findings onto ATT&CK Enterprise techniques using their CWE, category and
key. The mapping is a curated subset — enough to power an ATT&CK overlay on
findings and the dashboard without pretending to be complete. Technique IDs
follow MITRE ATT&CK v16; the data lives in this module so it works fully
offline.
"""

from __future__ import annotations

from typing import Any

# CWE -> list of (technique_id, technique_name, tactic)
CWE_TECHNIQUES: dict[str, list[tuple[str, str, str]]] = {
    "CWE-89": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "CWE-79": [("T1189", "Drive-by Compromise", "Initial Access")],
    "CWE-22": [("T1083", "File and Directory Discovery", "Discovery"),
               ("T1005", "Data from Local System", "Collection")],
    "CWE-200": [("T1087", "Account Discovery", "Discovery"),
                ("T1046", "Network Service Discovery", "Discovery")],
    "CWE-287": [("T1110", "Brute Force", "Credential Access")],
    "CWE-306": [("T1133", "External Remote Services", "Initial Access")],
    "CWE-307": [("T1110", "Brute Force", "Credential Access")],
    "CWE-522": [("T1003", "OS Credential Dumping", "Credential Access"),
                ("T1110", "Brute Force", "Credential Access"),
                ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access")],
    "CWE-798": [("T1078", "Valid Accounts", "Defense Evasion")],
    "CWE-284": [("T1098", "Account Manipulation", "Persistence"),
                ("T1078", "Valid Accounts", "Defense Evasion")],
    "CWE-269": [("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
                ("T1098", "Account Manipulation", "Persistence")],
    "CWE-263": [("T1558", "Steal or Forge Kerberos Tickets", "Credential Access")],
    "CWE-319": [("T1557", "Adversary-in-the-Middle", "Credential Access"),
                ("T1040", "Network Sniffing", "Credential Access")],
    "CWE-326": [("T1557", "Adversary-in-the-Middle", "Credential Access")],
    "CWE-327": [("T1600", "Weaken Encryption", "Defense Evasion"),
                ("T1110", "Brute Force", "Credential Access")],
    "CWE-521": [("T1110", "Brute Force", "Credential Access")],
    "CWE-538": [("T1083", "File and Directory Discovery", "Discovery")],
    "CWE-693": [("T1562", "Impair Defenses", "Defense Evasion")],
    "CWE-732": [("T1574", "Hijack Execution Flow", "Persistence")],
    "CWE-1104": [("T1505", "Server Software Component", "Persistence"),
                 ("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "CWE-345": [("T1557", "Adversary-in-the-Middle", "Credential Access")],
    "CWE-262": [("T1078", "Valid Accounts", "Defense Evasion")],
    "CWE-778": [("T1562", "Impair Defenses", "Defense Evasion")],
    "CWE-311": [("T1040", "Network Sniffing", "Credential Access")],
    "CWE-295": [("T1557", "Adversary-in-the-Middle", "Credential Access")],
}

# Category-level fallbacks when no CWE mapping applies.
CATEGORY_TECHNIQUES: dict[str, list[tuple[str, str, str]]] = {
    "network": [("T1046", "Network Service Discovery", "Discovery")],
    "web": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "dependency": [("T1204", "User Execution", "Execution")],
    "secrets": [("T1552", "Unsecured Credentials", "Credential Access")],
    "ad": [("T1098", "Account Manipulation", "Persistence"),
           ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access")],
}


def techniques_for(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Return ATT&CK techniques applicable to a finding."""
    matches: list[dict[str, str]] = []
    seen: set[str] = set()
    cwes = [c.strip() for c in str(finding.get("cwe") or "").split(",") if c.strip()]
    for cwe in cwes:
        for technique_id, name, tactic in CWE_TECHNIQUES.get(cwe.upper(), []):
            if technique_id in seen:
                continue
            seen.add(technique_id)
            matches.append({"id": technique_id, "name": name, "tactic": tactic})
    if not matches:
        category = str(finding.get("category") or "")
        for technique_id, name, tactic in CATEGORY_TECHNIQUES.get(category, []):
            if technique_id in seen:
                continue
            seen.add(technique_id)
            matches.append({"id": technique_id, "name": name, "tactic": tactic})
    return matches


def enrich_finding_with_attack(finding: dict[str, Any]) -> None:
    """Attach ``raw.attack`` to a finding when a mapping applies."""
    techniques = techniques_for(finding)
    if not techniques:
        return
    raw = finding.setdefault("raw", {})
    raw["attack"] = techniques
