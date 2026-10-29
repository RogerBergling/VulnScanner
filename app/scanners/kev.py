"""CISA Known Exploited Vulnerabilities catalog integration."""

from __future__ import annotations

from typing import Any

import requests

from ..database import get_db, set_setting, utcnow

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
USER_AGENT = "VulnScanner/1.0 (local vulnerability scanner)"


class KevSyncError(RuntimeError):
    pass


def sync_kev() -> dict[str, Any]:
    try:
        response = requests.get(KEV_URL, timeout=60, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise KevSyncError(f"Could not download the CISA KEV catalog: {exc}") from exc

    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise KevSyncError("Unexpected KEV catalog format")

    synced_at = utcnow()
    rows = []
    for item in vulnerabilities:
        cve_id = str(item.get("cveID") or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        rows.append(
            (
                cve_id,
                str(item.get("vendorProject") or ""),
                str(item.get("product") or ""),
                str(item.get("vulnerabilityName") or item.get("name") or ""),
                str(item.get("dateAdded") or ""),
                str(item.get("dueDate") or ""),
                str(item.get("knownRansomwareCampaignUse") or ""),
                str(item.get("requiredAction") or ""),
                synced_at,
            )
        )
    with get_db() as conn:
        # Replace the catalogue atomically. Upserting alone leaves CVEs that
        # CISA has removed from the feed in the local table forever.
        conn.execute("DELETE FROM kev_catalog")
        conn.executemany(
            "INSERT INTO kev_catalog"
            "(cve_id, vendor_project, product, name, date_added, due_date, "
            "known_ransomware, required_action, synced_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    set_setting("kev_last_sync", synced_at)
    return {
        "count": len(rows),
        "catalog_version": data.get("catalogVersion", ""),
        "date_released": data.get("dateReleased", ""),
        "synced_at": synced_at,
    }


def enrich_finding(finding: dict[str, Any], cves: dict[str, dict[str, Any]]) -> None:
    cve_ids = [
        item.strip()
        for item in str(finding.get("cve") or "").split(",")
        if item.strip()
    ]
    entries = [cves[cve] for cve in cve_ids if cve in cves]
    if not entries:
        return
    raw = finding.setdefault("raw", {})
    raw["kev"] = {
        "cve_id": entries[0]["cve_id"],
        "name": entries[0]["name"],
        "date_added": entries[0]["date_added"],
        "due_date": entries[0]["due_date"],
        "known_ransomware": entries[0]["known_ransomware"],
        "required_action": entries[0]["required_action"],
    }
    if len(entries) > 1:
        raw["kev_all"] = [
            {
                "cve_id": entry["cve_id"],
                "name": entry["name"],
                "date_added": entry["date_added"],
                "due_date": entry["due_date"],
                "known_ransomware": entry["known_ransomware"],
                "required_action": entry["required_action"],
            }
            for entry in entries
        ]
    if "(CISA KEV)" not in finding.get("title", ""):
        finding["title"] = f"{finding['title']} (CISA KEV)"
    for entry in entries:
        note = (
            f"{entry['cve_id']} is listed in CISA's Known Exploited Vulnerabilities catalog. "
            f"Required action: {entry['required_action'] or 'Apply vendor remediation.'}"
        )
        if note not in finding.get("description", ""):
            finding["description"] = (finding.get("description", "") + "\n\n" + note).strip()
        if entry.get("known_ransomware", "").lower() == "known":
            ransomware = "Known ransomware campaign use: yes."
            if ransomware not in finding.get("description", ""):
                finding["description"] += "\n" + ransomware
