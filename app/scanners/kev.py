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
        conn.executemany(
            "INSERT INTO kev_catalog"
            "(cve_id, vendor_project, product, name, date_added, due_date, "
            "known_ransomware, required_action, synced_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET vendor_project = excluded.vendor_project, "
            "product = excluded.product, name = excluded.name, date_added = excluded.date_added, "
            "due_date = excluded.due_date, known_ransomware = excluded.known_ransomware, "
            "required_action = excluded.required_action, synced_at = excluded.synced_at",
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
    cve = (finding.get("cve") or "").split(",")[0].strip()
    entry = cves.get(cve)
    if not entry:
        return
    raw = finding.setdefault("raw", {})
    raw["kev"] = {
        "cve_id": entry["cve_id"],
        "name": entry["name"],
        "date_added": entry["date_added"],
        "due_date": entry["due_date"],
        "known_ransomware": entry["known_ransomware"],
        "required_action": entry["required_action"],
    }
    finding["title"] = f"{finding['title']} (CISA KEV)"
    note = (
        "This CVE is listed in CISA's Known Exploited Vulnerabilities catalog. "
        f"Required action: {entry['required_action'] or 'Apply vendor remediation.'}"
    )
    if note not in finding.get("description", ""):
        finding["description"] = (finding.get("description", "") + "\n\n" + note).strip()
    if entry.get("known_ransomware", "").lower() == "known":
        finding["description"] += "\nKnown ransomware campaign use: yes."
