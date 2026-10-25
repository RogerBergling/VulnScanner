"""Common types for scan engines."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..database import log_event, scan_cancelled, update_scan
from ..utils import clean_text, normalize_severity, severity_summary, utcnow


@dataclass
class Finding:
    severity: str
    title: str
    category: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: str = ""
    cwe: str = ""
    cvss: float | None = None
    location: str = ""
    resource: str = ""
    key: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity = normalize_severity(self.severity)
        return {
            "severity": severity,
            "title": clean_text(self.title, 300),
            "category": clean_text(self.category, 60) or "other",
            "description": clean_text(self.description, 8000),
            "evidence": clean_text(self.evidence, 6000),
            "remediation": clean_text(self.remediation, 4000),
            "cve": clean_text(self.cve, 300),
            "cwe": clean_text(self.cwe, 300),
            "cvss": self.cvss,
            "location": clean_text(self.location, 2000),
            "resource": clean_text(self.resource, 2000),
            "key": clean_text(self.key, 300),
            "raw": self.raw,
        }


def normalize_finding(value: Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, Finding):
        return value.to_dict()
    severity = normalize_severity(str(value.get("severity", "medium")))
    return {
        "severity": severity,
        "title": clean_text(str(value.get("title") or "Unnamed finding"), 300),
        "category": clean_text(str(value.get("category") or "other"), 60),
        "description": clean_text(str(value.get("description") or ""), 8000),
        "evidence": clean_text(str(value.get("evidence") or ""), 6000),
        "remediation": clean_text(str(value.get("remediation") or ""), 4000),
        "cve": clean_text(str(value.get("cve") or ""), 300),
        "cwe": clean_text(str(value.get("cwe") or ""), 300),
        "cvss": value.get("cvss"),
        "location": clean_text(str(value.get("location") or ""), 2000),
        "resource": clean_text(str(value.get("resource") or ""), 2000),
        "key": clean_text(str(value.get("key") or ""), 300),
        "raw": value.get("raw") if isinstance(value.get("raw"), dict) else {},
    }


def finding_fingerprint(finding: dict[str, Any]) -> str:
    key = finding.get("key")
    if key:
        raw = f"{finding.get('category')}|{key}|{finding.get('cve')}|{finding.get('location')}"
    else:
        raw = "|".join(
            [
                str(finding.get("category") or ""),
                str(finding.get("title") or ""),
                str(finding.get("cve") or ""),
                str(finding.get("location") or ""),
                str(finding.get("resource") or ""),
            ]
        )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge identical findings, keeping the highest severity and evidence."""
    merged: dict[str, dict[str, Any]] = {}
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for finding in findings:
        fp = finding_fingerprint(finding)
        finding["fingerprint"] = fp
        existing = merged.get(fp)
        if not existing:
            merged[fp] = finding
            continue
        if rank.get(finding["severity"], 0) > rank.get(existing["severity"], 0):
            existing["severity"] = finding["severity"]
        evidence = finding.get("evidence", "")
        if evidence and evidence not in existing.get("evidence", ""):
            existing["evidence"] = (existing.get("evidence", "") + "\n" + evidence)[:6000]
        if finding.get("raw"):
            existing.setdefault("raw", {}).setdefault("occurrences", []).append(finding["raw"])
    return list(merged.values())


@dataclass
class ScanResult:
    findings: list[Finding | dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding | dict[str, Any]) -> None:
        self.findings.append(finding)

    def normalized(self) -> list[dict[str, Any]]:
        return deduplicate_findings([normalize_finding(item) for item in self.findings])

    def summary(self) -> dict[str, Any]:
        summary = severity_summary(self.normalized())
        summary["metadata"] = self.metadata
        summary["completed_at"] = utcnow()
        return summary


class ScanContext:
    """Progress/logging/cancellation facade handed to scan engines."""

    def __init__(self, scan_id: int, target: str, options: dict[str, Any]):
        self.scan_id = scan_id
        self.target = target
        self.options = options
        self._last_progress = -1
        self._last_stage = ""

    def log(self, message: str, level: str = "info") -> None:
        log_event(self.scan_id, message, level)

    def progress(self, value: int, stage: str | None = None) -> None:
        value = max(0, min(100, int(value)))
        if value == self._last_progress and (not stage or stage == self._last_stage):
            return
        self._last_progress = value
        fields: dict[str, Any] = {"progress": value, "status": "running"}
        if stage and stage != self._last_stage:
            self._last_stage = stage
            fields["stage"] = stage
        update_scan(self.scan_id, **fields)

    def cancelled(self) -> bool:
        return scan_cancelled(self.scan_id)

    def check_cancel(self) -> None:
        if self.cancelled():
            raise ScanCancelled("Scan cancelled by user")

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def option_bool(self, name: str, default: bool = False) -> bool:
        value = self.options.get(name, default)
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)


class ScanCancelled(Exception):
    pass


def truncate(value: str, length: int = 500) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value[:length]
