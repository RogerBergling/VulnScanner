"""Small dependency-free CVSS helpers used for OSV / scanner enrichment."""

from __future__ import annotations

import math
from typing import Any


def _roundup(value: float) -> float:
    return math.ceil(value * 10) / 10


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics.get("S", "U")
        pr_table = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.5},
        }[scope]
        pr = pr_table[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        impact = 1 - (
            (1 - cia[metrics["C"]])
            * (1 - cia[metrics["I"]])
            * (1 - cia[metrics["A"]])
        )
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        if scope == "U":
            base = min(impact * 6.42 + exploitability, 10)
        else:
            base = min(1.08 * (impact * 6.42 + exploitability), 10)
        return _roundup(base)
    except (KeyError, TypeError):
        return None


def cvss_from_vector(vector: str | None) -> float | None:
    if not vector:
        return None
    vector = vector.strip()
    if vector.startswith("CVSS:4"):
        return None
    if vector.startswith("CVSS:3"):
        return cvss3_base_score(vector)
    # CVSS v2 is still present in some older OSV records. Use a conservative
    # approximation rather than inventing a score when parsing fails.
    if "AV:" in vector and "AC:" in vector:
        return None
    return None


def osv_severity(vuln: dict[str, Any]) -> tuple[float | None, str]:
    database_specific = vuln.get("database_specific") or {}
    severity_label = str(database_specific.get("severity") or "").lower()
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, (int, float)):
            numeric = float(score)
            return numeric, label_for_score(numeric)
        if isinstance(score, str):
            if score.replace(".", "", 1).isdigit():
                numeric = float(score)
                return numeric, label_for_score(numeric)
            numeric = cvss_from_vector(score)
            if numeric is not None:
                return numeric, label_for_score(numeric)
    numeric = None
    if severity_label in {"critical", "high", "medium", "moderate", "low"}:
        label = "medium" if severity_label == "moderate" else severity_label
        numeric = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}[label]
        return numeric, label
    return numeric, "medium"


def label_for_score(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
