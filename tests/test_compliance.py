"""Tests for the compliance framework mapping (offline)."""

from app.scanners.compliance import FRAMEWORKS, scan_compliance


def _finding(**overrides):
    finding = {
        "severity": "medium",
        "title": "Generic finding",
        "category": "other",
        "cve": "",
        "cwe": "",
        "key": "",
        "location": "",
    }
    finding.update(overrides)
    return finding


def test_cve_finding_maps_to_vuln_management():
    findings = [_finding(category="dependency", cve="CVE-2024-0001", severity="critical")]
    report = scan_compliance(findings)
    frameworks = {item["name"]: item for item in report["frameworks"]}
    ids = {control["id"] for control in frameworks["PCI DSS 4.0"]["controls"]}
    assert "6.3" in ids
    iso_ids = {control["id"] for control in frameworks["ISO 27001:2022"]["controls"]}
    assert "A.8.8" in iso_ids
    assert report["mapped_findings"] >= 2  # matched by several frameworks


def test_sqli_maps_to_application_security():
    findings = [_finding(category="web", cwe="CWE-89", key="sqli:id", severity="high")]
    report = scan_compliance(findings)
    frameworks = {item["name"]: item for item in report["frameworks"]}
    assert "A.8.26" in {c["id"] for c in frameworks["ISO 27001:2022"]["controls"]}
    assert "2.2" in {c["id"] for c in frameworks["PCI DSS 4.0"]["controls"]}


def test_open_port_maps_to_network_controls():
    findings = [_finding(category="network", key="open-port:23", severity="info")]
    report = scan_compliance(findings)
    frameworks = {item["name"]: item for item in report["frameworks"]}
    pci_ids = {c["id"] for c in frameworks["PCI DSS 4.0"]["controls"]}
    assert "1.2" in pci_ids
    assert "A.8.21" in {c["id"] for c in frameworks["ISO 27001:2022"]["controls"]}


def test_ad_findings_map_to_identity():
    findings = [_finding(category="ad", cwe="CWE-522", severity="high")]
    report = scan_compliance(findings)
    frameworks = {item["name"]: item for item in report["frameworks"]}
    assert "8.2" in {c["id"] for c in frameworks["PCI DSS 4.0"]["controls"]}
    assert "A.8.5" in {c["id"] for c in frameworks["ISO 27001:2022"]["controls"]}


def test_secrets_map_to_leakage_controls():
    findings = [_finding(category="secrets", severity="critical")]
    report = scan_compliance(findings)
    frameworks = {item["name"]: item for item in report["frameworks"]}
    assert "A.8.12" in {c["id"] for c in frameworks["ISO 27001:2022"]["controls"]}
    assert "3.2" in {c["id"] for c in frameworks["PCI DSS 4.0"]["controls"]}


def test_unrelated_findings_map_to_nothing():
    findings = [_finding(category="other", severity="info")]
    report = scan_compliance(findings)
    assert report["frameworks"] == []
    assert report["mapped_findings"] == 0


def test_severity_counts_and_sample_findings():
    findings = [
        _finding(category="dependency", cve="CVE-2024-0001", severity="critical", title="A"),
        _finding(category="dependency", cve="CVE-2024-0002", severity="high", title="B"),
    ]
    report = scan_compliance(findings)
    framework = next(item for item in report["frameworks"] if item["name"] == "ISO 27001:2022")
    control = next(c for c in framework["controls"] if c["id"] == "A.8.8")
    assert control["finding_count"] == 2
    assert control["severity"]["critical"] == 1
    assert control["severity"]["high"] == 1
    assert {item["title"] for item in control["findings"]} == {"A", "B"}


def test_all_framework_names_present():
    assert set(FRAMEWORKS.keys()) == {"PCI DSS 4.0", "ISO 27001:2022", "CIS Controls v8"}
