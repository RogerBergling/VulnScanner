"""Tests for banner/CPE fingerprinting and NVD CVE filtering (offline)."""

from app.scanners.cpe import (
    _cpe_match_applies,
    filter_cves_for_product,
    fingerprint_text,
    product_cpe,
    split_cpe_fields,
    version_in_range,
    version_tuple,
)


def _nvd_response(criteria: str, cve_id: str = "CVE-2024-0001", **match_fields) -> dict:
    match = {"vulnerable": True, "criteria": criteria, **match_fields}
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "vulnStatus": "Analyzed",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "baseSeverity": "CRITICAL",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-287"}]}
                    ],
                    "configurations": [
                        {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [match]}]}
                    ],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }
        ]
    }


def test_fingerprint_ssh_banner():
    matches = fingerprint_text("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "banner")
    assert len(matches) == 1
    match = matches[0]
    assert match.vendor == "openbsd"
    assert match.product == "openssh"
    assert match.version.startswith("8.2")
    assert match.cpe == product_cpe("openbsd", "openssh", match.version)


def test_fingerprint_apache_header():
    matches = fingerprint_text("Apache/2.4.41 (Ubuntu)", "http-server-header")
    assert len(matches) == 1
    assert matches[0].vendor == "apache"
    assert matches[0].product == "http_server"
    assert matches[0].version.startswith("2.4.41")


def test_fingerprint_nginx_nmap_join():
    matches = fingerprint_text("nginx 1.18.0", "nmap")
    assert len(matches) == 1
    assert matches[0].product == "nginx"
    assert matches[0].version == "1.18.0"


def test_fingerprint_mariadb_banner():
    matches = fingerprint_text("5.5.5-10.3.38-MariaDB-0ubuntu0.20.04.1", "banner")
    assert len(matches) == 1
    assert matches[0].product == "mariadb"
    assert matches[0].version.startswith("10.3.38")


def test_fingerprint_php_powered_by():
    matches = fingerprint_text("PHP/7.4.3", "http-x-powered-by")
    assert len(matches) == 1
    assert matches[0].vendor == "php"
    assert matches[0].product == "php"
    assert matches[0].version == "7.4.3"


def test_fingerprint_empty_and_unknown():
    assert fingerprint_text("", "banner") == []
    assert fingerprint_text("random service text", "banner") == []


def test_version_tuple():
    assert version_tuple("8.2p1") >= version_tuple("8.2")
    assert version_tuple("8.2p1") < version_tuple("8.3")
    assert version_tuple("10.0") == version_tuple("10.0")
    assert version_tuple("2.4.41ubuntu") >= version_tuple("2.4.41")


def test_version_in_range():
    assert version_in_range("8.2", "8.1", None, None, None)
    assert version_in_range("8.2", None, None, "8.3", None)
    assert not version_in_range("8.2", None, None, None, "8.2")
    assert not version_in_range("8.2", "8.3", None, None, None)
    assert version_in_range("8.2p1", "8.2", None, "8.3", None)


def test_split_cpe_fields_handles_escaped_colons():
    criteria = r"cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
    fields = split_cpe_fields(criteria)
    assert fields[0:6] == ["cpe", "2.3", "a", "openbsd", "openssh", "8.2p1"]


def test_exact_cpe_match():
    criteria = r"cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
    data = _nvd_response(criteria)
    cves = filter_cves_for_product(data, "openbsd", "openssh", "8.2p1")
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2024-0001"


def test_range_match():
    criteria = r"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    data = _nvd_response(
        criteria, versionStartIncluding="8.0", versionEndExcluding="8.5"
    )
    assert len(filter_cves_for_product(data, "openbsd", "openssh", "8.2p1")) == 1
    assert filter_cves_for_product(data, "openbsd", "openssh", "8.6") == []


def test_non_vulnerable_match_ignored():
    criteria = r"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    data = _nvd_response(criteria, vulnerable=False)
    assert filter_cves_for_product(data, "openbsd", "openssh", "8.2") == []


def test_other_product_not_matched():
    data = _nvd_response(r"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
    assert filter_cves_for_product(data, "openbsd", "openssh", "8.2") == []


def test_versioned_mismatch():
    data = _nvd_response(r"cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*")
    assert filter_cves_for_product(data, "openbsd", "openssh", "8.2") == []
    assert len(filter_cves_for_product(data, "openbsd", "openssh", "9.0")) == 1


def test_cpe_match_applies_helper():
    match = {
        "vulnerable": True,
        "criteria": r"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "1.20",
    }
    assert _cpe_match_applies(match, "f5", "nginx", "1.18.0")
    assert not _cpe_match_applies(match, "f5", "nginx", "1.22.0")
    assert not _cpe_match_applies(match, "nginx", "nginx", "1.18.0")
