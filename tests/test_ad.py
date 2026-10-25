import json

import pytest

from app.scanners.ad import _count, _names, process_ad_report, scan_ad_report
from tests.helpers import DummyContext


def _risky_report():
    return {
        "domain": {
            "name": "corp.example",
            "forest": "corp.example",
            "domain_controller": "DC01",
            "machine_account_quota": 10,
            "recycle_bin_enabled": False,
            "functional_level": "Windows Server 2008 R2",
        },
        "collected_at": "2026-01-02T03:04:05Z",
        "collector": "test collector",
        "guest_enabled": True,
        "password_policy": {
            "min_length": 8,
            "complexity": False,
            "lockout_threshold": 0,
            "max_age_days": 400,
        },
        "krbtgt_password_age_days": 500,
        "unconstrained_delegation": {"count": 2, "accounts": ["DC01$", "DC02$"]},
        "kerberoastable": {"count": 3, "privileged": 1, "accounts": ["svc_sql", "svc_web"]},
        "asrep_roastable": {"count": 2, "privileged": 0, "accounts": ["olduser"]},
        "stale_users": {"count": 4, "privileged": 1, "accounts": ["former-admin"]},
        "never_expires": {"count": 20, "privileged": 2},
        "admin_count": {"non_privileged": {"count": 2, "accounts": ["leftover"]}},
        "privileged_groups": {"Domain Admins": 7, "Enterprise Admins": 2},
        "stale_computers": 5,
        "counts": {"users": 100, "computers": 20},
        "findings": [
            {
                "severity": "high",
                "title": "Custom AD issue",
                "description": "Imported custom finding",
                "key": "custom-ad",
            }
        ],
    }


def test_process_ad_report_generates_expected_findings():
    result = process_ad_report(_risky_report())
    findings = result.normalized()
    keys = {finding["key"] for finding in findings}
    assert {
        "ad:guest-enabled",
        "ad:password-length",
        "ad:password-complexity",
        "ad:no-lockout",
        "ad:password-age",
        "ad:krbtgt-age",
        "ad:unconstrained-delegation",
        "ad:kerberoastable",
        "ad:asrep-roastable",
        "ad:stale-users",
        "ad:never-expires",
        "ad:admin-count",
        "ad:privileged-group:Domain Admins",
        "ad:stale-computers",
        "ad:machine-account-quota",
        "ad:recycle-bin",
        "ad:functional-level",
        "custom-ad",
    }.issubset(keys)
    assert "ad:privileged-group:Enterprise Admins" not in keys
    assert result.metadata["domain"] == "corp.example"
    assert result.metadata["metrics"]["kerberoastable"] == 3
    assert result.metadata["metrics"]["unconstrained_delegation"] == 2
    assert result.metadata["risk_score"] > 0
    unconstrained = next(f for f in findings if f["key"] == "ad:unconstrained-delegation")
    assert unconstrained["severity"] == "critical"
    assert "DC01$" in unconstrained["evidence"]
    kerb = next(f for f in findings if f["key"] == "ad:kerberoastable")
    assert kerb["severity"] == "high"


def test_process_ad_report_accepts_string_domain_and_empty_report():
    result = process_ad_report({"domain": "example.test"})
    assert result.metadata["domain"] == "example.test"
    assert result.findings == []
    empty = process_ad_report({})
    assert empty.metadata["domain"] == "Unknown domain"
    assert empty.metadata["risk_score"] == 0


def test_medium_thresholds_for_password_and_krbtgt():
    result = process_ad_report(
        {
            "password_policy": {"min_length": 10},
            "krbtgt_password_age_days": 200,
        }
    )
    severities = {finding["key"]: finding["severity"] for finding in result.normalized()}
    assert severities["ad:password-length"] == "medium"
    assert severities["ad:krbtgt-age-medium"] == "medium"


def test_helpers_handle_shapes():
    assert _count({"count": "4"}) == 4
    assert _count({"accounts": ["a", "b"]}) == 2
    assert _count([1, 2, 3]) == 3
    assert _count("7") == 7
    assert _count("bad") == 0
    assert _names({"accounts": [{"name": "one"}, {"sam": "two"}, "three"]}) == [
        "one",
        "two",
        "three",
    ]
    assert _names({"privileged": [{"dn": "CN=x"}]}) == ["CN=x"]
    assert _names("bad") == []


def test_scan_ad_report_reads_file(tmp_path):
    report_path = tmp_path / "ad.json"
    report_path.write_text(json.dumps(_risky_report()), encoding="utf-8")
    ctx = DummyContext(target=str(report_path))
    result = scan_ad_report(ctx, str(report_path))
    assert result.metadata["domain"] == "corp.example"
    assert any("Loaded Active Directory" in message for _level, message in ctx.logs)


def test_scan_ad_report_validation(tmp_path):
    ctx = DummyContext()
    with pytest.raises(ValueError, match="not found"):
        scan_ad_report(ctx, str(tmp_path / "missing.json"))

    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not read"):
        scan_ad_report(ctx, str(bad))

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        scan_ad_report(ctx, str(array))

    huge = tmp_path / "huge.json"
    huge.write_bytes(b"{" + b" " * (20 * 1024 * 1024) + b"}")
    with pytest.raises(ValueError, match="larger than 20 MiB"):
        scan_ad_report(ctx, str(huge))
