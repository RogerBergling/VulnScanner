import pytest

from app.utils import (
    format_duration,
    human_age,
    normalize_repo_target,
    normalize_severity,
    normalize_target_url,
    parse_ports,
    redact_secret,
    redact_url,
    risk_label,
    risk_score,
    secure_filename,
    severity_summary,
    truncate,
    validate_host_target,
)


def test_normalize_severity_aliases_and_fallback():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("moderate") == "medium"
    assert normalize_severity("important") == "high"
    assert normalize_severity("informational") == "info"
    assert normalize_severity("nonsense") == "medium"
    assert normalize_severity(None) == "medium"
    assert normalize_severity("bad", default="low") == "low"


def test_risk_score_is_weighted_and_capped():
    assert risk_score({}) == 0
    assert risk_score({"medium": 2}) == 6
    assert risk_score({"critical": 10}) == 100
    assert risk_label(0) == "None"
    assert risk_label(1) == "Low"
    assert risk_label(20) == "Medium"
    assert risk_label(40) == "High"
    assert risk_label(70) == "Critical"


def test_severity_summary_counts_all_levels():
    summary = severity_summary(
        [
            {"severity": "high"},
            {"severity": "HIGH"},
            {"severity": "moderate"},
            {"severity": "unknown"},
        ]
    )
    assert summary["high"] == 2
    assert summary["medium"] == 2
    assert summary["total"] == 4


def test_normalize_target_url():
    assert normalize_target_url("example.com") == "https://example.com"
    assert normalize_target_url("http://example.com/path/") == "http://example.com/path"
    with pytest.raises(ValueError):
        normalize_target_url("")
    with pytest.raises(ValueError):
        normalize_target_url("ftp://example.com")
    with pytest.raises(ValueError):
        normalize_target_url("https:///nohost")


def test_repo_target_resolution(tmp_path):
    assert normalize_repo_target("owner/repo") == "https://github.com/owner/repo.git"
    assert normalize_repo_target("https://github.com/owner/repo") == "https://github.com/owner/repo"
    assert normalize_repo_target(str(tmp_path)) == str(tmp_path.resolve())
    with pytest.raises(ValueError):
        normalize_repo_target("git@github.com:owner/repo.git")
    with pytest.raises(ValueError):
        normalize_repo_target(str(tmp_path / "missing"))


def test_validate_host_target():
    assert validate_host_target("example.com") == ("host", "example.com")
    assert validate_host_target("10.0.0.0/24") == ("cidr", "10.0.0.0/24")
    with pytest.raises(ValueError):
        validate_host_target("")
    with pytest.raises(ValueError):
        validate_host_target("bad host")
    with pytest.raises(ValueError):
        validate_host_target("10.0.0.0/99")


def test_parse_ports_profiles_and_validation():
    assert parse_ports("443,80,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert parse_ports("web") == [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
    assert len(parse_ports(None, "common")) == 58
    assert len(parse_ports(None, "top1000")) == 1000
    with pytest.raises(ValueError):
        parse_ports("0")
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("10-5")
    with pytest.raises(ValueError):
        parse_ports("1-6000")
    with pytest.raises(ValueError):
        parse_ports("not-a-port")


def test_secret_and_url_redaction():
    assert redact_secret("abcdefghijklmnop") == "abcd********mnop"
    assert redact_secret("short") == "*****"
    assert redact_url("https://user:pass@example.com:8443/x") == "https://***@example.com:8443/x"
    assert redact_url("https://example.com/x") == "https://example.com/x"


def test_presentation_helpers():
    assert secure_filename("Report: Acme / 2026!") == "Report_Acme_2026"
    assert secure_filename("***") == "report"
    assert truncate(" one\n\ntwo   three ", 12) == "one two thre"
    assert human_age(None) == "never"
    assert format_duration(None, None) == "—"
    assert format_duration("2026-01-01T00:00:00+00:00", "2026-01-01T00:01:05+00:00") == "1m 5s"
