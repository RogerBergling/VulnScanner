"""Tests for ATT&CK mapping and context-aware risk scoring (offline)."""

from app.scanners.attack import enrich_finding_with_attack, techniques_for
from app.utils import context_risk_score, risk_score


def test_cwe_mapping():
    techniques = techniques_for({"cwe": "CWE-89"})
    assert any(item["id"] == "T1190" for item in techniques)
    assert any(item["tactic"] == "Initial Access" for item in techniques)


def test_multiple_cwes_dedupe():
    techniques = techniques_for({"cwe": "CWE-522,CWE-798"})
    ids = [item["id"] for item in techniques]
    assert len(ids) == len(set(ids))
    assert "T1110" in ids  # from CWE-522
    assert "T1078" in ids  # from CWE-798


def test_category_fallback():
    techniques = techniques_for({"cwe": "", "category": "secrets"})
    assert any(item["id"] == "T1552" for item in techniques)
    assert techniques_for({"cwe": "", "category": "other"}) == []


def test_enrich_attaches_to_raw():
    finding = {"cwe": "CWE-79", "raw": {"engine": "builtin"}}
    enrich_finding_with_attack(finding)
    assert "attack" in finding["raw"]
    assert any(item["id"] == "T1189" for item in finding["raw"]["attack"])


def test_enrich_no_mapping():
    finding = {"cwe": "", "category": "other", "raw": {}}
    enrich_finding_with_attack(finding)
    assert "attack" not in finding["raw"]


def test_context_score_kev_boost():
    summary = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1}
    base = risk_score(summary)
    plain = context_risk_score(summary, [{"severity": "critical", "raw": {}}])
    kev = context_risk_score(summary, [{"severity": "critical", "raw": {"kev": {"cve_id": "CVE-2024-0001"}}}])
    assert plain == base
    assert kev > base


def test_context_score_epss_boost():
    summary = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1}
    high_epss = context_risk_score(
        summary,
        [{"severity": "critical", "raw": {"epss": {"percentile": 0.97, "score": 0.8}}}],
    )
    low_epss = context_risk_score(
        summary,
        [{"severity": "critical", "raw": {"epss": {"percentile": 0.1, "score": 0.01}}}],
    )
    assert high_epss > low_epss


def test_context_score_capped_at_100():
    findings = [
        {"severity": "critical", "raw": {"kev": {"cve_id": f"CVE-2024-{i:04d}"}}}
        for i in range(20)
    ]
    summary = {"critical": 20, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 20}
    assert context_risk_score(summary, findings) == 100


def test_context_score_ignores_low_severity():
    summary = {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1}
    plain = context_risk_score(summary, [{"severity": "medium", "raw": {}}])
    kev = context_risk_score(summary, [{"severity": "medium", "raw": {"kev": {"cve_id": "CVE-2024-0001"}}}])
    assert plain == kev
