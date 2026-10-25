from app.scanners.base import (
    Finding,
    ScanResult,
    deduplicate_findings,
    finding_fingerprint,
    normalize_finding,
)


def test_finding_to_dict_normalizes_text_and_severity():
    finding = Finding(
        severity="moderate",
        title="  Test title  ",
        category="",
        description="x" * 9000,
        key="k",
    ).to_dict()
    assert finding["severity"] == "medium"
    assert finding["title"] == "  Test title  "
    assert finding["category"] == "other"
    assert len(finding["description"]) == 8000
    assert finding["key"] == "k"


def test_normalize_finding_accepts_dicts():
    finding = normalize_finding(
        {
            "severity": "IMPORTANT",
            "title": "Problem",
            "category": "web",
            "cve": "CVE-2026-0001",
            "raw": {"a": 1},
        }
    )
    assert finding["severity"] == "high"
    assert finding["title"] == "Problem"
    assert finding["raw"] == {"a": 1}
    empty = normalize_finding({})
    assert empty["title"] == "Unnamed finding"
    assert empty["severity"] == "medium"


def test_fingerprint_is_stable_and_key_aware():
    base = {"category": "secret", "title": "A", "cve": "", "location": "f:1"}
    assert finding_fingerprint(base) == finding_fingerprint(dict(base))
    keyed = dict(base, key="rule-a")
    assert finding_fingerprint(keyed) != finding_fingerprint(base)
    assert finding_fingerprint(keyed) == finding_fingerprint(dict(keyed))
    assert len(finding_fingerprint(base)) == 32


def test_deduplicate_merges_severity_evidence_and_occurrences():
    findings = [
        {
            "severity": "low",
            "title": "Same",
            "category": "source",
            "location": "a.py:1",
            "key": "rule",
            "evidence": "first",
            "raw": {"line": 1},
        },
        {
            "severity": "high",
            "title": "Same",
            "category": "source",
            "location": "a.py:1",
            "key": "rule",
            "evidence": "second",
            "raw": {"line": 1},
        },
    ]
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"
    assert "first" in merged[0]["evidence"]
    assert "second" in merged[0]["evidence"]
    assert merged[0]["raw"]["occurrences"] == [{"line": 1}]


def test_scan_result_normalizes_and_summarizes():
    result = ScanResult()
    result.add(Finding(severity="high", title="One", category="test", key="one"))
    result.add({"severity": "low", "title": "One", "category": "test", "key": "one"})
    result.metadata = {"ok": True}
    normalized = result.normalized()
    assert len(normalized) == 1
    assert normalized[0]["severity"] == "high"
    summary = result.summary()
    assert summary["high"] == 1
    assert summary["metadata"] == {"ok": True}
