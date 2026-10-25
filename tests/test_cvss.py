import pytest

from app.scanners.cvss import (
    cvss3_base_score,
    cvss_from_vector,
    label_for_score,
    osv_severity,
)


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", None),
        ("not-a-vector", None),
    ],
)
def test_cvss3_base_score(vector, expected):
    assert cvss3_base_score(vector) == expected


def test_cvss_from_vector_handles_missing_and_v4():
    assert cvss_from_vector(None) is None
    assert cvss_from_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None


def test_label_for_score_boundaries():
    assert label_for_score(None) == "medium"
    assert label_for_score(0) == "info"
    assert label_for_score(0.1) == "low"
    assert label_for_score(4.0) == "medium"
    assert label_for_score(7.0) == "high"
    assert label_for_score(9.0) == "critical"


def test_osv_severity_numeric_vector_and_label():
    assert osv_severity({"severity": [{"score": 9.8}]}) == (9.8, "critical")
    assert osv_severity({"severity": [{"score": "7.5"}]}) == (7.5, "high")
    vector = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert osv_severity(vector) == (9.8, "critical")
    label = {"database_specific": {"severity": "moderate"}}
    assert osv_severity(label) == (5.5, "medium")
    assert osv_severity({}) == (None, "medium")
