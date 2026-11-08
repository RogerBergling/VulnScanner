"""Tests for endpoint package normalization and Windows EOL checks."""

from app.scanners.agent import _add_windows_software_eol
from app.scanners.base import ScanResult


def test_windows_registry_eol_software_produces_finding():
    result = ScanResult()
    _add_windows_software_eol(
        result,
        [
            {
                "name": "Adobe Flash Player",
                "version": "32.0.0.465",
                "ecosystem": "",
                "source": "windows-registry",
                "publisher": "Adobe",
            }
        ],
    )
    assert len(result.findings) == 1
    assert result.findings[0].severity == "critical"
    assert "Adobe Flash" in result.findings[0].title
