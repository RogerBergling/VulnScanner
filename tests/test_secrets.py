from pathlib import Path

from app.scanners.base import ScanResult
from app.scanners.secrets import _looks_placeholder, scan_secrets, scan_text, shannon_entropy
from tests.helpers import DummyContext


def _scan(text: str) -> tuple[ScanResult, int]:
    result = ScanResult()
    count = scan_text(text, "src/config.py", result)
    return result, count


def test_entropy_and_placeholder_heuristics():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("aB3dE5fG7hJ9") > 3.5
    assert _looks_placeholder("changeme123456")
    assert _looks_placeholder("${SECRET_VALUE}")
    assert _looks_placeholder("123456789012")
    assert not _looks_placeholder("aB3dE5fG7hJ9kL2m")


def test_provider_specific_secret_is_redacted():
    result, count = _scan('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
    assert count == 1
    finding = result.normalized()[0]
    assert finding["severity"] == "critical"
    assert finding["category"] == "secret"
    assert finding["location"] == "src/config.py:1"
    assert "AKIAIOSFODNN7EXAMPLE" not in finding["evidence"]
    assert finding["raw"]["rule"] == "aws-access-key"


def test_private_key_and_database_url_are_detected():
    text = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "postgres://app:supersecret@db.internal/prod\n"
        "DATABASE_URL=mysql://root:hunter2@db/prod\n"
    )
    result, count = _scan(text)
    assert count >= 3
    rules = {finding["raw"]["rule"] for finding in result.normalized()}
    assert "private-key" in rules
    assert "database-url" in rules


def test_generic_high_entropy_assignment():
    result, count = _scan('client_secret = "aB3dE5fG7hJ9kL2mN4pQ6rS8"\n')
    assert count == 1
    finding = result.normalized()[0]
    assert finding["raw"]["rule"] == "generic-secret"
    assert finding["severity"] == "high"
    assert "aB3dE5fG7hJ9kL2mN4pQ6rS8" not in finding["evidence"]


def test_placeholders_and_lockfiles_are_not_flagged():
    text = (
        'password = "changeme123456"\n'
        'api_key = "your-api-key-goes-here"\n'
        "this is normal documentation text\n"
    )
    result, count = _scan(text)
    assert count == 0
    assert result.normalized() == []


def test_scan_secrets_finds_env_file_and_metadata(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"name":"x","lockfileVersion":3,"packages":{}}', encoding="utf-8"
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("token=AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
    result = scan_secrets(DummyContext(), tmp_path)
    titles = {finding["title"] for finding in result.normalized()}
    assert "Environment file committed to the repository" in titles
    assert "AWS access key ID detected" in titles
    assert result.metadata["files_scanned"] >= 1
    assert result.metadata["env_files"] == [".env"]


def test_scan_secrets_rejects_non_directory(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("x")
    try:
        scan_secrets(DummyContext(), path)
    except ValueError as exc:
        assert "not a directory" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_secret_scan_has_a_finding_limit():
    result = ScanResult()
    text = "\n".join(f"aws_key_{i} = 'AKIAIOSFODNN7EXAMPLE'" for i in range(5))
    added = scan_text(text, "x.py", result, max_findings=2)
    assert added == 2
    assert len(result.findings) == 2
