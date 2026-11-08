"""Tests for encrypted database backups."""

import pytest

from app.backup_crypto import (
    BackupCryptoError,
    decrypt_file,
    encrypt_file,
    is_encrypted,
)


def test_encrypted_backup_roundtrip(tmp_path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.db.vsenc"
    restored = tmp_path / "restored.db"
    source.write_bytes(b"SQLite format 3\x00" + b"x" * 10000)
    encrypt_file(source, encrypted, "correct horse battery staple")
    assert is_encrypted(encrypted)
    assert encrypted.read_bytes()[:8] == b"VSBACKUP"
    decrypt_file(encrypted, restored, "correct horse battery staple")
    assert restored.read_bytes() == source.read_bytes()


def test_encrypted_backup_rejects_wrong_passphrase(tmp_path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.db.vsenc"
    source.write_bytes(b"data")
    encrypt_file(source, encrypted, "right")
    with pytest.raises(BackupCryptoError):
        decrypt_file(encrypted, tmp_path / "out.db", "wrong")


def test_unencrypted_file_is_not_detected(tmp_path):
    source = tmp_path / "plain.db"
    source.write_bytes(b"SQLite format 3\x00")
    assert not is_encrypted(source)
