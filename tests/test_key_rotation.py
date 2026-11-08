"""Tests for credential encryption key rotation."""

from app.credentials import (
    create_credential,
    decrypt_secret,
    rotate_credential_key,
)
from app.database import get_db


def test_rotate_credential_key_reencrypts_credentials(data_dir):
    credential = create_credential(
        name="Linux admin",
        os_name="linux",
        username="svc",
        secret="super-secret",
    )
    result = rotate_credential_key()
    assert result["ok"] is True
    with get_db() as conn:
        row = conn.execute(
            "SELECT secret FROM credentials WHERE id = ?", (credential["id"],)
        ).fetchone()
    assert row is not None
    assert decrypt_secret(row["secret"]) == "super-secret"
    # The old key is kept for rollback/forensics.
    assert (data_dir / "credential.key.old").is_file()
