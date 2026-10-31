"""Notification test buttons and legacy password cleanup."""

from __future__ import annotations

from app.database import get_setting


def test_notification_test_email_and_webhook(api_client, monkeypatch):
    import app.scheduler as scheduler

    sent: list[tuple[str, str, str]] = []

    def fake_email(to_address, subject, body):
        sent.append(("email", to_address, subject))

    def fake_webhook(url, payload):
        sent.append(("webhook", url, payload.get("event", "")))
        return 202

    monkeypatch.setattr(scheduler, "_send_email", fake_email)
    monkeypatch.setattr(scheduler, "_send_webhook", fake_webhook)

    email = api_client.post(
        "/api/settings/notifications/test",
        json={"channel": "email", "email": "soc@example.test"},
    )
    assert email.status_code == 200, email.text
    assert email.json()["channel"] == "email"

    webhook = api_client.post(
        "/api/settings/notifications/test",
        json={"channel": "webhook", "webhook": "https://hooks.example.test/vs"},
    )
    assert webhook.status_code == 200, webhook.text
    assert webhook.json()["status_code"] == 202
    assert [item[0] for item in sent] == ["email", "webhook"]


def test_legacy_plaintext_password_is_scrubbed(data_dir, monkeypatch, tmp_path):
    from app.security import migrate_env_admin_password

    env_file = tmp_path / "service.env"
    env_file.write_text(
        "VS_HOST=127.0.0.1\nVS_ADMIN_PASSWORD=legacy-password-123\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VS_ENV_FILE", str(env_file))
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "legacy-password-123")
    migrate_env_admin_password()

    assert get_setting("admin_password_hash", "").startswith("pbkdf2_sha256$")
    text = env_file.read_text(encoding="utf-8")
    assert "legacy-password-123" not in text
    assert "VS_HOST=127.0.0.1" in text
