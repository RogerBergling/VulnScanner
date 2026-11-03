"""Notification test buttons and legacy password cleanup."""

from __future__ import annotations

import ssl

from app.database import get_setting, set_setting


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


def test_smtp_tls_verification_is_on_by_default(data_dir, monkeypatch):
    import app.scheduler as scheduler

    set_setting("smtp_host", "smtp.example.test")
    set_setting("smtp_port", "587")
    set_setting("smtp_user", "scanner@example.test")
    set_setting("smtp_password", "smtp-password")
    set_setting("smtp_from", "scanner@example.test")
    set_setting("smtp_insecure", "false")

    contexts: list[ssl.SSLContext] = []

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self, context=None):
            contexts.append(context)

        def login(self, *_args):
            pass

        def sendmail(self, *_args):
            pass

    monkeypatch.setattr(scheduler.smtplib, "SMTP", FakeSMTP)
    scheduler._send_email("soc@example.test", "subject", "body")
    assert contexts
    assert contexts[0].check_hostname is True
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED

    ssl_contexts: list[ssl.SSLContext] = []

    class FakeSMTPSSL(FakeSMTP):
        def __init__(self, *_args, context=None, **_kwargs):
            ssl_contexts.append(context)

    monkeypatch.setattr(scheduler.smtplib, "SMTP_SSL", FakeSMTPSSL)
    set_setting("smtp_port", "465")
    scheduler._send_email("soc@example.test", "subject", "body")
    assert ssl_contexts[-1].check_hostname is True
    assert ssl_contexts[-1].verify_mode == ssl.CERT_REQUIRED
    set_setting("smtp_port", "587")

    set_setting("smtp_insecure", "true")
    scheduler._send_email("soc@example.test", "subject", "body")
    assert contexts[-1].check_hostname is False
    assert contexts[-1].verify_mode == ssl.CERT_NONE


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
