"""Credential storage, API and resolution tests."""

from __future__ import annotations

from app.credentials import (
    decrypt_secret,
    resolve_for_scan,
    resolved_credential_for_target,
)
from app.database import get_db


def _create_credential(api_client, **overrides):
    payload = {
        "name": "Linux admin",
        "os": "linux",
        "username": "svc-vulnscan",
        "password": "s3cret-value",
        "auth_type": "password",
        "is_default": False,
    }
    payload.update(overrides)
    response = api_client.post("/api/credentials", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_credentials_are_encrypted_and_never_returned(api_client, data_dir):
    credential = _create_credential(api_client)
    assert credential["has_secret"] is True
    assert "password" not in credential
    assert "secret" not in credential
    assert "private_key" not in credential
    assert "passphrase" not in credential

    with get_db() as conn:
        row = conn.execute(
            "SELECT secret FROM credentials WHERE id = ?", (credential["id"],)
        ).fetchone()
    assert row["secret"] != "s3cret-value"
    assert decrypt_secret(row["secret"]) == "s3cret-value"

    listing = api_client.get("/api/credentials").json()
    assert len(listing) == 1
    assert "secret" not in listing[0]


def test_credentials_update_delete_and_validation(api_client):
    credential = _create_credential(api_client)
    updated = api_client.patch(
        f"/api/credentials/{credential['id']}",
        json={"password": "new-secret", "is_default": True},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["is_default"] is True
    assert "secret" not in updated.json()

    bad = api_client.post(
        "/api/credentials",
        json={"os": "windows", "username": "admin", "private_key": "key"},
    )
    assert bad.status_code == 400
    assert "password" in bad.json()["detail"].lower()

    missing = api_client.patch("/api/credentials/9999", json={"username": "x"})
    assert missing.status_code in {400, 404}

    deleted = api_client.delete(f"/api/credentials/{credential['id']}")
    assert deleted.status_code == 200
    assert api_client.get("/api/credentials").json() == []


def test_credential_scope_and_asset_binding(api_client, customer):
    group_id = customer["group_id"]
    asset = api_client.post(
        f"/api/groups/{group_id}/assets",
        json={"name": "web01", "kind": "host", "identifier": "192.0.2.10"},
    ).json()

    global_cred = _create_credential(api_client, name="Global Linux", is_default=True)
    customer_cred = _create_credential(
        api_client,
        name="Customer Linux",
        customer_id=customer["id"],
        is_default=True,
    )
    scoped = api_client.get(
        f"/api/credentials?customer_id={customer['id']}"
    ).json()
    assert {item["name"] for item in scoped} == {"Global Linux", "Customer Linux"}

    bound = api_client.put(
        f"/api/assets/{asset['id']}/credentials",
        json={"linux": customer_cred["id"]},
    )
    assert bound.status_code == 200, bound.text
    bindings = api_client.get(f"/api/assets/{asset['id']}/credentials").json()["bindings"]
    assert bindings["linux"]["id"] == customer_cred["id"]
    assert bindings["windows"] is None

    resolved = resolved_credential_for_target(None, customer["id"], asset["id"], "linux")
    assert resolved is not None
    assert resolved["name"] == "Customer Linux"
    assert resolved["secret"] == "s3cret-value"

    # Clearing the binding falls back to the customer default.
    cleared = api_client.put(
        f"/api/assets/{asset['id']}/credentials", json={"linux": None}
    )
    assert cleared.status_code == 200
    assert cleared.json()["bindings"]["linux"] is None
    assert resolved_credential_for_target(None, customer["id"], asset["id"], "linux")["name"] == "Customer Linux"

    mismatched = api_client.put(
        f"/api/assets/{asset['id']}/credentials", json={"windows": customer_cred["id"]}
    )
    assert mismatched.status_code == 400

    del global_cred


def test_scan_credentials_override_saved_and_reject_agent(api_client, customer):
    created = _create_credential(
        api_client,
        name="Saved Linux",
        customer_id=customer["id"],
        is_default=True,
    )
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "192.0.2.10",
            "options": {"profile": "web", "authenticated": True},
            "credentials": {
                "linux": {
                    "username": "scan-user",
                    "password": "scan-secret",
                    "account_type": "local",
                }
            },
        },
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["options"]["authenticated"] is True
    assert scan["credentials"] == [
        {
            "os": "linux",
            "username": "scan-user",
            "domain": "",
            "account_type": "",
            "auth_type": "password",
            "created_at": scan["credentials"][0]["created_at"],
        }
    ]
    assert "scan-secret" not in response.text

    resolved = resolve_for_scan(scan["id"], "linux")
    assert resolved["username"] == "scan-user"
    assert resolved["secret"] == "scan-secret"
    assert resolved["source"] == "scan"

    # Windows falls back to the saved customer default.
    assert resolve_for_scan(scan["id"], "windows") is None
    assert created["username"] == "svc-vulnscan"

    rejected = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "192.0.2.10",
            "agent_id": "missing-agent",
            "options": {"authenticated": True},
            "credentials": {
                "linux": {"username": "scan-user", "password": "scan-secret"}
            },
        },
    )
    assert rejected.status_code == 400
    assert "agent" in rejected.json()["detail"].lower()


def test_network_option_validation(api_client, customer):
    base = {
        "customer_id": customer["id"],
        "scan_type": "network",
        "target": "192.0.2.10",
    }
    created = api_client.post(
        "/api/scans",
        json={
            **base,
            "options": {
                "authenticated": True,
                "target_os": "windows",
                "max_auth_hosts": 5,
                "auth_timeout": 15,
                "max_web_hosts": 4,
                "ssh_port": 2222,
                "winrm_port": 5986,
                "winrm_https": True,
                "winrm_transport": "ntlm",
                "verify_tls": True,
                "web_checks": True,
            },
        },
    )
    assert created.status_code == 201, created.text
    options = created.json()["options"]
    assert options["target_os"] == "windows"
    assert options["max_auth_hosts"] == 5
    assert options["ssh_port"] == 2222
    assert options["winrm_port"] == 5986
    assert options["winrm_https"] is True
    assert options["verify_tls"] is True

    invalid = api_client.post(
        "/api/scans", json={**base, "options": {"target_os": "solaris"}}
    )
    assert invalid.status_code == 400
    invalid = api_client.post(
        "/api/scans", json={**base, "options": {"winrm_transport": "telnet"}}
    )
    assert invalid.status_code == 400
