from datetime import datetime, timedelta, timezone

from app.agents import enroll_agent, public_agent
from app.database import get_db, utcnow
from app.security import (
    authenticate_agent,
    constant_time_equal,
    consume_enrollment_token,
    create_enrollment_token,
    hash_token,
    new_agent_token,
    new_enrollment_token,
    token_hint,
)


def _customer_and_group():
    with get_db() as conn:
        customer_id = conn.execute(
            "INSERT INTO customers(name, description, created_at) VALUES ('Acme', '', ?)",
            (utcnow(),),
        ).lastrowid
        group_id = conn.execute(
            "INSERT INTO asset_groups(customer_id, name, description, created_at) VALUES (?, 'General', '', ?)",
            (customer_id, utcnow()),
        ).lastrowid
        conn.commit()
    return customer_id, group_id


def test_token_generation_and_hash():
    agent_token = new_agent_token()
    enrollment = new_enrollment_token()
    assert agent_token.startswith("vs_agent_")
    assert enrollment.startswith("vs_enroll_")
    assert hash_token(agent_token) == hash_token(agent_token)
    assert hash_token(agent_token) != agent_token
    assert len(hash_token(agent_token)) == 64
    assert token_hint(agent_token).endswith("…")
    assert constant_time_equal("abc", "abc")
    assert not constant_time_equal("abc", "abd")


def test_enrollment_token_is_single_use(data_dir):
    customer_id, group_id = _customer_and_group()
    token, meta = create_enrollment_token(customer_id, group_id, "web01", 1)
    assert meta["prefix"].endswith("…")
    consumed = consume_enrollment_token(token)
    assert consumed["customer_id"] == customer_id
    assert consumed["agent_name"] == "web01"
    assert consume_enrollment_token(token) is None
    with get_db() as conn:
        row = conn.execute(
            "SELECT used_at FROM enrollment_tokens WHERE id = ?", (meta["id"],)
        ).fetchone()
    assert row["used_at"]


def test_expired_enrollment_token_is_rejected(data_dir):
    customer_id, group_id = _customer_and_group()
    token, meta = create_enrollment_token(customer_id, group_id, hours=1)
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE enrollment_tokens SET expires_at = ? WHERE id = ?", (expired, meta["id"])
        )
        conn.commit()
    assert consume_enrollment_token(token) is None


def test_enroll_agent_creates_asset_agent_and_unique_name(data_dir):
    customer_id, group_id = _customer_and_group()
    token, _meta = create_enrollment_token(customer_id, group_id, "web01")
    result = enroll_agent(token, "", "Linux", "1.0.0", "web01", ["system"], "127.0.0.1")
    assert result["name"] == "web01"
    assert result["customer_id"] == customer_id
    assert authenticate_agent(result["token"])["id"] == result["agent_id"]

    second_token, _ = create_enrollment_token(customer_id, group_id, "web01")
    second = enroll_agent(second_token, "", "Linux", "1.0.0", "web01", [], "127.0.0.1")
    assert second["name"] == "web01 (2)"

    with get_db() as conn:
        assets = conn.execute(
            "SELECT * FROM assets WHERE kind = 'agent' AND group_id = ?", (group_id,)
        ).fetchall()
        agent_row = conn.execute(
            "SELECT * FROM agents WHERE id = ?", (result["agent_id"],)
        ).fetchone()
    assert len(assets) == 2
    public = public_agent(dict(agent_row))
    assert "token_hash" not in public
    assert public["online"] is True
    assert public["capabilities"] == ["system"]


def test_invalid_enrollment_token_raises(data_dir):
    try:
        enroll_agent("vs_enroll_invalid", "x", "Linux", "", "", [], "")
    except ValueError as exc:
        assert "invalid" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError")


def test_revoked_agent_cannot_authenticate(data_dir):
    customer_id, group_id = _customer_and_group()
    token, _meta = create_enrollment_token(customer_id, group_id, "web01")
    result = enroll_agent(token, "", "Linux", "", "", [], "")
    with get_db() as conn:
        conn.execute("UPDATE agents SET status = 'revoked' WHERE id = ?", (result["agent_id"],))
        conn.commit()
    assert authenticate_agent(result["token"]) is None
    assert authenticate_agent(None) is None
