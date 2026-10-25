from app.database import (
    ensure_default_group,
    get_db,
    get_setting,
    json_dump,
    json_load,
    log_event,
    set_setting,
    update_scan,
    utcnow,
)


def test_database_is_initialized_with_defaults(data_dir):
    with get_db() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert {
        "customers",
        "asset_groups",
        "assets",
        "agents",
        "enrollment_tokens",
        "scans",
        "scan_events",
        "findings",
        "agent_jobs",
        "settings",
        "osv_cache",
        "kev_catalog",
    }.issubset(tables)
    assert version == 1
    assert get_setting("product_name") == "VulnScanner"
    assert get_setting("missing", "fallback") == "fallback"


def test_settings_upsert(data_dir):
    set_setting("nuclei_enabled", "false")
    assert get_setting("nuclei_enabled") == "false"
    set_setting("nuclei_enabled", "true")
    assert get_setting("nuclei_enabled") == "true"


def test_json_helpers():
    assert json_load(None, {}) == {}
    assert json_load("not json", []) == []
    assert json_load('{"a":1}', {}) == {"a": 1}
    assert json_dump({"a": 1}) == '{"a":1}'


def test_default_group_is_created_once(data_dir):
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO customers(name, description, created_at) VALUES ('Acme', '', ?)",
            (utcnow(),),
        )
        customer_id = cursor.lastrowid
        conn.commit()
    first = ensure_default_group(customer_id)
    second = ensure_default_group(customer_id)
    assert first == second
    with get_db() as conn:
        row = conn.execute(
            "SELECT name FROM asset_groups WHERE id = ?", (first,)
        ).fetchone()
    assert row["name"] == "General"


def test_scan_updates_and_event_logging(data_dir):
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO customers(name, description, created_at) VALUES ('Acme', '', ?)",
            (utcnow(),),
        )
        customer_id = cursor.lastrowid
        scan_id = conn.execute(
            "INSERT INTO scans(customer_id, scan_type, target, created_at) VALUES (?, 'web', ?, ?)",
            (customer_id, "https://example.test", utcnow()),
        ).lastrowid
        conn.commit()
    update_scan(scan_id, status="running", progress=40, stage="Testing", summary={"high": 2})
    update_scan(scan_id, unknown_field="ignored")
    log_event(scan_id, "hello", "warning")
    with get_db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        event = conn.execute("SELECT * FROM scan_events WHERE scan_id = ?", (scan_id,)).fetchone()
    assert scan["status"] == "running"
    assert scan["progress"] == 40
    assert json_load(scan["summary"], {}) == {"high": 2}
    assert event["level"] == "warning"
    assert event["message"] == "hello"
