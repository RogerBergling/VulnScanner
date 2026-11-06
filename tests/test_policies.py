"""Tests for scan policies."""

import pytest

from app.policies import (
    BUILTIN_POLICIES,
    create_policy,
    delete_policy,
    get_policy,
    list_policies,
    merge_policy_options,
    resolve_policy,
    seed_builtin_policies,
    set_default_policy,
    update_policy,
)


def test_builtin_policies_seed(data_dir):
    seeded = seed_builtin_policies()
    policies = list_policies()
    names = {policy["name"] for policy in policies}
    assert seeded >= 0
    assert {"Discovery", "Basic network scan", "Web application", "PCI-DSS", "OWASP Top 10"} <= names
    builtins = [policy for policy in policies if policy["builtin"]]
    assert len(builtins) == len(BUILTIN_POLICIES)


def test_builtin_policies_are_seeded_once(data_dir):
    seed_builtin_policies()
    assert seed_builtin_policies() == 0


def test_policy_crud(data_dir):
    policy = create_policy(
        "DMZ basic", "network", {"profile": "common", "nuclei": False}, "DMZ preset"
    )
    assert policy["builtin"] is False
    assert policy["options"]["nuclei"] is False
    fetched = get_policy(policy["id"])
    assert fetched["name"] == "DMZ basic"

    updated = update_policy(policy["id"], options={"profile": "top1000"})
    assert updated["options"] == {"profile": "top1000"}
    updated = update_policy(policy["id"], name="DMZ fast", description="faster")
    assert updated["name"] == "DMZ fast"
    assert updated["description"] == "faster"

    assert delete_policy(policy["id"]) is True
    assert get_policy(policy["id"]) is None
    assert delete_policy(policy["id"]) is False


def test_duplicate_policy_name_rejected(data_dir):
    create_policy("unique-name", "network", {})
    with pytest.raises(ValueError):
        create_policy("unique-name", "network", {})


def test_builtin_policy_is_read_only(data_dir):
    builtin = next(policy for policy in list_policies() if policy["builtin"])
    with pytest.raises(ValueError):
        update_policy(builtin["id"], name="Hacked")
    with pytest.raises(ValueError):
        delete_policy(builtin["id"])


def test_merge_policy_options():
    merged = merge_policy_options({"nuclei": False, "profile": "common"}, {"nuclei": True})
    assert merged == {"nuclei": True, "profile": "common"}


def test_resolve_policy_applies_and_overrides(data_dir):
    policy = create_policy("resolve-test", "network", {"nuclei": False, "profile": "common"})
    resolved = resolve_policy(policy["id"], "network", {"nuclei": True})
    assert resolved["nuclei"] is True  # scan wins
    assert resolved["profile"] == "common"  # policy applied
    assert resolved["policy_id"] == policy["id"]
    assert resolved["policy_name"] == "resolve-test"


def test_resolve_policy_type_mismatch(data_dir):
    policy = create_policy("web-only", "web", {})
    with pytest.raises(ValueError):
        resolve_policy(policy["id"], "network", {})


def test_resolve_policy_missing(data_dir):
    with pytest.raises(ValueError):
        resolve_policy(99999, "network", {})


def test_resolve_no_policy_returns_options(data_dir):
    assert resolve_policy(None, "network", {"nuclei": True}) == {"nuclei": True}


def test_default_policy_setting(data_dir):
    policy = create_policy("default-test", "network", {})
    set_default_policy(policy["id"])
    from app.policies import default_policy_id

    assert default_policy_id() == policy["id"]
    set_default_policy(None)
    assert default_policy_id() is None


def test_policies_api(api_client, customer):
    created = api_client.post(
        "/api/policies",
        json={"name": "api policy", "scan_type": "network", "options": {"nuclei": False}},
    )
    assert created.status_code == 201, created.text
    policy = created.json()
    assert policy["options"]["nuclei"] is False

    listed = api_client.get("/api/policies")
    assert listed.status_code == 200
    assert any(item["id"] == policy["id"] for item in listed.json())

    updated = api_client.put(
        f"/api/policies/{policy['id']}", json={"options": {"profile": "web"}}
    )
    assert updated.status_code == 200
    assert updated.json()["options"] == {"profile": "web"}

    default = api_client.post("/api/policies/default", json={"policy_id": policy["id"]})
    assert default.status_code == 200
    assert default.json()["default_policy_id"] == policy["id"]
    assert api_client.get("/api/meta").json()["default_scan_policy"] == policy["id"]

    cleared = api_client.post("/api/policies/default", json={"policy_id": None})
    assert cleared.status_code == 200
    assert cleared.json()["default_policy_id"] is None

    removed = api_client.delete(f"/api/policies/{policy['id']}")
    assert removed.status_code == 200
    assert api_client.delete(f"/api/policies/{policy['id']}").status_code == 404


def test_scan_applies_policy(api_client, customer):
    policy = api_client.post(
        "/api/policies",
        json={"name": "scan-apply", "scan_type": "network", "options": {"nuclei": False}},
    ).json()
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "192.0.2.10",
            "policy_id": policy["id"],
            "options": {"service_probes": True},
        },
    )
    assert created.status_code == 201, created.text
    scan = created.json()
    options = scan.get("options") or {}
    assert options.get("nuclei") is False  # from policy
    assert options.get("service_probes") is True  # explicit option
    assert options.get("policy_id") == policy["id"]


def test_scan_rejects_policy_type_mismatch(api_client, customer):
    policy = api_client.post(
        "/api/policies", json={"name": "web-policy", "scan_type": "web", "options": {}}
    ).json()
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "192.0.2.10",
            "policy_id": policy["id"],
        },
    )
    assert created.status_code == 400
