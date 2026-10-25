"""Encrypted storage and resolution of authenticated-scan credentials.

Credentials are stored with Fernet (AES-128-CBC + HMAC) using a key that is
generated next to the SQLite database on first use. Set ``VS_CREDENTIAL_KEY``
to a Fernet key to supply the key externally (for example from a secret
manager). Secrets are never returned by the API or written to scan logs.

Resolution order for a network target:

1. a credential supplied for the scan job itself;
2. a credential bound to the scan's asset;
3. a customer-level default credential for that operating system;
4. a global default credential for that operating system.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from .config import data_dir
from .database import get_db, transaction, utcnow

OS_CHOICES = ("linux", "windows")
AUTH_TYPES = ("password", "key")
ACCOUNT_TYPES = ("local", "domain")

KEY_ENV = "VS_CREDENTIAL_KEY"
KEY_FILE = "credential.key"


class CredentialError(ValueError):
    """Raised for invalid credentials or a missing/incorrect encryption key."""


def _fernet_for_key(key: bytes):
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise CredentialError(
            "Credential storage needs the 'cryptography' package. "
            "Install the server requirements again."
        ) from exc
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise CredentialError(
            "VS_CREDENTIAL_KEY is not a valid Fernet key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from exc


def _key_path():
    return data_dir() / KEY_FILE


def _load_key() -> bytes:
    configured = os.getenv(KEY_ENV, "").strip()
    if configured:
        return configured.encode("ascii")
    path = _key_path()
    try:
        return path.read_bytes().strip()
    except FileNotFoundError:
        pass
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes().strip()
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


@lru_cache(maxsize=8)
def _fernet(key: bytes):
    return _fernet_for_key(key)


def _cipher():
    return _fernet(_load_key())


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        from cryptography.fernet import InvalidToken
    except ImportError as exc:  # pragma: no cover
        raise CredentialError("Install the 'cryptography' package to use stored credentials") from exc
    try:
        return _cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialError(
            "Could not decrypt a stored credential. The credential key changed or the "
            "data directory was copied without credential.key. Re-enter the credential."
        ) from exc


def _clean(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def normalize_os(value: str) -> str:
    text = _clean(value, 20).lower()
    if text not in OS_CHOICES:
        raise CredentialError("os must be 'linux' or 'windows'")
    return text


def _normalize_common(
    os_name: str,
    username: str,
    auth_type: str,
    domain: str,
    account_type: str,
) -> tuple[str, str, str, str]:
    username = _clean(username, 200)
    if not username:
        raise CredentialError("A username is required")
    auth_type = _clean(auth_type, 20).lower() or "password"
    if auth_type not in AUTH_TYPES:
        raise CredentialError("auth_type must be 'password' or 'key'")
    if os_name == "windows" and auth_type != "password":
        raise CredentialError("Windows WinRM credentials must use a password")
    domain = _clean(domain, 200)
    if os_name == "linux":
        domain = ""
        account_type = ""
    else:
        account_type = _clean(account_type, 20).lower() or ("domain" if domain else "local")
        if account_type not in ACCOUNT_TYPES:
            raise CredentialError("account_type must be 'local' or 'domain'")
        if account_type == "domain" and not domain and "\\" not in username and "@" not in username:
            raise CredentialError(
                "A domain account needs a domain (DOMAIN\\user or user@domain is also accepted)"
            )
    return username, auth_type, domain, account_type


def normalize_input(os_name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a per-scan credential body into a storable entry."""
    os_name = normalize_os(os_name)
    password = str(data.get("password") or "")
    private_key = str(data.get("private_key") or "")
    if password and private_key:
        raise CredentialError("Provide either a password or a private key, not both")
    passphrase = str(data.get("passphrase") or "")
    auth_type = _clean(data.get("auth_type"), 20).lower()
    if not auth_type:
        auth_type = "key" if private_key else "password"
    username, auth_type, domain, account_type = _normalize_common(
        os_name,
        str(data.get("username") or ""),
        auth_type,
        str(data.get("domain") or ""),
        str(data.get("account_type") or ""),
    )
    if auth_type == "key":
        if not private_key:
            raise CredentialError("A private key is required for key authentication")
        secret = private_key
    else:
        if not password:
            raise CredentialError("A password is required for password authentication")
        secret = password
    if len(secret) > 40_000:
        raise CredentialError("The credential secret is too large")
    return {
        "os": os_name,
        "username": username,
        "domain": domain,
        "account_type": account_type,
        "auth_type": auth_type,
        "secret": secret,
        "passphrase": passphrase[:4_000],
    }


def _public(row: dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data.pop("secret", None)
    data.pop("passphrase", None)
    data["has_secret"] = bool(row.get("secret"))
    data["has_passphrase"] = bool(row.get("passphrase"))
    data["is_default"] = bool(row.get("is_default"))
    return data


def _decrypted(row: dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["secret"] = decrypt_secret(str(row.get("secret") or ""))
    data["passphrase"] = decrypt_secret(str(row.get("passphrase") or ""))
    return data


def _asset_customer(conn, asset_id: int) -> int:
    row = conn.execute("SELECT customer_id FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        raise CredentialError("Asset not found")
    return int(row["customer_id"])


def create_credential(
    *,
    name: str,
    os_name: str,
    username: str,
    secret: str,
    auth_type: str = "password",
    domain: str = "",
    account_type: str = "",
    passphrase: str = "",
    customer_id: int | None = None,
    is_default: bool = False,
    asset_id: int | None = None,
) -> dict[str, Any]:
    os_name = normalize_os(os_name)
    name = _clean(name, 160) or f"{os_name} scan account"
    username, auth_type, domain, account_type = _normalize_common(
        os_name, username, auth_type, domain, account_type
    )
    secret = str(secret or "")
    if not secret:
        raise CredentialError("A password or private key is required")
    if len(secret) > 40_000:
        raise CredentialError("The credential secret is too large")
    if os_name == "windows" and auth_type != "password":
        raise CredentialError("Windows WinRM credentials must use a password")

    with transaction() as conn:
        if asset_id is not None:
            asset_customer = _asset_customer(conn, asset_id)
            if customer_id is not None and int(customer_id) != asset_customer:
                raise CredentialError("Asset does not belong to the selected customer")
            customer_id = asset_customer
            is_default = False
        now = utcnow()
        cursor = conn.execute(
            "INSERT INTO credentials("
            "customer_id, name, os, username, domain, account_type, auth_type, "
            "secret, passphrase, is_default, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                customer_id,
                name,
                os_name,
                username,
                domain,
                account_type,
                auth_type,
                encrypt_secret(secret),
                encrypt_secret(str(passphrase or "")),
                1 if is_default else 0,
                now,
                now,
            ),
        )
        credential_id = int(cursor.lastrowid)
        if is_default:
            conn.execute(
                "UPDATE credentials SET is_default = 0 WHERE os = ? AND id != ? "
                "AND ((customer_id IS NULL AND ? IS NULL) OR customer_id = ?)",
                (os_name, credential_id, customer_id, customer_id),
            )
        if asset_id is not None:
            conn.execute(
                "INSERT INTO asset_credential_bindings(asset_id, os, credential_id) "
                "VALUES (?, ?, ?) ON CONFLICT(asset_id, os) DO UPDATE SET credential_id = excluded.credential_id",
                (asset_id, os_name, credential_id),
            )
    row = get_credential(credential_id)
    if not row:
        raise CredentialError("Could not save the credential")
    return row


def get_credential(credential_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    return _public(dict(row)) if row else None


def list_credentials(customer_id: int | None = None, os_name: str | None = None) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []
    if customer_id is not None:
        where.append("(customer_id IS NULL OR customer_id = ?)")
        params.append(customer_id)
    if os_name:
        where.append("os = ?")
        params.append(normalize_os(os_name))
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM credentials" + clause + " ORDER BY os, name COLLATE NOCASE",
            tuple(params),
        ).fetchall()
    return [_public(dict(row)) for row in rows]


def update_credential(credential_id: int, **fields: Any) -> dict[str, Any]:
    current = _raw_credential(credential_id)
    if not current:
        raise CredentialError("Credential not found")
    os_name = normalize_os(fields.get("os_name") or current["os"])
    username, auth_type, domain, account_type = _normalize_common(
        os_name,
        fields.get("username", current["username"]),
        fields.get("auth_type", current["auth_type"]),
        fields.get("domain", current["domain"]),
        fields.get("account_type", current["account_type"]),
    )
    updates: dict[str, Any] = {
        "os": os_name,
        "username": username,
        "domain": domain,
        "account_type": account_type,
        "auth_type": auth_type,
        "updated_at": utcnow(),
    }
    if fields.get("name") is not None:
        name = _clean(fields["name"], 160)
        if not name:
            raise CredentialError("A credential name is required")
        updates["name"] = name
    if fields.get("secret") is not None:
        secret = str(fields["secret"])
        if not secret:
            raise CredentialError("A password or private key is required")
        if len(secret) > 40_000:
            raise CredentialError("The credential secret is too large")
        updates["secret"] = encrypt_secret(secret)
    if fields.get("passphrase") is not None:
        updates["passphrase"] = encrypt_secret(str(fields["passphrase"]))
    if fields.get("is_default") is not None:
        updates["is_default"] = 1 if fields["is_default"] else 0

    with transaction() as conn:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        conn.execute(
            f"UPDATE credentials SET {set_sql} WHERE id = ?",
            (*updates.values(), credential_id),
        )
        if updates.get("is_default"):
            conn.execute(
                "UPDATE credentials SET is_default = 0 WHERE os = ? AND id != ? "
                "AND ((customer_id IS NULL AND ? IS NULL) OR customer_id = ?)",
                (os_name, credential_id, current["customer_id"], current["customer_id"]),
            )
        if os_name != current["os"]:
            conn.execute(
                "DELETE FROM asset_credential_bindings WHERE credential_id = ? AND os != ?",
                (credential_id, os_name),
            )
    row = get_credential(credential_id)
    if not row:
        raise CredentialError("Credential not found")
    return row


def delete_credential(credential_id: int) -> None:
    with transaction() as conn:
        cursor = conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        if cursor.rowcount == 0:
            raise CredentialError("Credential not found")


def _raw_credential(credential_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    return dict(row) if row else None


def default_order() -> str:
    return " ORDER BY is_default DESC, updated_at DESC, id DESC LIMIT 1"


def resolve_credential(
    customer_id: int | None, asset_id: int | None, os_name: str
) -> dict[str, Any] | None:
    """Return the raw (encrypted) credential row for a target, or None."""
    os_name = normalize_os(os_name)
    with get_db() as conn:
        if asset_id:
            row = conn.execute(
                "SELECT c.* FROM asset_credential_bindings b "
                "JOIN credentials c ON c.id = b.credential_id "
                "WHERE b.asset_id = ? AND b.os = ? AND c.os = ?",
                (asset_id, os_name, os_name),
            ).fetchone()
            if row:
                return dict(row)
        if customer_id is not None:
            row = conn.execute(
                "SELECT * FROM credentials WHERE customer_id = ? AND os = ?" + default_order(),
                (customer_id, os_name),
            ).fetchone()
            if row:
                return dict(row)
        row = conn.execute(
            "SELECT * FROM credentials WHERE customer_id IS NULL AND os = ?" + default_order(),
            (os_name,),
        ).fetchone()
    return dict(row) if row else None


def set_asset_credential(asset_id: int, os_name: str, credential_id: int | None) -> None:
    os_name = normalize_os(os_name)
    with transaction() as conn:
        if not conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone():
            raise CredentialError("Asset not found")
        if credential_id is None:
            conn.execute(
                "DELETE FROM asset_credential_bindings WHERE asset_id = ? AND os = ?",
                (asset_id, os_name),
            )
            return
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (credential_id,)
        ).fetchone()
        if not row:
            raise CredentialError("Credential not found")
        if row["os"] != os_name:
            raise CredentialError("The credential operating system does not match the binding")
        conn.execute(
            "INSERT INTO asset_credential_bindings(asset_id, os, credential_id) VALUES (?, ?, ?) "
            "ON CONFLICT(asset_id, os) DO UPDATE SET credential_id = excluded.credential_id",
            (asset_id, os_name, credential_id),
        )


def asset_credential_bindings(asset_id: int) -> dict[str, dict[str, Any] | None]:
    result: dict[str, dict[str, Any] | None] = {"linux": None, "windows": None}
    with get_db() as conn:
        rows = conn.execute(
            "SELECT c.*, b.os AS bound_os FROM asset_credential_bindings b "
            "JOIN credentials c ON c.id = b.credential_id WHERE b.asset_id = ?",
            (asset_id,),
        ).fetchall()
    for row in rows:
        item = _public(dict(row))
        item.pop("bound_os", None)
        result[row["bound_os"]] = item
    return result


def store_scan_credentials(scan_id: int, entries: dict[str, dict[str, Any]]) -> None:
    """Persist per-scan overrides, encrypting every secret."""
    if not entries:
        return
    normalized: dict[str, dict[str, Any]] = {}
    for os_name, data in entries.items():
        normalized[normalize_os(os_name)] = normalize_input(os_name, data)
    with transaction() as conn:
        if not conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone():
            raise CredentialError("Scan not found")
        conn.execute("DELETE FROM scan_credentials WHERE scan_id = ?", (scan_id,))
        now = utcnow()
        for os_name, item in normalized.items():
            conn.execute(
                "INSERT INTO scan_credentials("
                "scan_id, os, username, domain, account_type, auth_type, secret, passphrase, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    os_name,
                    item["username"],
                    item["domain"],
                    item["account_type"],
                    item["auth_type"],
                    encrypt_secret(item["secret"]),
                    encrypt_secret(item["passphrase"]),
                    now,
                ),
            )


def scan_credentials_public(scan_id: int) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT os, username, domain, account_type, auth_type, created_at "
            "FROM scan_credentials WHERE scan_id = ? ORDER BY os",
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def copy_scan_credentials(source_scan_id: int, target_scan_id: int) -> None:
    with transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_credentials WHERE scan_id = ?", (source_scan_id,)
        ).fetchall()
        for row in rows:
            conn.execute(
                "INSERT OR REPLACE INTO scan_credentials("
                "scan_id, os, username, domain, account_type, auth_type, secret, passphrase, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_scan_id,
                    row["os"],
                    row["username"],
                    row["domain"],
                    row["account_type"],
                    row["auth_type"],
                    row["secret"],
                    row["passphrase"],
                    row["created_at"],
                ),
            )


def resolve_for_scan(scan_id: int, os_name: str) -> dict[str, Any] | None:
    """Resolve a decrypted credential for a scan, or None.

    The per-scan override wins. Otherwise the scan's asset binding, customer
    default and global default are consulted. Callers must never log the
    returned ``secret`` value.
    """
    os_name = normalize_os(os_name)
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_credentials WHERE scan_id = ? AND os = ?",
            (scan_id, os_name),
        ).fetchone()
        if row:
            data = _decrypted(dict(row))
            data["source"] = "scan"
            return data
        scan = conn.execute(
            "SELECT customer_id, asset_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if not scan:
        return None
    row = resolve_credential(scan["customer_id"], scan["asset_id"], os_name)
    if not row:
        return None
    data = _decrypted(row)
    data["source"] = "asset" if row.get("customer_id") and scan["asset_id"] else "saved"
    return data


def resolved_credential_for_target(
    scan_id: int,
    customer_id: int | None,
    asset_id: int | None,
    os_name: str,
) -> dict[str, Any] | None:
    """Resolve a decrypted credential for an explicit target context."""
    os_name = normalize_os(os_name)
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_credentials WHERE scan_id = ? AND os = ?",
            (scan_id, os_name),
        ).fetchone()
        if row:
            data = _decrypted(dict(row))
            data["source"] = "scan"
            return data
    row = resolve_credential(customer_id, asset_id, os_name)
    if not row:
        return None
    data = _decrypted(row)
    data["source"] = "saved"
    return data
