"""Read and write the deployment environment file safely.

The Settings GUI stores database-backed preferences in SQLite, but the
launcher and service manager need a small number of values before Python
starts (listener address, TLS, data paths and optional tool paths).  Those
values are mirrored into ``VS_ENV_FILE`` (``.env`` by default).

Keeping the parser in one module avoids the Settings routes and startup
migration each growing their own subtly different implementation.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def is_env_entry(line: str, key: str) -> bool:
    """Return True when *line* defines *key* (including commented entries)."""
    stripped = line.strip()
    if stripped.startswith("#"):
        stripped = stripped[1:].lstrip()
    return stripped.startswith(key + "=")


def env_entries(path: Path) -> dict[str, str]:
    """Return the uncommented ``KEY=VALUE`` entries in *path*."""
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return entries
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key:
            entries[key] = value.strip()
    return entries


def write_env_file(path: Path, lines: list[str]) -> None:
    """Atomically replace *path* with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines).rstrip("\n") + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".env.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        os.replace(temp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def upsert_env_entries(path: Path, entries: dict[str, str]) -> None:
    """Add or replace ``KEY=VALUE`` entries while preserving other lines."""
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    for key, value in entries.items():
        entry = f"{key}={value}"
        new_lines: list[str] = []
        found = False
        for line in lines:
            if is_env_entry(line, key):
                if not found:
                    new_lines.append(entry)
                    found = True
                # Drop duplicate entries for the same key.
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(entry)
        lines = new_lines
    write_env_file(path, lines)


def remove_env_entries(path: Path, keys: set[str] | list[str]) -> list[str]:
    """Remove every entry for *keys* and return the removed key names.

    Both active and commented-out entries are removed so a plaintext legacy
    secret cannot be resurrected by uncommenting a line later.
    """
    if not path.exists():
        return []
    wanted = set(keys)
    removed: list[str] = []
    kept: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        matched = next(
            (key for key in wanted if is_env_entry(line, key)),
            None,
        )
        if matched:
            if matched not in removed:
                removed.append(matched)
            continue
        kept.append(line)
    if removed:
        write_env_file(path, kept)
    return removed


def env_safe(value: str, label: str) -> str:
    """Reject values that cannot be written to ``.env`` without quoting.

    The launchers source the file from POSIX shell or Windows ``cmd.exe``.
    Supporting arbitrary quoting in both shells is error-prone, so the GUI
    rejects whitespace, shell metacharacters and control characters instead.
    """
    unsafe = set("\r\n\x00;$\"`'|<>{}[]*!~#")
    if os.name != "nt":
        unsafe |= {" ", "\t", "\\", "&", "(", ")"}
    else:
        unsafe |= {"%", "^"}
    if any(char in value for char in unsafe):
        raise ValueError(f"{label} contains characters that are unsafe in .env")
    return value
