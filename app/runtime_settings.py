"""Mirror database-backed runtime settings into the launcher environment file.

The database is authoritative.  The environment file remains the interface used
by ``run.sh``/``run.bat`` and service managers, so it is refreshed after a
settings restore and when deployment-level values change.
"""

from __future__ import annotations

import os

from .config import (
    BASE_DIR,
    HOST,
    PORT,
    TOOL_ENV_VARS,
    TOOL_PATHS,
    env_file_path,
)
from .database import get_setting, get_setting_optional
from .envfile import upsert_env_entries


def active_ssl() -> bool:
    return os.getenv("VS_SSL", "true").strip().lower() in {"1", "true", "yes", "on"}


def sync_env_from_settings() -> None:
    bind_host = get_setting("bind_host", os.getenv("VS_HOST", HOST))
    bind_port = get_setting("bind_port", os.getenv("VS_PORT", str(PORT)))
    ssl_setting = get_setting("ssl_enabled", "true" if active_ssl() else "false")
    ssl_text = (
        "true"
        if ssl_setting.strip().lower() in {"1", "true", "yes", "on"}
        else "false"
    )
    entries = {
        "VS_HOST": bind_host,
        "VS_PORT": str(bind_port),
        "VS_SSL": ssl_text,
        "VS_ADMIN_USER": get_setting(
            "admin_user", os.getenv("VS_ADMIN_USER", "admin")
        ),
        "VS_ADMIN_PASSWORD": "",
    }

    if get_setting_optional("tool_paths") is None:
        for name, env_name in TOOL_ENV_VARS.items():
            entries[env_name] = ""
            TOOL_PATHS[name] = ""
            os.environ.pop(env_name, None)
    else:
        for name, env_name in TOOL_ENV_VARS.items():
            entries[env_name] = TOOL_PATHS.get(name, "")

    upsert_env_entries(env_file_path(BASE_DIR), entries)
    os.environ["VS_HOST"] = bind_host
    os.environ["VS_PORT"] = str(bind_port)
    os.environ["VS_SSL"] = ssl_text
    os.environ["VS_ADMIN_USER"] = entries["VS_ADMIN_USER"]
    os.environ.pop("VS_ADMIN_PASSWORD", None)
