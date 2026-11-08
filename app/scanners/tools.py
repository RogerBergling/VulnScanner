"""Safe wrappers around optional command-line security tools."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..config import TOOL_PATHS

# External tools need a normal process environment, but not the application's
# secrets. These keys are sufficient for PATH lookup, temporary files, locale,
# proxy/CA configuration and Windows tool execution.
SAFE_ENV_KEYS = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "TERM",
    "NO_COLOR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
}


def safe_tool_env(extra: dict[str, Any] | None = None) -> dict[str, str]:
    """Return a minimal environment for an external scanner subprocess.

    The server process may contain ``VS_CREDENTIAL_KEY``, SMTP passwords or
    other secrets. External tools must not inherit them by default.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in SAFE_ENV_KEYS
    }
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return env

TOOL_NAMES = (
    "nmap",
    "nuclei",
    "testssl",
    "trivy",
    "subfinder",
    "osv-scanner",
    "gitleaks",
    "semgrep",
    "sqlmap",
    "gvm-cli",
    "git",
)
# Commands that may be installed under a different name than the integration.
TOOL_COMMANDS = {
    "testssl": ("testssl.sh", "testssl"),
    "gvm-cli": ("gvm-cli", "omp"),
}
VERSION_ARGS = {
    "nuclei": ("-version",),
    "subfinder": ("-version",),
    "testssl": ("--version",),
    "sqlmap": ("--version",),
    "gvm-cli": ("--version",),
}


def tool_path(name: str) -> str | None:
    try:
        from ..tools_manager import configured_tool_path, managed_tool_path, tool_mode

        mode = tool_mode(name)
        if mode == "disabled":
            return None
        if mode == "managed":
            return managed_tool_path(name)
        if mode == "path":
            configured = configured_tool_path(name) or (TOOL_PATHS.get(name) or "").strip()
            path = Path(configured).expanduser() if configured else None
            return str(path) if path and path.is_file() else None
    except Exception:
        # Tool management is optional; fall back to the historical PATH
        # resolution if its state cannot be read.
        pass
    configured = (TOOL_PATHS.get(name) or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path)
    for command in TOOL_COMMANDS.get(name, (name,)):
        found = shutil.which(command)
        if found:
            return found
    return None


def tool_status() -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name in TOOL_NAMES:
        path = tool_path(name)
        entry: dict[str, Any] = {"available": bool(path), "path": path or "", "version": ""}
        if path:
            try:
                proc = subprocess.run(
                    [path, *VERSION_ARGS.get(name, ("--version",))],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                output = (proc.stdout or proc.stderr or "").strip().splitlines()
                entry["version"] = output[0][:200] if output else ""
                # Some tools return a non-zero code for --version but still
                # print a usable version.
                returncode = getattr(proc, "returncode", 0)
                entry["available"] = returncode == 0 or bool(entry["version"])
            except (OSError, subprocess.SubprocessError):
                entry["available"] = False
        results[name] = entry
    return results


def run_tool(
    args: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        env=safe_tool_env(env),
        check=False,
    )
