"""Safe wrappers around optional command-line security tools."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..config import TOOL_PATHS

TOOL_NAMES = (
    "nmap",
    "nuclei",
    "testssl",
    "trivy",
    "subfinder",
    "osv-scanner",
    "gitleaks",
    "semgrep",
    "git",
)
# Commands that may be installed under a different name than the integration.
TOOL_COMMANDS = {
    "testssl": ("testssl.sh", "testssl"),
}
VERSION_ARGS = {
    "nuclei": ("-version",),
    "subfinder": ("-version",),
    "testssl": ("--version",),
}


def tool_path(name: str) -> str | None:
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
        env=env,
        check=False,
    )
