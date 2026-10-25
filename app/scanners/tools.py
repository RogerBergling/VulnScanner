"""Safe wrappers around optional command-line security tools."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..config import TOOL_PATHS


def tool_path(name: str) -> str | None:
    configured = (TOOL_PATHS.get(name) or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path)
    return shutil.which(name)


def tool_status() -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name in ("nmap", "nuclei", "osv-scanner", "gitleaks", "semgrep", "git"):
        path = tool_path(name)
        entry: dict[str, Any] = {"available": bool(path), "path": path or "", "version": ""}
        if path:
            try:
                proc = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                output = (proc.stdout or proc.stderr or "").strip().splitlines()
                entry["version"] = output[0][:200] if output else ""
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
