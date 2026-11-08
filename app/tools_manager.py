"""Optional external-tool acquisition and source selection.

Operators can choose, per tool, whether VulnScanner should:

* use a binary found on ``PATH`` (``system``),
* use an explicit path (``path``),
* install and update a managed release under ``VS_DATA_DIR/tools`` (``managed``),
* or disable the integration (``disabled``).

Managed downloads are checksum-verified against the release's checksum asset.
Tools that do not publish checksums are deliberately not eligible for managed
installation; use a package manager or an explicit path for those.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any, Callable

import requests

from .config import TOOL_ENV_VARS, data_dir
from .database import get_setting, set_setting, utcnow

USER_AGENT = "VulnScanner/1.0 (tool manager)"
GITHUB_API = "https://api.github.com"
INSTALL_LOCK = threading.Lock()

TOOL_CATALOG: dict[str, dict[str, Any]] = {
    "nuclei": {
        "label": "Nuclei",
        "repo": "projectdiscovery/nuclei",
        "binary": "nuclei",
        "asset_linux": r"nuclei_.*_linux_amd64\.zip$",
        "asset_windows": r"nuclei_.*_windows_amd64\.zip$",
        "checksum": r"checksums.*\.txt$",
    },
    "subfinder": {
        "label": "Subfinder",
        "repo": "projectdiscovery/subfinder",
        "binary": "subfinder",
        "asset_linux": r"subfinder_.*_linux_amd64\.zip$",
        "asset_windows": r"subfinder_.*_windows_amd64\.zip$",
        "checksum": r"checksums.*\.txt$",
    },
    "trivy": {
        "label": "Trivy",
        "repo": "aquasecurity/trivy",
        "binary": "trivy",
        "asset_linux": r"trivy_.*_Linux-64bit\.tar\.gz$",
        "asset_windows": r"trivy_.*_windows-64bit\.zip$",
        "checksum": r"checksums.*\.txt$",
    },
    "gitleaks": {
        "label": "Gitleaks",
        "repo": "gitleaks/gitleaks",
        "binary": "gitleaks",
        "asset_linux": r"gitleaks_.*_linux_x64\.tar\.gz$",
        "asset_windows": r"gitleaks_.*_windows_x64\.zip$",
        "checksum": r"checksums.*\.txt$",
    },
    "osv-scanner": {
        "label": "OSV-Scanner",
        "repo": "google/osv-scanner",
        "binary": "osv-scanner",
        "asset_linux": r"osv-scanner_linux_amd64$",
        "asset_windows": r"osv-scanner_windows_amd64\.exe$",
        "checksum": r"(checksums.*\.txt|.*SHA256SUMS)$",
    },
}

MANUAL_TOOLS = {
    "nmap": "Install with the operating-system package manager or set an explicit path.",
    "testssl": "Install from https://github.com/testssl/testssl.sh and set an explicit path.",
    "sqlmap": "Install from https://sqlmap.org (pre-installed on Kali) and set an explicit path.",
    "semgrep": "Install with pipx or a dedicated virtual environment and set an explicit path.",
    "gvm-cli": "Install the Greenbone/GVM client with your distribution package manager.",
    "git": "Install Git with the operating-system package manager.",
}


def _platform_key() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    machine = platform.machine().lower()
    if machine in {"aarch64", "arm64"}:
        # The catalog currently targets x86_64. Keep the mode available but
        # fail with a clear message rather than installing the wrong binary.
        return "linux-arm64"
    return "linux"


def _sources() -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(get_setting("tool_sources", "{}") or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _save_sources(sources: dict[str, dict[str, Any]]) -> None:
    set_setting("tool_sources", json.dumps(sources, separators=(",", ":")))


def tool_mode(name: str) -> str:
    source = _sources().get(name) or {}
    mode = str(source.get("mode") or "").strip().lower()
    if mode in {"system", "path", "managed", "disabled"}:
        return mode
    return "system"


def managed_root(name: str) -> Path:
    return data_dir() / "tools" / name


def configured_tool_path(name: str) -> str:
    return str((_sources().get(name) or {}).get("path") or "")


def managed_tool_path(name: str) -> str | None:
    root = managed_root(name)
    if not root.is_dir():
        return None
    binary = TOOL_CATALOG.get(name, {}).get("binary") or name
    candidates = sorted(root.rglob(binary), key=lambda path: path.stat().st_mtime, reverse=True)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def current_source(name: str) -> dict[str, Any]:
    source = dict(_sources().get(name) or {})
    mode = tool_mode(name)
    configured_path = str(source.get("path") or "")
    from .scanners.tools import tool_path as _tool_path

    resolved = _tool_path(name)
    return {
        "name": name,
        "mode": mode,
        "path": configured_path,
        "resolved_path": resolved or "",
        "managed_path": managed_tool_path(name) or "",
        "installed_version": str(source.get("version") or ""),
        "last_install": str(source.get("last_install") or ""),
        "last_error": str(source.get("last_error") or ""),
        "catalog": TOOL_CATALOG.get(name),
        "manual_help": MANUAL_TOOLS.get(name, ""),
    }


def set_tool_source(name: str, mode: str, path: str = "") -> dict[str, Any]:
    if name not in TOOL_ENV_VARS:
        raise ValueError("Unknown tool")
    mode = (mode or "").strip().lower()
    if mode not in {"system", "path", "managed", "disabled"}:
        raise ValueError("mode must be system, path, managed or disabled")
    if mode == "managed" and name not in TOOL_CATALOG:
        raise ValueError(f"{name} does not support managed installation; use system or path")
    if mode == "path":
        value = (path or "").strip()
        if not value:
            raise ValueError("A path is required for path mode")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise ValueError("Tool path must be absolute")
        path = str(candidate)
    sources = _sources()
    entry = dict(sources.get(name) or {})
    entry.update({"mode": mode, "path": path})
    sources[name] = entry
    _save_sources(sources)
    return current_source(name)


def _release(asset_repo: str, version: str = "") -> dict[str, Any]:
    url = (
        f"{GITHUB_API}/repos/{asset_repo}/releases/tags/{version}"
        if version
        else f"{GITHUB_API}/repos/{asset_repo}/releases/latest"
    )
    response = requests.get(
        url,
        timeout=30,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )
    if response.status_code == 404 and not version:
        raise RuntimeError(f"No release found for {asset_repo}")
    response.raise_for_status()
    return response.json()


def _download(url: str, destination: Path, max_bytes: int = 500 * 1024 * 1024) -> str:
    response = requests.get(
        url, timeout=120, stream=True, headers={"User-Agent": USER_AGENT}
    )
    response.raise_for_status()
    digest = hashlib.sha256()
    size = 0
    with destination.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=256 * 1024):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError("Download exceeded the size limit")
            digest.update(chunk)
            handle.write(chunk)
    return digest.hexdigest()


def _checksum_for_asset(checksum_url: str, asset_name: str) -> str:
    response = requests.get(
        checksum_url, timeout=60, headers={"User-Agent": USER_AGENT}
    )
    response.raise_for_status()
    for line in response.text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").endswith(asset_name):
            value = parts[0].strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", value):
                return value
    raise RuntimeError(f"No SHA-256 checksum found for {asset_name}")


def _extract_binary(archive: Path, name: str, destination: Path) -> Path:
    binary = TOOL_CATALOG[name]["binary"]
    destination.mkdir(parents=True, exist_ok=True)
    lower_name = archive.name.lower()
    if not lower_name.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
        # Some releases ship a bare binary (for example osv-scanner).
        target = destination / (f"{binary}.exe" if os.name == "nt" else binary)
        shutil.copy2(archive, target)
        return target
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.namelist():
                if Path(member).name == binary or Path(member).name == f"{binary}.exe":
                    target = destination / Path(member).name
                    with bundle.open(member) as source, target.open("wb") as handle:
                        shutil.copyfileobj(source, handle)
                    return target
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                if Path(member.name).name == binary or Path(member.name).name == f"{binary}.exe":
                    source = bundle.extractfile(member)
                    if source is None:
                        continue
                    target = destination / Path(member.name).name
                    with source, target.open("wb") as handle:
                        shutil.copyfileobj(source, handle)
                    return target
    raise RuntimeError(f"The release archive did not contain {binary}")


def install_tool(
    name: str,
    *,
    version: str = "",
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Download, verify and install a managed release for one tool."""
    if name not in TOOL_CATALOG:
        raise ValueError(f"{name} does not support managed installation")
    catalog = TOOL_CATALOG[name]
    platform_key = _platform_key()
    if platform_key not in {"linux", "windows"}:
        raise ValueError(
            f"Managed installation is not implemented for {platform_key}; use an explicit path"
        )
    pattern = catalog[f"asset_{platform_key}"]
    with INSTALL_LOCK:
        release = _release(catalog["repo"], version)
        assets = release.get("assets") or []
        asset = next(
            (item for item in assets if re.search(pattern, str(item.get("name") or ""))),
            None,
        )
        if not asset:
            raise RuntimeError(f"No release asset matched {pattern}")
        checksum_asset = next(
            (
                item
                for item in assets
                if re.search(str(catalog.get("checksum") or ""), str(item.get("name") or ""), re.I)
            ),
            None,
        )
        if not checksum_asset:
            raise RuntimeError(
                "This release does not publish a checksum file; managed installation "
                "is refused. Use the operating-system package manager or an explicit path."
            )
        version_tag = str(release.get("tag_name") or version or "latest").lstrip("v")
        if log:
            log(f"Downloading {name} {version_tag} ({asset['name']})")
        with tempfile.TemporaryDirectory(prefix=f"vulnscanner-{name}-") as temp:
            temp_dir = Path(temp)
            archive = temp_dir / str(asset["name"])
            actual = _download(str(asset["browser_download_url"]), archive)
            expected = _checksum_for_asset(
                str(checksum_asset["browser_download_url"]), str(asset["name"])
            )
            if actual.lower() != expected.lower():
                raise RuntimeError(
                    f"Checksum mismatch for {asset['name']}: expected {expected}, got {actual}"
                )
            if log:
                log(f"Checksum verified for {asset['name']}")
            destination = managed_root(name) / version_tag
            binary_path = _extract_binary(archive, name, destination)
            binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        sources = _sources()
        entry = dict(sources.get(name) or {})
        entry.update(
            {
                "mode": "managed",
                "version": version_tag,
                "last_install": utcnow(),
                "last_error": "",
            }
        )
        sources[name] = entry
        _save_sources(sources)
        if log:
            log(f"Installed {name} {version_tag} at {binary_path}")
        return current_source(name)


def install_tool_background(
    name: str, *, version: str = "", log: Callable[[str], None] | None = None
) -> dict[str, Any]:
    if name not in TOOL_CATALOG:
        raise ValueError(f"{name} does not support managed installation")

    def _run() -> None:
        try:
            install_tool(name, version=version, log=log)
        except Exception as exc:
            sources = _sources()
            entry = dict(sources.get(name) or {})
            entry["last_error"] = str(exc)[:1000]
            sources[name] = entry
            _save_sources(sources)
            if log:
                log(f"Installation failed: {exc}")

    thread = threading.Thread(
        target=_run, name=f"tool-install-{name}", daemon=True
    )
    thread.start()
    return {"started": True, "name": name}


def catalog() -> list[dict[str, Any]]:
    names = list(TOOL_CATALOG) + [name for name in MANUAL_TOOLS if name not in TOOL_CATALOG]
    return [current_source(name) for name in names]
