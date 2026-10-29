"""Repository, source-code and GitHub scanning."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse

from ..config import MAX_REPO_BYTES, clone_dir, get_limit
from ..utils import normalize_repo_target, redact_url, truncate
from .base import ScanContext, ScanResult
from .dependencies import scan_dependencies
from .secrets import scan_secrets
from .source import scan_source
from .tools import run_tool, tool_path
from .trivy import scan_trivy


def _directory_size(path: Path) -> int:
    limit = get_limit("max_repo_bytes", MAX_REPO_BYTES)
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
            if total > limit * 2:
                return total
    return total


def _remove_tree(path: Path) -> None:
    def on_error(func, target, _exc):
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=on_error)


def _clone_github(ctx: ScanContext, target: str, token: str | None = None) -> Path:
    git = tool_path("git")
    if not git:
        raise RuntimeError("Git is required to scan GitHub repositories but was not found")
    parsed = urlparse(target)
    if parsed.scheme != "https":
        raise ValueError("GitHub scans require an https:// repository URL")
    destination = clone_dir() / f"scan-{ctx.scan_id}-{uuid.uuid4().hex[:8]}"
    command = [git, "clone", "--no-tags"]
    if not ctx.option_bool("git_history", False):
        command.extend(["--depth", "1", "--single-branch"])
    command.extend([target, str(destination)])
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    if token:
        encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
        env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {encoded}"
    ctx.log(f"Cloning {redact_url(target)} (shallow={not ctx.option_bool('git_history', False)})")
    try:
        proc = run_tool(command, timeout=300, env=env)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Repository clone timed out after 5 minutes") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "unknown git error").strip()
        message = message.replace(token, "***") if token else message
        raise RuntimeError(f"Git clone failed: {truncate(message, 800)}")
    size = _directory_size(destination)
    limit = get_limit("max_repo_bytes", MAX_REPO_BYTES)
    ctx.log(f"Repository cloned ({size / (1024 * 1024):.1f} MiB)")
    if size > limit:
        _remove_tree(destination)
        raise RuntimeError(
            f"Repository is larger than the configured limit ({limit // (1024 * 1024)} MiB)"
        )
    return destination


def _merge_metadata(result: ScanResult, part: ScanResult, prefix: str) -> None:
    for key, value in part.metadata.items():
        result.metadata[f"{prefix}_{key}"] = value


def scan_repository(ctx: ScanContext, target: str, token: str | None = None) -> ScanResult:
    result = ScanResult()
    temporary = False
    root: Path
    normalized = normalize_repo_target(target)
    if normalized.startswith(("http://", "https://")):
        root = _clone_github(ctx, normalized, token)
        temporary = True
        result.metadata["repository"] = redact_url(normalized)
    else:
        root = Path(normalized)
        result.metadata["repository"] = str(root)
    try:
        ctx.progress(8, "Repository ready")
        include_secrets = ctx.option_bool("include_secrets", True)
        include_dependencies = ctx.option_bool("include_dependencies", True)
        include_source = ctx.option_bool("include_source", True)
        if include_secrets:
            ctx.progress(15, "Scanning for secrets")
            secrets = scan_secrets(ctx, root)
            result.findings.extend(secrets.findings)
            _merge_metadata(result, secrets, "secrets")
        if include_dependencies:
            ctx.progress(42, "Analyzing dependencies")
            dependencies = scan_dependencies(ctx, root)
            result.findings.extend(dependencies.findings)
            _merge_metadata(result, dependencies, "dependencies")
        if include_source:
            ctx.progress(72, "Reviewing source code")
            source = scan_source(ctx, root)
            result.findings.extend(source.findings)
            _merge_metadata(result, source, "source")
        ctx.progress(86, "Running Trivy (optional)")
        try:
            result.metadata["trivy_findings"] = scan_trivy(ctx, root, result)
        except Exception as exc:
            ctx.log(f"Trivy integration failed: {exc}", "warning")
            result.metadata["trivy_findings"] = 0
        result.metadata["options"] = {
            "secrets": include_secrets,
            "dependencies": include_dependencies,
            "source": include_source,
            "git_history": ctx.option_bool("git_history", False),
            "external_tools": ctx.option_bool("external_tools", False),
            "trivy": ctx.option_bool("trivy", False),
        }
        ctx.progress(96, "Finalizing repository results")
        return result
    finally:
        if temporary:
            ctx.log("Removing temporary repository clone")
            _remove_tree(root)
