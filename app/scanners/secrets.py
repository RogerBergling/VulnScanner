"""Secret detection for repositories and agent-selected paths."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from ..config import MAX_SCAN_FILES, get_limit
from ..utils import redact_secret, truncate
from .base import Finding, ScanContext, ScanResult
from .filesystem import iter_files, read_text_file, relative_path
from .tools import run_tool, tool_path

SKIP_SECRET_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "composer.lock", "Gemfile.lock", "Pipfile.lock",
}
PLACEHOLDER_RE = re.compile(
    r"^(?:x+|\*+|\.+|your[-_ ]|example|sample|changeme|change[-_ ]?me|placeholder|"
    r"replace[-_ ]?me|dummy|test(?:ing)?|none|null|true|false|redacted|secret|password|"
    r"insert[-_ ]|todo|fixme|env\(|process\.env|\$\{|<|\{\{|%\().*",
    re.I,
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


SECRET_RULES: list[dict[str, Any]] = [
    {
        "id": "private-key",
        "title": "Private key committed to source",
        "severity": "critical",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "description": "A private key is stored in the repository. Anyone with repository access can impersonate the key owner.",
        "remediation": "Revoke and rotate the key, remove it from git history, and store keys in a secrets manager.",
        "cwe": "CWE-321",
    },
    {
        "id": "aws-access-key",
        "title": "AWS access key ID detected",
        "severity": "critical",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "description": "An AWS access key ID is present in source code or configuration.",
        "remediation": "Disable the key in IAM, rotate credentials, purge git history and use short-lived roles/credentials.",
        "cwe": "CWE-798",
    },
    {
        "id": "aws-secret-key",
        "title": "AWS secret access key detected",
        "severity": "critical",
        "pattern": re.compile(
            r"(?i)(?:aws_?secret_?access_?key|aws_?secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "group": 1,
        "description": "An AWS secret access key appears to be hard-coded.",
        "remediation": "Rotate the key immediately and move credentials to IAM roles or a secrets manager.",
        "cwe": "CWE-798",
    },
    {
        "id": "github-token",
        "title": "GitHub token detected",
        "severity": "high",
        "pattern": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
        "description": "A GitHub personal access token or app token is committed.",
        "remediation": "Revoke the token in GitHub, rotate it, and use short-lived GitHub App tokens.",
        "cwe": "CWE-798",
    },
    {
        "id": "gitlab-token",
        "title": "GitLab token detected",
        "severity": "high",
        "pattern": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "description": "A GitLab personal access token is committed.",
        "remediation": "Revoke the token in GitLab and store replacements outside the repository.",
        "cwe": "CWE-798",
    },
    {
        "id": "slack-token",
        "title": "Slack token detected",
        "severity": "high",
        "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "description": "A Slack API token is committed.",
        "remediation": "Revoke and rotate the Slack token.",
        "cwe": "CWE-798",
    },
    {
        "id": "stripe-live-key",
        "title": "Stripe live secret key detected",
        "severity": "critical",
        "pattern": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
        "description": "A live Stripe secret key is present in the repository and can move real money.",
        "remediation": "Roll the key in the Stripe dashboard immediately and review recent API activity.",
        "cwe": "CWE-798",
    },
    {
        "id": "google-api-key",
        "title": "Google API key detected",
        "severity": "high",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "description": "A Google API key is hard-coded.",
        "remediation": "Restrict or rotate the API key in Google Cloud and use workload identity where possible.",
        "cwe": "CWE-798",
    },
    {
        "id": "npm-token",
        "title": "npm access token detected",
        "severity": "high",
        "pattern": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "description": "An npm access token is committed.",
        "remediation": "Revoke the token in npm and rotate it.",
        "cwe": "CWE-798",
    },
    {
        "id": "sendgrid-key",
        "title": "SendGrid API key detected",
        "severity": "high",
        "pattern": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        "description": "A SendGrid API key is committed.",
        "remediation": "Revoke and rotate the API key.",
        "cwe": "CWE-798",
    },
    {
        "id": "openai-key",
        "title": "OpenAI API key detected",
        "severity": "high",
        "pattern": re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b"),
        "description": "An OpenAI/Anthropic-style API key is committed.",
        "remediation": "Revoke and rotate the API key and review usage.",
        "cwe": "CWE-798",
    },
    {
        "id": "database-url",
        "title": "Database connection string with password",
        "severity": "high",
        "pattern": re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/@]+:[^@\s/]+@[^\s'\"]+",
            re.I,
        ),
        "description": "A connection URI containing an embedded password was found.",
        "remediation": "Rotate the database password and read credentials from environment variables or a secrets manager.",
        "cwe": "CWE-798",
    },
]

GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\n]{12,160})['\"]"
)


def _looks_placeholder(value: str) -> bool:
    value = value.strip()
    if len(value) < 12:
        return True
    if PLACEHOLDER_RE.match(value):
        return True
    if re.fullmatch(r"[\d\W_]+", value):
        return True
    if len(set(value)) < 6:
        return True
    return False


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(
    text: str,
    display_path: str,
    result: ScanResult,
    max_findings: int = 500,
) -> int:
    added = 0
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()
    for line_index, line in enumerate(lines, start=1):
        if len(line) > 4000:
            line = line[:4000]
        for rule in SECRET_RULES:
            for match in rule["pattern"].finditer(line):
                group = rule.get("group", 0)
                value = match.group(group) if match.groups() else match.group(0)
                if not value:
                    continue
                dedupe = (rule["id"], line_index)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                preview = redact_secret(value)
                result.add(
                    Finding(
                        severity=rule["severity"],
                        title=rule["title"],
                        category="secret",
                        description=rule["description"],
                        evidence=f"{display_path}:{line_index}\nMatch: {preview}",
                        remediation=rule["remediation"],
                        cwe=rule["cwe"],
                        location=f"{display_path}:{line_index}",
                        resource=display_path,
                        key=f"secret:{rule['id']}",
                        raw={"rule": rule["id"], "line": line_index, "preview": preview},
                    )
                )
                added += 1
                if added >= max_findings:
                    return added
        # Generic high-entropy assignment, only if this line was not already
        # covered by a provider-specific rule.
        if not any(rule["pattern"].search(line) for rule in SECRET_RULES):
            match = GENERIC_SECRET_RE.search(line)
            if match:
                key_name, value = match.group(1), match.group(2)
                if not _looks_placeholder(value) and shannon_entropy(value) >= 3.0:
                    dedupe = ("generic-secret", line_index)
                    if dedupe not in seen:
                        seen.add(dedupe)
                        preview = redact_secret(value)
                        result.add(
                            Finding(
                                severity="high",
                                title=f"Possible hard-coded secret ({key_name})",
                                category="secret",
                                description="A high-entropy value is assigned to a credential-like variable. Confirm whether it is a live secret.",
                                evidence=f"{display_path}:{line_index}\nVariable: {key_name}\nMatch: {preview}\nEntropy: {shannon_entropy(value):.2f}",
                                remediation="Remove the secret from source, rotate it, and load it from a secrets manager or environment variable.",
                                cwe="CWE-798",
                                location=f"{display_path}:{line_index}",
                                resource=display_path,
                                key="secret:generic",
                                raw={
                                    "rule": "generic-secret",
                                    "line": line_index,
                                    "preview": preview,
                                    "entropy": round(shannon_entropy(value), 2),
                                },
                            )
                        )
                        added += 1
                        if added >= max_findings:
                            return added
    return added


def _run_gitleaks(ctx: ScanContext, root: Path, result: ScanResult) -> None:
    if not ctx.option_bool("external_tools", False):
        return
    path = tool_path("gitleaks")
    if not path:
        return
    if not (root / ".git").exists() and ctx.option_bool("git_history", False):
        ctx.log("Gitleaks history scan skipped because this is not a git repository", "warning")
        return
    ctx.log("Running Gitleaks for supplemental secret detection")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        report_path = handle.name
    command = [
        path,
        "detect",
        "--source",
        str(root),
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--no-banner",
        "--redact",
    ]
    if ctx.option_bool("git_history", False):
        command.extend(["--log-opts", "--all"])
    try:
        proc = run_tool(command, timeout=300)
        if proc.returncode not in (0, 1):
            ctx.log(f"Gitleaks exited with code {proc.returncode}", "warning")
            return
        with open(report_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        ctx.log(f"Gitleaks failed: {exc}", "warning")
        return
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass
    count = 0
    for item in data if isinstance(data, list) else []:
        file_path = str(item.get("File") or item.get("file") or "")
        line = item.get("StartLine") or item.get("startLine") or 0
        rule_id = str(item.get("RuleID") or item.get("ruleId") or "gitleaks")
        secret = str(item.get("Secret") or item.get("secret") or "")
        result.add(
            Finding(
                severity="high",
                title=f"Gitleaks: {truncate(rule_id.replace('-', ' ').title(), 150)}",
                category="secret",
                description=str(item.get("Description") or "Gitleaks detected a credential in the repository."),
                evidence=f"{file_path}:{line}\nMatch: {redact_secret(secret) if secret else '(redacted)'}",
                remediation="Revoke/rotate the credential and remove it from git history.",
                cwe="CWE-798",
                location=f"{file_path}:{line}",
                resource=file_path,
                key=f"gitleaks:{rule_id}",
                raw={"rule": rule_id, "line": line},
            )
        )
        count += 1
    ctx.log(f"Gitleaks reported {count} finding(s)")


def scan_secrets(ctx: ScanContext, root: Path, max_files: int | None = None) -> ScanResult:
    max_files = get_limit("max_scan_files", MAX_SCAN_FILES) if max_files is None else max_files
    result = ScanResult()
    if not root.is_dir():
        raise ValueError(f"Secret scan path is not a directory: {root}")
    files_scanned = 0
    total = 0
    env_files: list[str] = []
    ctx.log(f"Scanning {root} for secrets and credentials")
    for path in iter_files(root, max_files=max_files):
        ctx.check_cancel()
        if path.name in SKIP_SECRET_FILES:
            continue
        if path.name.startswith(".env") and not path.name.endswith((".example", ".sample", ".template")):
            env_files.append(relative_path(path, root))
        text = read_text_file(path)
        if not text:
            continue
        files_scanned += 1
        total += scan_text(text, relative_path(path, root), result)
        if files_scanned % 100 == 0:
            ctx.progress(min(85, 10 + int(files_scanned / max(1, max_files) * 60)), "Scanning files for secrets")
            ctx.log(f"Secret scan: {files_scanned} files inspected")
        if total >= 500:
            ctx.log("Secret finding limit reached (500); remaining files were skipped", "warning")
            break
    for env_file in env_files[:50]:
        result.add(
            Finding(
                severity="medium",
                title="Environment file committed to the repository",
                category="secret",
                description="A .env file is tracked in the project. These files commonly contain live credentials.",
                evidence=f"File present: {env_file}",
                remediation="Add .env to .gitignore, commit a .env.example instead, and rotate any values that were committed.",
                cwe="CWE-538",
                location=env_file,
                resource=env_file,
                key="env-file-committed",
            )
        )
    result.metadata = {
        "files_scanned": files_scanned,
        "secrets_found": total,
        "env_files": env_files[:50],
    }
    ctx.log(f"Secret scan complete: {files_scanned} files, {total} potential secret(s)")
    _run_gitleaks(ctx, root, result)
    return result
