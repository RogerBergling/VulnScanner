"""Lightweight source-code review rules.

These checks complement dedicated SAST tools (Semgrep, CodeQL, Bandit).  They
are intentionally transparent heuristics, not a replacement for taint analysis.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import ENABLE_EXTERNAL_APIS, MAX_SCAN_FILES, get_limit
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult
from .filesystem import iter_files, read_text_file, relative_path
from .tools import run_tool, tool_path

MASK_RE = re.compile(
    r"\b((?:gh[pousr]_|github_pat_|glpat-|sk_live_|sk-|AKIA|ASIA|AIza)[A-Za-z0-9_\-]{8,})"
)


def _safe_evidence(line: str) -> str:
    line = MASK_RE.sub(lambda m: m.group(1)[:6] + "***", line.strip())
    return truncate(line, 400)


RULES: list[dict[str, Any]] = [
    {
        "id": "dynamic-sql",
        "title": "Potential SQL injection from dynamic query construction",
        "severity": "high",
        "extensions": {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".kt", ".rb", ".cs", ".go", ".scala"},
        "pattern": re.compile(
            r"(?i)(?:execute|executemany|query|rawQuery|createStatement|prepareStatement|sequelize\.query)\s*\(\s*"
            r"(?:f[\"']|[^\"']*[\"']\s*(?:\+|%|\.format\()|.*\$)"
        ),
        "description": "A SQL statement appears to be assembled from dynamic values and executed. If any value is user-controlled this can allow SQL injection.",
        "remediation": "Use parameterized queries/prepared statements and never concatenate or format user input into SQL.",
        "cwe": "CWE-89",
        "sql_context": True,
    },
    {
        "id": "command-injection",
        "title": "Potential command injection sink",
        "severity": "high",
        "extensions": {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java"},
        "pattern": re.compile(
            r"(?:os\.system\s*\(|os\.popen\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|"
            r"child_process\.(?:exec|execSync)\s*\(|shell_exec\s*\(|passthru\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()"
        ),
        "description": "A shell command execution API was found. If arguments include untrusted input, command injection is possible.",
        "remediation": "Avoid shell execution. Pass argument arrays with shell=False, use allow-lists, and validate input.",
        "cwe": "CWE-78",
    },
    {
        "id": "unsafe-eval",
        "title": "Unsafe dynamic code evaluation",
        "severity": "medium",
        "extensions": {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"},
        "pattern": re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        "description": "Dynamic code evaluation can become remote code execution if attacker-controlled data reaches it.",
        "remediation": "Replace eval/exec with explicit parsing or dispatch tables. Never pass user input to dynamic evaluation.",
        "cwe": "CWE-95",
    },
    {
        "id": "unsafe-deserialization",
        "title": "Unsafe deserialization",
        "severity": "high",
        "extensions": {".py", ".js", ".ts", ".php", ".rb", ".java"},
        "pattern": re.compile(
            r"(?:pickle\.loads?\s*\(|marshal\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)|"
            r"unserialize\s*\(|readObject\s*\()"
        ),
        "description": "Deserializing untrusted data with this API can lead to code execution.",
        "remediation": "Use safe formats (JSON) and safe loader APIs. If pickle/serialized objects are required, sign and authenticate the data.",
        "cwe": "CWE-502",
    },
    {
        "id": "debug-enabled",
        "title": "Debug mode may be enabled in source",
        "severity": "medium",
        "extensions": {".py", ".js", ".ts", ".rb", ".php"},
        "pattern": re.compile(r"(?i)(?:debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*:\s*true)"),
        "description": "Debug mode can disclose stack traces, environment variables and interactive consoles in production.",
        "remediation": "Read debug settings from the environment and ensure they are disabled in production.",
        "cwe": "CWE-489",
    },
    {
        "id": "xss-sink",
        "title": "Potential DOM XSS sink",
        "severity": "medium",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".html", ".php"},
        "pattern": re.compile(r"(?:innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html\s*=)"),
        "description": "An HTML sink was found. If the assigned value contains unencoded user input, cross-site scripting is possible.",
        "remediation": "Use textContent or framework escaping. Sanitize HTML with a maintained allow-list sanitizer if rich HTML is required.",
        "cwe": "CWE-79",
    },
    {
        "id": "tls-verification-disabled",
        "title": "TLS certificate verification disabled",
        "severity": "medium",
        "extensions": {".py", ".js", ".ts", ".go", ".java", ".rb", ".php"},
        "pattern": re.compile(
            r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
            r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|TrustAllCerts|NoopHostnameVerifier)"
        ),
        "description": "TLS certificate validation is disabled, allowing man-in-the-middle attacks.",
        "remediation": "Enable certificate and hostname verification. If using a private CA, install that CA explicitly.",
        "cwe": "CWE-295",
    },
    {
        "id": "weak-hash",
        "title": "Weak cryptographic hash used for security",
        "severity": "low",
        "extensions": {".py", ".js", ".ts", ".php", ".java", ".rb", ".go"},
        "pattern": re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)|Crypto\.Hash\.(?:MD5|SHA1))"),
        "description": "MD5/SHA-1 are unsuitable for password hashing or integrity checks against attackers.",
        "remediation": "Use Argon2id, scrypt or bcrypt for passwords and SHA-256+ for integrity where appropriate.",
        "cwe": "CWE-328",
    },
    {
        "id": "insecure-random",
        "title": "Non-cryptographic random number generator",
        "severity": "low",
        "extensions": {".py", ".js", ".ts", ".php", ".java", ".rb"},
        "pattern": re.compile(r"(?i)(?:Math\.random\s*\(|random\.random\s*\(|new Random\s*\()"),
        "description": "A non-cryptographic PRNG may be used for tokens, passwords or security decisions.",
        "remediation": "Use a CSPRNG: secrets module, crypto.randomBytes, SecureRandom, or random_bytes.",
        "cwe": "CWE-338",
    },
]


SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def _semgrep_cwe(metadata: dict[str, Any]) -> str:
    value = metadata.get("cwe")
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    matches = re.findall(r"CWE-\d+", str(value or ""))
    return ", ".join(dict.fromkeys(matches))


def _run_semgrep(ctx: ScanContext, root: Path, result: ScanResult) -> int:
    if not ctx.option_bool("external_tools", False):
        return 0
    if not ENABLE_EXTERNAL_APIS:
        ctx.log("Semgrep skipped because external APIs are disabled", "warning")
        return 0
    path = tool_path("semgrep")
    if not path:
        return 0
    ctx.log("Running Semgrep security rules (registry config: auto)")
    command = [
        path,
        "scan",
        "--config",
        "auto",
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--disable-version-check",
        "--timeout",
        "10",
        "--max-target-bytes",
        "1048576",
        str(root),
    ]
    try:
        proc = run_tool(command, timeout=600)
    except Exception as exc:
        ctx.log(f"Semgrep failed to run: {exc}", "warning")
        return 0
    output = (proc.stdout or "").strip()
    if not output:
        if proc.returncode != 0:
            ctx.log(f"Semgrep exited with code {proc.returncode}: {truncate(proc.stderr, 300)}", "warning")
        return 0
    try:
        data = json.loads(output[output.find("{"):] if "{" in output else output)
    except ValueError:
        ctx.log("Semgrep returned output that was not valid JSON", "warning")
        return 0
    if not isinstance(data, dict):
        return 0
    if data.get("errors"):
        ctx.log(f"Semgrep reported {len(data['errors'])} rule/scanning error(s)", "warning")
    count = 0
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(item.get("check_id") or "semgrep")
        raw_path = str(item.get("path") or "")
        try:
            display = str(Path(raw_path).resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            display = raw_path
        line = (item.get("start") or {}).get("line") or 0
        message = str(extra.get("message") or metadata.get("message") or "Semgrep rule matched.")
        severity = SEMGREP_SEVERITY.get(str(extra.get("severity") or "").upper(), "medium")
        result.add(
            Finding(
                severity=severity,
                title=f"Semgrep: {truncate(rule_id.split('.')[-1].replace('-', ' ').title(), 150)}",
                category="source",
                description=message,
                evidence=f"{display}:{line}\n{_safe_evidence(str(extra.get('lines') or ''))}",
                remediation=str(metadata.get("remediation") or "Review the data flow and apply the Semgrep rule guidance."),
                cwe=_semgrep_cwe(metadata),
                location=f"{display}:{line}",
                resource=display,
                key=f"semgrep:{rule_id}",
                raw={"rule": rule_id, "line": line, "confidence": metadata.get("confidence", "")},
            )
        )
        count += 1
        if count >= 300:
            ctx.log("Semgrep finding limit reached (300)", "warning")
            break
    ctx.log(f"Semgrep reported {count} finding(s)")
    return count


def scan_source(ctx: ScanContext, root: Path) -> ScanResult:
    result = ScanResult()
    files = 0
    count = 0
    for path in iter_files(root, max_files=get_limit("max_scan_files", MAX_SCAN_FILES)):
        ctx.check_cancel()
        extension = path.suffix.lower()
        if not any(extension in rule["extensions"] for rule in RULES):
            continue
        text = read_text_file(path)
        if not text:
            continue
        files += 1
        display = relative_path(path, root)
        for line_index, line in enumerate(text.splitlines(), start=1):
            if len(line) > 2000:
                line = line[:2000]
            for rule in RULES:
                if extension not in rule["extensions"]:
                    continue
                if rule.get("sql_context"):
                    if not re.search(r"(?i)\b(?:select|insert|update|delete|where|from)\b", line):
                        continue
                if rule["pattern"].search(line):
                    result.add(
                        Finding(
                            severity=rule["severity"],
                            title=rule["title"],
                            category="source",
                            description=rule["description"] + "\n\nReview the surrounding data flow to confirm exploitability.",
                            evidence=f"{display}:{line_index}\n{_safe_evidence(line)}",
                            remediation=rule["remediation"],
                            cwe=rule["cwe"],
                            location=f"{display}:{line_index}",
                            resource=display,
                            key=f"source:{rule['id']}",
                            raw={"rule": rule["id"], "line": line_index},
                        )
                    )
                    count += 1
                    if count >= 300:
                        ctx.log("Source finding limit reached (300)", "warning")
                        semgrep_count = _run_semgrep(ctx, root, result)
                        result.metadata = {
                            "files_scanned": files,
                            "findings": count,
                            "semgrep_findings": semgrep_count,
                        }
                        return result
        if files % 100 == 0:
            ctx.log(f"Source review: {files} files inspected")
    semgrep_count = _run_semgrep(ctx, root, result)
    result.metadata = {
        "files_scanned": files,
        "findings": count,
        "semgrep_findings": semgrep_count,
    }
    ctx.log(f"Source review complete: {files} files, {count} potential issue(s)")
    return result
