"""Web application and website scanner.

Checks are intentionally non-destructive: configuration review, exposed-file
checks, passive TLS inspection, safe error-based SQL injection probes, and
reflected-XSS canaries.  Nuclei is used in addition when installed and enabled.
"""

from __future__ import annotations

import json
import random
import re
import socket
import ssl
import string
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from requests.packages import urllib3

from ..config import ENABLE_EXTERNAL_APIS
from ..database import get_setting
from ..utils import normalize_target_url, redact_url, truncate
from .base import Finding, ScanContext, ScanResult
from .tools import run_tool, tool_path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (compatible; VulnScanner/1.0; +local-authorized-scan)"
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_(query|fetch|connect)",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"unterminated quoted string",
    r"ORA-\d{4,5}",
    r"Oracle error",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"Microsoft OLE DB Provider",
    r"ODBC SQL Server Driver",
    r"Unclosed quotation mark after the character string",
    r"syntax error at or near",
    r"quoted string not properly terminated",
    r"SQLSTATE\[\d+\]",
]
SQL_ERROR_RE = re.compile("|".join(f"(?:{p})" for p in SQL_ERROR_PATTERNS), re.I)

EXPOSED_PATHS: list[dict[str, Any]] = [
    {
        "path": ".git/HEAD",
        "title": "Exposed Git repository metadata",
        "severity": "high",
        "category": "web",
        "validator": lambda body, ctype: body.lstrip().startswith("ref:") or re.match(r"^[0-9a-f]{40}", body),
        "description": "The .git directory is publicly readable. Attackers can reconstruct source code and secrets from it.",
        "remediation": "Block access to dotfiles and .git in the web server or reverse proxy, then rotate any exposed secrets.",
        "cwe": "CWE-538",
    },
    {
        "path": ".env",
        "title": "Exposed .env file",
        "severity": "critical",
        "category": "web",
        "validator": lambda body, ctype: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=", body, re.M)) and "<html" not in body[:500].lower(),
        "description": "An environment file is publicly readable and may contain database passwords, API keys or signing secrets.",
        "remediation": "Remove the file from the web root, deny dotfile access, and rotate every credential it contained.",
        "cwe": "CWE-538",
    },
    {
        "path": ".svn/entries",
        "title": "Exposed Subversion metadata",
        "severity": "medium",
        "category": "web",
        "validator": lambda body, ctype: body.strip().isdigit() or "svn" in body[:200].lower(),
        "description": "Subversion metadata is accessible and may disclose source code.",
        "remediation": "Deny access to .svn directories.",
        "cwe": "CWE-538",
    },
    {
        "path": "phpinfo.php",
        "title": "PHP information page exposed",
        "severity": "medium",
        "category": "web",
        "validator": lambda body, ctype: "PHP Version" in body and "phpinfo" in body.lower(),
        "description": "phpinfo() discloses the PHP configuration, paths and installed modules.",
        "remediation": "Remove phpinfo pages from production.",
        "cwe": "CWE-200",
    },
    {
        "path": "server-status",
        "title": "Web server status page exposed",
        "severity": "medium",
        "category": "web",
        "validator": lambda body, ctype: "Apache Server Status" in body or "Server Status" in body[:1000],
        "description": "The server-status endpoint discloses active requests and internal hostnames.",
        "remediation": "Restrict server-status to localhost or remove it.",
        "cwe": "CWE-200",
    },
    {
        "path": "swagger.json",
        "title": "API documentation exposed",
        "severity": "low",
        "category": "web",
        "validator": lambda body, ctype: '"swagger"' in body[:2000] or '"openapi"' in body[:2000],
        "description": "API documentation is publicly reachable and can help attackers map endpoints.",
        "remediation": "Require authentication or restrict API documentation to internal networks.",
        "cwe": "CWE-200",
    },
    {
        "path": "package.json",
        "title": "Package manifest exposed",
        "severity": "info",
        "category": "web",
        "validator": lambda body, ctype: bool(re.match(r'\s*\{\s*"name"', body)),
        "description": "A package manifest is publicly readable. It can reveal dependency versions.",
        "remediation": "Serve only the built frontend assets, not the source project directory.",
        "cwe": "",
    },
    {
        "path": "backup.zip",
        "title": "Backup archive exposed",
        "severity": "high",
        "category": "web",
        "validator": lambda body, ctype: "zip" in ctype.lower() or body[:2] == "PK",
        "description": "A downloadable backup archive was found. It may contain source code, configuration or customer data.",
        "remediation": "Remove backups from the web root and store them in access-controlled storage.",
        "cwe": "CWE-538",
    },
    {
        "path": "backup.sql",
        "title": "Database dump exposed",
        "severity": "critical",
        "category": "web",
        "validator": lambda body, ctype: bool(re.search(r"(CREATE TABLE|INSERT INTO|-- MySQL dump)", body[:4000], re.I)),
        "description": "A database dump is publicly accessible.",
        "remediation": "Remove the dump immediately, restrict backups, and review for a data breach.",
        "cwe": "CWE-538",
    },
    {
        "path": "db.sql",
        "title": "Database dump exposed",
        "severity": "critical",
        "category": "web",
        "validator": lambda body, ctype: bool(re.search(r"(CREATE TABLE|INSERT INTO|-- MySQL dump)", body[:4000], re.I)),
        "description": "A database dump is publicly accessible.",
        "remediation": "Remove the dump immediately, restrict backups, and review for a data breach.",
        "cwe": "CWE-538",
    },
    {
        "path": "config.php.bak",
        "title": "Configuration backup exposed",
        "severity": "high",
        "category": "web",
        "validator": lambda body, ctype: "<?php" in body[:2000] or bool(re.search(r"(DB_PASSWORD|password|secret)\s*=", body[:4000], re.I)),
        "description": "A backup of a server-side configuration file is readable.",
        "remediation": "Remove backup files from the web root and rotate any credentials.",
        "cwe": "CWE-538",
    },
    {
        "path": ".DS_Store",
        "title": "macOS metadata file exposed",
        "severity": "low",
        "category": "web",
        "validator": lambda body, ctype: body.startswith("\x00\x00\x00\x01Bud1"),
        "description": "A .DS_Store file can disclose directory and file names.",
        "remediation": "Deny access to dotfiles.",
        "cwe": "CWE-538",
    },
]

SECURITY_HEADERS = [
    (
        "content-security-policy",
        "Content-Security-Policy header missing",
        "medium",
        "A Content-Security-Policy limits the impact of XSS and resource injection.",
        "Define a restrictive Content-Security-Policy (avoid unsafe-inline and unsafe-eval).",
        "CWE-693",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options header missing",
        "low",
        "MIME sniffing can turn otherwise harmless uploads into executable content.",
        "Set X-Content-Type-Options: nosniff on all responses.",
        "CWE-693",
    ),
    (
        "referrer-policy",
        "Referrer-Policy header missing",
        "low",
        "URLs and query parameters may leak to third parties through the Referer header.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        "CWE-200",
    ),
    (
        "permissions-policy",
        "Permissions-Policy header missing",
        "info",
        "Browser features such as camera and geolocation are not explicitly restricted.",
        "Define a Permissions-Policy appropriate for the application.",
        "CWE-693",
    ),
]


def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7",
        }
    )
    session.verify = False
    return session


def _safe_text(response: requests.Response, limit: int = 1_500_000) -> str:
    content = response.content or b""
    if len(content) > limit:
        content = content[:limit]
    return content.decode(response.encoding or "utf-8", errors="replace")


def _get(session: requests.Session, url: str, timeout: float = 10.0, **kwargs: Any) -> requests.Response:
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault("timeout", timeout)
    return session.get(url, **kwargs)


def _title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return ""
    return truncate(re.sub(r"\s+", " ", match.group(1)), 160)


def _resolve_web_target(ctx: ScanContext, session: requests.Session) -> tuple[str, requests.Response, str]:
    requested = normalize_target_url(ctx.target)
    ctx.log(f"Fetching {redact_url(requested)}")
    try:
        response = _get(session, requested, timeout=12)
        return requested, response, _safe_text(response)
    except requests.RequestException as exc:
        parsed = urlparse(requested)
        if parsed.scheme == "https":
            fallback = urlunparse(parsed._replace(scheme="http"))
            ctx.log(f"HTTPS failed ({exc.__class__.__name__}); trying HTTP", "warning")
            response = _get(session, fallback, timeout=12)
            return fallback, response, _safe_text(response)
        raise RuntimeError(f"Could not reach {redact_url(requested)}: {exc}") from exc


def _add_header_findings(
    result: ScanResult,
    url: str,
    response: requests.Response,
    body: str,
    ctx: ScanContext,
) -> None:
    headers = {key.lower(): value for key, value in response.headers.items()}
    parsed = urlparse(url)
    if parsed.scheme == "http":
        result.add(
            Finding(
                severity="medium",
                title="Site uses unencrypted HTTP",
                category="web",
                description="The website is available over plain HTTP. Credentials, session cookies and data can be intercepted.",
                evidence=f"Final URL: {redact_url(response.url)}",
                remediation="Redirect all HTTP traffic to HTTPS and deploy a valid certificate.",
                cwe="CWE-319",
                location=url,
                key="web-http",
            )
        )
    elif "strict-transport-security" not in headers:
        result.add(
            Finding(
                severity="medium",
                title="HTTP Strict Transport Security (HSTS) missing",
                category="web",
                description="Without HSTS, browsers may be downgraded to HTTP by an attacker.",
                evidence=f"URL: {url}",
                remediation="Send Strict-Transport-Security with a suitable max-age after confirming HTTPS works for all subdomains.",
                cwe="CWE-319",
                location=url,
                key="web-hsts",
            )
        )

    for header, title, severity, description, remediation, cwe in SECURITY_HEADERS:
        if header == "content-security-policy" and "content-security-policy-report-only" in headers:
            continue
        if header not in headers:
            result.add(
                Finding(
                    severity=severity,
                    title=title,
                    category="web",
                    description=description,
                    evidence=f"Response headers did not include {header}.",
                    remediation=remediation,
                    cwe=cwe,
                    location=url,
                    key=f"header:{header}",
                )
            )

    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get(
        "content-security-policy", ""
    ):
        result.add(
            Finding(
                severity="medium",
                title="Clickjacking protection missing",
                category="web",
                description="Neither X-Frame-Options nor CSP frame-ancestors prevents the site from being framed.",
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive.",
                remediation="Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                cwe="CWE-1021",
                location=url,
                key="header:frame-options",
            )
        )

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    disclosed = ", ".join(value for value in (server, powered) if value)
    if disclosed and re.search(r"\d+\.\d+", disclosed):
        result.add(
            Finding(
                severity="low",
                title="Server version disclosed in response headers",
                category="web",
                description="Software version information helps attackers select exploits for known vulnerabilities.",
                evidence=truncate(disclosed, 250),
                remediation="Remove version banners from Server and X-Powered-By headers.",
                cwe="CWE-200",
                location=url,
                key="header:version-banner",
            )
        )

    cors = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    if cors == "*" and credentials == "true":
        result.add(
            Finding(
                severity="medium",
                title="Permissive CORS with credentials",
                category="web",
                description="The CORS configuration allows any origin while also allowing credentials.",
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                remediation="Return specific trusted origins instead of * when credentials are allowed.",
                cwe="CWE-942",
                location=url,
                key="header:cors",
            )
        )
    elif cors == "*":
        result.add(
            Finding(
                severity="info",
                title="Wildcard CORS policy",
                category="web",
                description="Any origin can read unauthenticated responses from this endpoint. Confirm this is intentional.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to known origins if the endpoint returns sensitive data.",
                cwe="CWE-942",
                location=url,
                key="header:cors-wildcard",
            )
        )

    # Cookies
    for cookie_header in response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []:
        name = cookie_header.split("=", 1)[0].strip()
        lower = cookie_header.lower()
        issues = []
        if parsed.scheme == "https" and "secure" not in lower:
            issues.append("Secure")
        if "httponly" not in lower:
            issues.append("HttpOnly")
        if "samesite" not in lower:
            issues.append("SameSite")
        if issues:
            result.add(
                Finding(
                    severity="low",
                    title=f"Cookie '{truncate(name, 60)}' lacks security attributes",
                    category="web",
                    description="Cookies without Secure/HttpOnly/SameSite are easier to steal or abuse.",
                    evidence=f"Cookie {truncate(name, 80)} is missing: {', '.join(issues)}",
                    remediation="Set Secure, HttpOnly and SameSite=Lax or Strict on session cookies.",
                    cwe="CWE-614",
                    location=url,
                    key=f"cookie:{name}:{','.join(issues)}",
                )
            )

    if re.search(r"<title[^>]*>\s*Index of /", body, re.I) or (
        "Parent Directory" in body and "Index of" in body[:3000]
    ):
        result.add(
            Finding(
                severity="medium",
                title="Directory listing enabled",
                category="web",
                description="The web server exposes a browsable directory index.",
                evidence="Response contains an 'Index of /' directory listing.",
                remediation="Disable autoindex/directory browsing and add an index file.",
                cwe="CWE-548",
                location=url,
                key="web-directory-listing",
            )
        )


def _exposed_files(
    result: ScanResult, session: requests.Session, base_url: str, ctx: ScanContext
) -> None:
    parsed = urlparse(base_url)
    base = urlunparse(parsed._replace(path="/", query="", fragment=""))
    for index, item in enumerate(EXPOSED_PATHS):
        ctx.check_cancel()
        probe_url = urljoin(base, item["path"])
        try:
            response = _get(session, probe_url, timeout=7)
        except requests.RequestException:
            continue
        if response.status_code != 200:
            continue
        body = _safe_text(response, 60_000)
        content_type = response.headers.get("content-type", "")
        try:
            valid = bool(item["validator"](body, content_type))
        except Exception:
            valid = False
        if not valid:
            continue
        result.add(
            Finding(
                severity=item["severity"],
                title=item["title"],
                category="web",
                description=item["description"],
                evidence=f"HTTP 200 at {probe_url} (content-type: {truncate(content_type, 100)})",
                remediation=item["remediation"],
                cwe=item.get("cwe", ""),
                location=probe_url,
                key=f"exposed:{item['path']}",
            )
        )
    if len(EXPOSED_PATHS) > 0:
        ctx.log(f"Checked {len(EXPOSED_PATHS)} common exposed-file paths")


def _injection_checks(
    result: ScanResult,
    session: requests.Session,
    url: str,
    response: requests.Response,
    body: str,
    ctx: ScanContext,
) -> None:
    if not ctx.option_bool("active", True):
        ctx.log("Active injection probes disabled by scan options")
        return
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        ctx.log("No query parameters available for injection probes")
        return
    if len(params) > 8:
        params = params[:8]
    # SQL injection: append a quote and look for database error output.
    for name, value in params:
        ctx.check_cancel()
        mutated = [(k, (v + "'") if k == name else v) for k, v in params]
        probe_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        try:
            probe = _get(session, probe_url, timeout=10)
        except requests.RequestException:
            continue
        probe_body = _safe_text(probe, 500_000)
        match = SQL_ERROR_RE.search(probe_body)
        if match:
            result.add(
                Finding(
                    severity="high",
                    title=f"Possible SQL injection in parameter '{name}'",
                    category="web",
                    description="A single quote in a query parameter produced a database error. This strongly suggests unsanitized input reaches a SQL query.",
                    evidence=f"Parameter: {name}\nDatabase error fragment: {truncate(match.group(0), 250)}\nProbe: {redact_url(probe_url)}",
                    remediation="Use parameterized queries/prepared statements. Suppress database errors in production responses.",
                    cwe="CWE-89",
                    location=probe_url,
                    key=f"sqli:{name}",
                )
            )
            ctx.log(f"Possible SQL injection detected in parameter '{name}'", "warning")

    # Reflected XSS canary.
    canary = "vs" + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    payload = f'"><{canary}>'
    for name, _ in params[:6]:
        ctx.check_cancel()
        mutated = [(k, payload if k == name else v) for k, v in params]
        probe_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        try:
            probe = _get(session, probe_url, timeout=10)
        except requests.RequestException:
            continue
        probe_body = _safe_text(probe, 500_000)
        ctype = probe.headers.get("content-type", "")
        if payload in probe_body and "html" in ctype.lower():
            result.add(
                Finding(
                    severity="high",
                    title=f"Reflected HTML injection in parameter '{name}'",
                    category="web",
                    description="User input was reflected into the HTML response without encoding. This is a strong indicator of reflected cross-site scripting (XSS).",
                    evidence=f"Parameter: {name}\nPayload reflected literally: {payload}\nProbe: {redact_url(probe_url)}",
                    remediation="Contextually encode output and apply a restrictive Content-Security-Policy. Validate input server-side.",
                    cwe="CWE-79",
                    location=probe_url,
                    key=f"xss:{name}",
                )
            )
            ctx.log(f"Reflected HTML injection detected in parameter '{name}'", "warning")


def _tls_findings(result: ScanResult, host: str, port: int, ctx: ScanContext) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                version = tls.version() or ""
    except (OSError, ssl.SSLError) as exc:
        result.add(
            Finding(
                severity="medium",
                title="TLS connection could not be established",
                category="web",
                description="The HTTPS endpoint did not complete a TLS handshake during the scan.",
                evidence=truncate(str(exc), 300),
                remediation="Verify the certificate chain, TLS configuration and service availability.",
                cwe="CWE-295",
                location=f"{host}:{port}",
                key="tls-handshake",
            )
        )
        return

    if version in {"TLSv1", "TLSv1.1"}:
        result.add(
            Finding(
                severity="medium",
                title=f"Obsolete TLS protocol negotiated ({version})",
                category="web",
                description="TLS 1.0/1.1 are deprecated and should not be used.",
                evidence=f"Negotiated {version}",
                remediation="Disable TLS 1.0 and TLS 1.1; allow TLS 1.2 and TLS 1.3 only.",
                cwe="CWE-326",
                location=f"{host}:{port}",
                key="tls-version",
            )
        )

    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days = (expires - datetime.now(timezone.utc)).days
            evidence = f"Certificate expires {expires.date().isoformat()} ({days} days)"
            if days < 0:
                result.add(
                    Finding(
                        severity="high",
                        title="TLS certificate has expired",
                        category="web",
                        description="Browsers and clients will reject the certificate.",
                        evidence=evidence,
                        remediation="Renew and deploy the TLS certificate.",
                        cwe="CWE-298",
                        location=f"{host}:{port}",
                        key="tls-expired",
                    )
                )
            elif days < 30:
                result.add(
                    Finding(
                        severity="medium",
                        title="TLS certificate expires soon",
                        category="web",
                        description="The certificate expires in less than 30 days.",
                        evidence=evidence,
                        remediation="Renew the certificate and automate renewal.",
                        cwe="CWE-298",
                        location=f"{host}:{port}",
                        key="tls-expiry",
                    )
                )
        except ValueError:
            pass

    issuer = dict(x[0] for x in cert.get("issuer", []) if x)
    subject = dict(x[0] for x in cert.get("subject", []) if x)
    if issuer and subject and issuer == subject:
        result.add(
            Finding(
                severity="high",
                title="Self-signed TLS certificate",
                category="web",
                description="The server uses a self-signed certificate that is not trusted by normal clients.",
                evidence=f"Issuer: {truncate(issuer.get('commonName', ''), 150)}",
                remediation="Deploy a certificate from a trusted public or internal CA.",
                cwe="CWE-295",
                location=f"{host}:{port}",
                key="tls-self-signed",
            )
        )
    else:
        verify_context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with verify_context.wrap_socket(sock, server_hostname=host):
                    pass
        except ssl.SSLCertVerificationError as exc:
            message = exc.verify_message or str(exc)
            severity = "high" if "expired" in message.lower() else "medium"
            result.add(
                Finding(
                    severity=severity,
                    title="TLS certificate is not trusted",
                    category="web",
                    description="The certificate chain or hostname did not validate against the system trust store.",
                    evidence=truncate(message, 300),
                    remediation="Use a valid certificate matching the hostname and include the full intermediate chain.",
                    cwe="CWE-295",
                    location=f"{host}:{port}",
                    key="tls-untrusted",
                )
            )
        except (OSError, ssl.SSLError):
            pass


def _run_nuclei(result: ScanResult, url: str, ctx: ScanContext) -> None:
    if not ctx.option_bool("external_tools", False):
        return
    if not ENABLE_EXTERNAL_APIS or get_setting("nuclei_enabled", "true") != "true":
        return
    path = tool_path("nuclei")
    if not path:
        ctx.log("Nuclei not installed; using built-in checks only", "warning")
        return
    ctx.log("Running Nuclei templates (non-interactive, critical/high/medium)")
    command = [
        path,
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-no-interactsh",
        "-disable-update-check",
        "-severity",
        "critical,high,medium",
        "-timeout",
        "10",
        "-retries",
        "1",
    ]
    try:
        proc = run_tool(command, timeout=600)
    except Exception as exc:
        ctx.log(f"Nuclei failed to run: {exc}", "warning")
        return
    if proc.returncode not in (0, 1):
        ctx.log(f"Nuclei exited with code {proc.returncode}", "warning")
    count = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") or ""
        cwe = classification.get("cwe-id") or ""
        if isinstance(cve, list):
            cve = ",".join(str(x) for x in cve)
        if isinstance(cwe, list):
            cwe = ",".join(str(x) for x in cwe)
        matched = item.get("matched-at") or item.get("host") or url
        result.add(
            Finding(
                severity=str(info.get("severity") or "medium"),
                title=str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                category="web",
                description=str(info.get("description") or "") + (
                    f"\n\nTags: {', '.join(info.get('tags') or [])}" if info.get("tags") else ""
                ),
                evidence=f"Template: {item.get('template-id', '')}\nMatcher: {item.get('matcher-name', '')}\nMatched at: {matched}",
                remediation=str(info.get("remediation") or "Review the Nuclei template and vendor guidance."),
                cve=str(cve),
                cwe=str(cwe),
                cvss=classification.get("cvss-score"),
                location=matched,
                resource=f"nuclei:{item.get('template-id', '')}",
                key=f"nuclei:{item.get('template-id', '')}:{item.get('matcher-name', '')}",
                raw={"template_id": item.get("template-id", ""), "tags": info.get("tags", [])},
            )
        )
        count += 1
    ctx.log(f"Nuclei reported {count} finding(s)")


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    session = _session()
    try:
        url, response, body = _resolve_web_target(ctx, session)
        ctx.progress(20, "Analyzing HTTP response")
        result.metadata = {
            "final_url": redact_url(response.url),
            "status_code": response.status_code,
            "title": _title(body),
            "server": truncate(response.headers.get("server", ""), 200),
            "content_type": truncate(response.headers.get("content-type", ""), 200),
            "content_length": len(response.content or b""),
        }
        ctx.log(f"HTTP {response.status_code} from {redact_url(response.url)}")

        _add_header_findings(result, url, response, body, ctx)
        ctx.progress(35, "Checking exposed files")
        _exposed_files(result, session, url, ctx)
        ctx.progress(55, "Testing input handling")
        try:
            _injection_checks(result, session, url, response, body, ctx)
        except requests.RequestException as exc:
            ctx.log(f"Injection probes stopped: {exc}", "warning")

        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.hostname:
            ctx.progress(70, "Inspecting TLS configuration")
            _tls_findings(result, parsed.hostname, parsed.port or 443, ctx)

        ctx.progress(82, "Running Nuclei (optional)")
        _run_nuclei(result, url, ctx)
        ctx.progress(95, "Finalizing web results")
        return result
    finally:
        session.close()
