"""Passive and wordlist-based subdomain discovery.

Subfinder is used for passive enumeration. Because subfinder does not accept a
wordlist itself, the editable SecLists-style wordlist is used for a local DNS
brute-force pass. Discovered hosts are reported, not scanned automatically.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from ..config import (
    ENABLE_EXTERNAL_APIS,
    SECLISTS_REPOSITORY_URL,
    SECLISTS_SUBDOMAIN_URL,
    data_dir,
    subfinder_wordlist_path,
)
from ..database import get_setting
from ..utils import truncate
from .base import Finding, ScanCancelled, ScanContext, ScanResult
from .tools import run_tool, tool_path

MAX_SUBDOMAINS = 5000
MAX_WORDLIST_BYTES = 2 * 1024 * 1024
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)


def normalize_domain(value: str) -> str:
    """Return a bare domain, rejecting URLs, IP addresses and invalid labels."""
    candidate = (value or "").strip()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    else:
        candidate = candidate.split("/", 1)[0]
    candidate = candidate.strip().strip(".").lower()
    if not candidate or "*" in candidate or ":" in candidate:
        raise ValueError("Domain scans require a bare domain such as example.com")
    try:
        socket.inet_pton(socket.AF_INET, candidate)
        raise ValueError("Domain scans require a domain name, not an IP address")
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, candidate)
        raise ValueError("Domain scans require a domain name, not an IP address")
    except OSError:
        pass
    if not DOMAIN_RE.match(candidate):
        raise ValueError("Enter a valid domain name such as example.com")
    return candidate


def _wordlist_lines(content: str) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for raw in content.splitlines():
        word = raw.split("#", 1)[0].strip()
        if not word:
            continue
        word = word.lstrip("*.").strip().lower()
        if not word or word in seen:
            continue
        if not re.match(r"^[a-z0-9_](?:[a-z0-9._-]{0,251}[a-z0-9_])?$", word, re.I):
            continue
        seen.add(word)
        lines.append(word)
    return lines


def read_wordlist(path: Path | None = None) -> list[str]:
    target = path or subfinder_wordlist_path()
    try:
        data = target.read_bytes()[:MAX_WORDLIST_BYTES].decode("utf-8", errors="replace")
    except OSError:
        return []
    return _wordlist_lines(data)


def wordlist_info() -> dict[str, Any]:
    path = subfinder_wordlist_path()
    exists = path.is_file()
    content = ""
    truncated = False
    if exists:
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_WORDLIST_BYTES:
                raw = raw[:MAX_WORDLIST_BYTES]
                truncated = True
            content = raw.decode("utf-8", errors="replace")
        except OSError:
            exists = False
    try:
        path.resolve().relative_to(data_dir().resolve())
        editable = True
    except ValueError:
        editable = False
    return {
        "path": str(path),
        "exists": exists,
        "editable": editable and not truncated,
        "truncated": truncated,
        "content": content,
        "line_count": len(_wordlist_lines(content)),
        "size": path.stat().st_size if exists else 0,
        "source": SECLISTS_REPOSITORY_URL,
        "source_url": SECLISTS_SUBDOMAIN_URL,
    }


def save_wordlist(content: str, path: Path | None = None) -> dict[str, Any]:
    target = path or subfinder_wordlist_path()
    target = target.resolve()
    try:
        target.relative_to(data_dir().resolve())
    except ValueError as exc:
        raise ValueError("The editable wordlist must be inside the VulnScanner data directory") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    text = (content or "").replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in text:
        raise ValueError("Wordlist contains invalid null bytes")
    if len(text.encode("utf-8")) > MAX_WORDLIST_BYTES:
        raise ValueError(f"Wordlist must be smaller than {MAX_WORDLIST_BYTES // (1024 * 1024)} MiB")
    fd, temp_name = tempfile.mkstemp(prefix=".wordlist.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, 0o644)
        except OSError:
            pass
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return wordlist_info()


def download_seclists_wordlist() -> dict[str, Any]:
    """Download the standard SecLists DNS wordlist to the editable path."""
    response = requests.get(SECLISTS_SUBDOMAIN_URL, timeout=30, stream=True)
    try:
        response.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_WORDLIST_BYTES:
                raise ValueError("SecLists wordlist is larger than the configured limit")
            chunks.append(chunk)
        content = b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        response.close()
    if not _wordlist_lines(content):
        raise ValueError("Downloaded SecLists wordlist did not contain usable entries")
    info = save_wordlist(content)
    info["downloaded"] = True
    return info


def _parse_subfinder_output(output: str, domain: str) -> set[str]:
    hosts: set[str] = set()
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        host = ""
        if line.startswith("{"):
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                host = str(item.get("host") or item.get("domain") or "")
        else:
            host = line.split()[0]
        host = host.strip().strip(".").lower()
        if (
            host
            and host != domain
            and host.endswith("." + domain)
            and DOMAIN_RE.match(host)
        ):
            hosts.add(host)
    return hosts


def _run_subfinder(ctx: ScanContext, domain: str) -> set[str]:
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        ctx.log("Subfinder skipped because external APIs are disabled", "warning")
        return set()
    if get_setting("subfinder_enabled", "true") != "true":
        ctx.log("Subfinder is disabled in Settings", "warning")
        return set()
    path = tool_path("subfinder")
    if not path:
        ctx.log("Subfinder not installed; using wordlist DNS discovery only", "warning")
        return set()
    ctx.log(f"Running Subfinder passive enumeration for {domain}")
    command = [path, "-d", domain, "-silent", "-json", "-all"]
    try:
        proc = run_tool(command, timeout=300)
    except Exception as exc:
        ctx.log(f"Subfinder failed to run: {exc}", "warning")
        return set()
    if proc.returncode not in (0, 1):
        ctx.log(f"Subfinder exited with code {proc.returncode}", "warning")
    # The parser accepts both JSON lines and the plain host-per-line output of
    # older releases that ignore ``-json``.
    hosts = _parse_subfinder_output(proc.stdout or "", domain)
    ctx.log(f"Subfinder reported {len(hosts)} unique subdomain(s)")
    return hosts


def _resolve_host(host: str) -> list[str]:
    addresses: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                addresses.add(str(sockaddr[0]))
    except (OSError, socket.gaierror):
        pass
    return sorted(addresses)


def _bruteforce(ctx: ScanContext, domain: str) -> tuple[set[str], dict[str, list[str]], dict[str, Any]]:
    words = read_wordlist()
    if not words:
        ctx.log(
            "No subdomain wordlist is configured. Add one under Settings or load the "
            "SecLists DNS wordlist.",
            "warning",
        )
        return set(), {}, {"words": 0, "reason": "missing-wordlist"}
    try:
        max_words = int(ctx.option("max_words", 5000))
    except (TypeError, ValueError):
        max_words = 5000
    max_words = max(1, min(max_words, 50_000))
    try:
        workers = int(ctx.option("workers", 50))
    except (TypeError, ValueError):
        workers = 50
    workers = max(1, min(workers, 100))
    words = words[:max_words]
    wildcard = f"vs-wildcard-{os.urandom(4).hex()}.{domain}"
    if _resolve_host(wildcard):
        ctx.log(
            "Wildcard DNS detected; wordlist brute force was skipped to avoid false positives",
            "warning",
        )
        return set(), {}, {"words": 0, "reason": "wildcard-dns"}
    ctx.log(f"Resolving {len(words)} wordlist candidates under {domain}")
    hosts: set[str] = set()
    addresses: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_resolve_host, f"{word}.{domain}"): word
            for word in words
        }
        for future in concurrent.futures.as_completed(futures):
            if ctx.cancelled():
                for pending in futures:
                    pending.cancel()
                ctx.check_cancel()
            host = f"{futures[future]}.{domain}"
            try:
                resolved = future.result()
            except Exception:
                continue
            if resolved:
                hosts.add(host)
                addresses[host] = resolved
    ctx.log(f"Wordlist discovery found {len(hosts)} resolving host(s)")
    return hosts, addresses, {
        "words": len(words),
        "resolved": len(hosts),
        "source": str(subfinder_wordlist_path()),
    }


def scan_subdomains(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    domain = normalize_domain(ctx.target)
    result.metadata = {"domain": domain}
    ctx.progress(8, "Enumerating subdomains")
    found: set[str] = set()
    sources: dict[str, set[str]] = {}
    passive_count = 0
    if ctx.option_bool("subfinder", True):
        passive = _run_subfinder(ctx, domain)
        passive_count = len(passive)
        found.update(passive)
        for host in passive:
            sources.setdefault(host, set()).add("subfinder")
    else:
        ctx.log("Passive Subfinder enumeration disabled by scan options")

    addresses: dict[str, list[str]] = {}
    bruteforce_meta: dict[str, Any] = {}
    if ctx.option_bool("bruteforce", True):
        ctx.progress(40, "Resolving wordlist candidates")
        try:
            active, addresses, bruteforce_meta = _bruteforce(ctx, domain)
            found.update(active)
            for host in active:
                sources.setdefault(host, set()).add("wordlist")
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"Wordlist discovery stopped: {exc}", "warning")
            bruteforce_meta = {"error": truncate(str(exc), 300)}
    else:
        ctx.log("Wordlist DNS discovery disabled by scan options")

    try:
        max_hosts = int(ctx.option("max_subdomains", MAX_SUBDOMAINS))
    except (TypeError, ValueError):
        max_hosts = MAX_SUBDOMAINS
    max_hosts = max(1, min(max_hosts, MAX_SUBDOMAINS))
    hosts = sorted(found)[:max_hosts]
    for host in hosts:
        source_text = ", ".join(sorted(sources.get(host, {"unknown"})))
        resolved = addresses.get(host) or _resolve_host(host)
        result.add(
            Finding(
                severity="info",
                title=f"Subdomain discovered: {host}",
                category="subdomain",
                description=(
                    "A DNS name under the scanned domain was discovered. It was not "
                    "scanned automatically; confirm ownership and authorisation first."
                ),
                evidence=(
                    f"Host: {host}\nSource: {source_text}"
                    + (f"\nResolved addresses: {', '.join(resolved)}" if resolved else "")
                ),
                remediation=(
                    "Confirm that the host is owned by the organisation, then add it as an "
                    "asset and start a web or network scan if in scope."
                ),
                location=host,
                resource=f"subdomain:{domain}",
                key=f"subdomain:{host}",
                raw={"host": host, "sources": sorted(sources.get(host, [])), "addresses": resolved},
            )
        )
    result.add(
        Finding(
            severity="info",
            title=f"Subdomain discovery completed for {domain}",
            category="subdomain",
            description=(
                f"Discovered {len(hosts)} subdomain(s). Passive sources: "
                f"{'enabled' if ctx.option_bool('subfinder', True) else 'disabled'}. "
                "Wordlist DNS discovery: "
                f"{'enabled' if ctx.option_bool('bruteforce', True) else 'disabled'}."
            ),
            evidence=(
                f"Domain: {domain}\n"
                f"Subdomains: {len(hosts)}\n"
                f"Wordlist: {subfinder_wordlist_path()}\n"
                f"SecLists: {SECLISTS_REPOSITORY_URL}"
            ),
            remediation="Review the discovered hosts and add authorised in-scope assets.",
            location=domain,
            key=f"subdomain-summary:{domain}",
            raw={"domain": domain, "count": len(hosts)},
        )
    )
    result.metadata.update(
        {
            "subdomains": hosts,
            "count": len(hosts),
            "subfinder": passive_count,
            "bruteforce": bruteforce_meta,
            "wordlist": str(subfinder_wordlist_path()),
            "seclists": SECLISTS_REPOSITORY_URL,
        }
    )
    ctx.progress(96, "Finalizing subdomain results")
    return result
