"""VulnScanner satellite runner.

A satellite is a second VulnScanner installation that polls a master server
over outbound HTTPS, executes scan jobs from its own network position (for
example a DMZ) and uploads findings to the master. The master owns all data;
the satellite never needs an inbound firewall rule.

Usage::

    python -m app.satellite enroll --server https://master.example.com \
        --code vs_pair_... [--name dmz-1] [--subnets 10.30.0.0/16]
    python -m app.satellite run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from . import __version__


def default_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("APPDATA", str(Path.home())))
        return base / "VulnScanner" / "satellite.json"
    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "vulnscanner" / "satellite.json"


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"Satellite configuration not found at {path}. Run 'enroll' first.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"Could not read satellite configuration: {exc}") from exc


def save_config(path: Path, config: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def local_hostname() -> str:
    return socket.gethostname()


def ensure_local_database() -> None:
    """Create the local cache/settings database used by scanner engines.

    A satellite is a disposable executor and never stores findings, but the
    shared scan engines use SQLite for tool settings and for the NVD/OSV/EPSS
    caches. Without this the documented "database-free" runner fails with
    ``no such table: settings`` as soon as CVE matching or Nmap is enabled.
    """
    from .database import init_db

    init_db()


def _clean_fingerprint(value: str) -> str:
    return "".join(char for char in (value or "").lower() if char in "0123456789abcdef")


class FingerprintAdapter(HTTPAdapter):
    """Pin a SHA-256 certificate fingerprint for requests/urllib3.

    ``requests`` has no public certificate-pinning API. urllib3 supports
    ``assert_fingerprint`` on its HTTPS connection pool, so this adapter sets it
    after the normal CA verification has been configured.
    """

    def __init__(self, fingerprint: str, *args: Any, **kwargs: Any) -> None:
        self.fingerprint = _clean_fingerprint(fingerprint)
        if len(self.fingerprint) != 64:
            raise ValueError("A certificate fingerprint must be a SHA-256 hex digest")
        super().__init__(*args, **kwargs)

    def cert_verify(self, conn: Any, url: str, verify: Any, cert: Any) -> None:
        super().cert_verify(conn, url, verify, cert)
        # The pinned fingerprint is the trust anchor. Public-CA validation
        # would reject the default self-signed master before the pin is
        # checked, so disable CA verification and keep the pin.
        conn.cert_reqs = ssl.CERT_NONE
        conn.ca_certs = None
        conn.ca_cert_dir = None
        conn.assert_fingerprint = self.fingerprint


def _server_certificate_fingerprint(server_url: str, timeout: float = 15.0) -> str:
    """Fetch the TLS certificate fingerprint without trusting it yet.

    This is only used to show the operator the value to pin or to diagnose a
    failed verification. It must never be treated as proof of identity by
    itself.
    """
    parsed = urlparse(server_url if "://" in server_url else f"https://{server_url}")
    host = parsed.hostname
    if not host:
        raise SystemExit("The satellite server URL does not contain a hostname")
    port = parsed.port or 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
    except OSError as exc:
        raise SystemExit(f"Could not read the server certificate from {host}:{port}: {exc}") from exc
    if not der:
        raise SystemExit(f"The server at {host}:{port} did not present a TLS certificate")
    return hashlib.sha256(der).hexdigest()


def _enrollment_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    if args.insecure:
        session.verify = False
    elif args.ca_cert:
        session.verify = args.ca_cert
    else:
        session.verify = True
    if args.fingerprint:
        session.mount("https://", FingerprintAdapter(args.fingerprint))
    return session


def enroll(args: argparse.Namespace) -> None:
    config_path = Path(args.config).expanduser() if args.config else default_config_path()
    payload: dict[str, Any] = {
        "pairing_code": args.code,
        "name": args.name or local_hostname(),
        "hostname": local_hostname(),
        "platform": sys.platform,
        "version": __version__,
    }
    if args.subnets:
        payload["subnets"] = [item.strip() for item in args.subnets.split(",") if item.strip()]
    session = _enrollment_session(args)
    try:
        response = session.post(
            f"{args.server.rstrip('/')}/api/satellite/pair",
            json=payload,
            timeout=60,
            headers={"User-Agent": f"VulnScanner-satellite/{__version__}"},
        )
    except requests.exceptions.SSLError as exc:
        fingerprint = _server_certificate_fingerprint(args.server)
        raise SystemExit(
            "TLS verification of the master failed.\n"
            f"  Server certificate SHA-256: {fingerprint}\n"
            "Re-run with one of:\n"
            f"  --fingerprint {fingerprint}\n"
            "  --ca-cert /path/to/master-server-or-ca.pem\n"
            "Use --insecure only on an isolated lab network."
        ) from exc
    finally:
        session.close()
    if response.status_code != 200:
        raise SystemExit(f"Pairing failed: HTTP {response.status_code} {response.text[:400]}")
    data = response.json()
    cert_path = config_path.parent / "client.crt"
    key_path = config_path.parent / "client.key"
    ca_path = config_path.parent / "ca.crt"
    cert_path.write_text(data["client_cert"], encoding="utf-8")
    key_path.write_text(data["client_key"], encoding="utf-8")
    ca_path.write_text(data["ca_cert"], encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o600)
        os.chmod(ca_path, 0o644)
    except OSError:
        pass

    # Pin the certificate observed during enrolment unless the operator asked
    # for CA-only verification. This makes the documented command work against
    # the default self-signed master without disabling TLS verification later.
    fingerprint = _clean_fingerprint(args.fingerprint or "")
    if not args.no_pin and not args.insecure:
        try:
            fingerprint = _clean_fingerprint(
                args.fingerprint or _server_certificate_fingerprint(args.server)
            )
        except SystemExit:
            # The pairing request already succeeded, so a later TLS probe
            # failure should not discard the enrollment. CA/system trust still
            # applies.
            fingerprint = _clean_fingerprint(args.fingerprint or "")

    config = {
        # Enrolment happens on the main listener; subsequent polling uses the
        # dedicated mTLS listener when the master advertises one.
        "server": str(data.get("server_url") or args.server).rstrip("/"),
        "satellite_id": data["satellite_id"],
        "token": data["token"],
        "name": args.name or local_hostname(),
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        # ca_path is the client-certificate CA issued by the master. It is not
        # the trust anchor for the master's own TLS certificate.
        "ca_path": str(ca_path),
        "client_ca_path": str(ca_path),
        "server_ca_path": str(Path(args.ca_cert).expanduser()) if args.ca_cert else "",
        "server_fingerprint": fingerprint,
        "verify_tls": not args.insecure,
        "poll_interval": 30,
        "subnets": payload.get("subnets", []),
    }
    save_config(config_path, config)
    print(f"Satellite {config['satellite_id']} enrolled with {config['server']}")
    if fingerprint and not args.insecure:
        print(f"Pinned master certificate SHA-256: {fingerprint}")
    print(f"Configuration stored at {config_path}")


class SatelliteContext:
    """ScanContext-compatible facade that logs to memory, never to a database."""

    def __init__(self, target: str, options: dict[str, Any]):
        self.scan_id = 0
        self.target = target
        self.options = options
        self.logs: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "info") -> None:
        self.logs.append((level, message))

    def progress(self, value: int, stage: str | None = None) -> None:
        pass

    def cancelled(self) -> bool:
        return False

    def check_cancel(self) -> None:
        return None

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def option_bool(self, name: str, default: bool = False) -> bool:
        value = self.options.get(name, default)
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)


def execute_job(job: dict[str, Any]) -> dict[str, Any]:
    """Run a scan job locally and return the upload payload."""
    ensure_local_database()
    scan_type = job.get("scan_type")
    target = str(job.get("target") or "")
    options = job.get("options") or {}
    ctx = SatelliteContext(target, options)
    if scan_type == "network":
        from .scanners.network import scan as scan_network

        result = scan_network(ctx)
    elif scan_type == "web":
        from .scanners.web import scan as scan_web

        result = scan_web(ctx)
    else:
        raise ValueError(f"Unsupported satellite scan type: {scan_type}")
    metadata = dict(result.metadata or {})
    metadata["execution"] = "satellite"
    return {
        "findings": result.normalized(),
        "metadata": metadata,
        "logs": [{"level": level, "message": message} for level, message in ctx.logs[-200:]],
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _session(config: dict[str, Any]) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {config['token']}",
            "User-Agent": f"VulnScanner-satellite/{__version__}",
        }
    )
    if config.get("cert_path") and Path(config["cert_path"]).is_file():
        session.cert = (config["cert_path"], config.get("key_path", ""))
    session.verify = True if config.get("verify_tls", True) else False
    if config.get("verify_tls", True):
        server_ca = str(config.get("server_ca_path") or "").strip()
        if not server_ca and not config.get("server_fingerprint"):
            # Backwards compatibility for configurations created before the
            # client CA and server CA were separated.
            legacy_ca = str(config.get("ca_path") or "").strip()
            if legacy_ca and Path(legacy_ca).is_file():
                server_ca = legacy_ca
        if server_ca and Path(server_ca).is_file():
            session.verify = server_ca
        fingerprint = _clean_fingerprint(str(config.get("server_fingerprint") or ""))
        if fingerprint:
            session.mount("https://", FingerprintAdapter(fingerprint))
    return session


def run(config_path: Path) -> None:
    config = load_config(config_path)
    ensure_local_database()
    session = _session(config)
    server = config["server"].rstrip("/")
    poll_interval = max(10, int(config.get("poll_interval") or 30))

    def post(path: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        for attempt in range(2):
            try:
                response = session.post(f"{server}{path}", json=payload, timeout=120)
                if response.status_code in (401, 403):
                    print("Authentication rejected by the master; token may be revoked.")
                    raise SystemExit(1)
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                if attempt == 0:
                    time.sleep(5)
                    continue
                print(f"Request to master failed ({path}): {exc}")
                return None
        return None

    print(f"Satellite running: {config.get('name')} -> {server}")
    while True:
        heartbeat_payload = {
            "platform": sys.platform,
            "version": __version__,
            "subnets": config.get("subnets") or [],
        }
        post("/api/satellite/heartbeat", heartbeat_payload)
        job_response = post("/api/satellite/jobs/next", {})
        job = (job_response or {}).get("job") if job_response else None
        if job:
            job_id = job.get("job_id")
            print(f"Executing job {job_id} ({job.get('scan_type')} {job.get('target')})")
            try:
                payload = execute_job(job)
                result_payload = {"status": "completed", "results": payload}
            except Exception as exc:  # noqa: BLE001 - reported to the master
                print(f"Job {job_id} failed: {exc}")
                result_payload = {"status": "failed", "error": f"{exc.__class__.__name__}: {exc}"[:4000]}
            post(f"/api/satellite/jobs/{job_id}/result", result_payload)
            time.sleep(5)
        else:
            time.sleep(poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnscanner-satellite")
    sub = parser.add_subparsers(dest="command", required=True)
    enroll_parser = sub.add_parser("enroll", help="pair with a master server")
    enroll_parser.add_argument("--server", required=True, help="master URL, e.g. https://scanner.example.com")
    enroll_parser.add_argument("--code", required=True, help="one-time pairing code from the master GUI")
    enroll_parser.add_argument("--name", default="", help="friendly satellite name")
    enroll_parser.add_argument("--subnets", default="", help="comma-separated subnets this satellite can reach")
    enroll_parser.add_argument(
        "--fingerprint",
        default="",
        help="SHA-256 fingerprint of the master certificate to pin (recommended)",
    )
    enroll_parser.add_argument(
        "--ca-cert",
        default="",
        help="PEM file with the master certificate or CA to trust",
    )
    enroll_parser.add_argument(
        "--no-pin",
        action="store_true",
        help="use CA/system trust only and do not pin the observed certificate",
    )
    enroll_parser.add_argument("--insecure", action="store_true", help="disable TLS verification (lab only)")
    enroll_parser.add_argument("--config", default="", help="config file path (default ~/.config/vulnscanner/satellite.json)")
    enroll_parser.set_defaults(func=enroll)
    run_parser = sub.add_parser("run", help="poll the master and execute jobs")
    run_parser.add_argument("--config", default="", help="config file path")
    run_parser.set_defaults(func=lambda a: run(Path(a.config).expanduser() if a.config else default_config_path()))
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
