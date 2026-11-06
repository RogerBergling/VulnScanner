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
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import requests

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
    response = requests.post(
        f"{args.server.rstrip('/')}/api/satellite/pair",
        json=payload,
        timeout=60,
        verify=not args.insecure,
        headers={"User-Agent": f"VulnScanner-satellite/{__version__}"},
    )
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
    except OSError:
        pass
    config = {
        "server": args.server.rstrip("/"),
        "satellite_id": data["satellite_id"],
        "token": data["token"],
        "name": args.name or local_hostname(),
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "ca_path": str(ca_path),
        "verify_tls": not args.insecure,
        "poll_interval": 30,
        "subnets": payload.get("subnets", []),
    }
    save_config(config_path, config)
    print(f"Satellite {config['satellite_id']} enrolled with {config['server']}")
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
    if config.get("ca_path") and Path(config["ca_path"]).is_file() and config.get("verify_tls", True):
        session.verify = config["ca_path"]
    return session


def run(config_path: Path) -> None:
    config = load_config(config_path)
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
