# VulnScanner

VulnScanner is a local-first vulnerability scanner and management platform. It
stores customers, asset groups, assets, scans, findings and endpoint agents in a
single SQLite database, and it provides a Nessus-style web interface for running
and reviewing scans.

VulnScanner can scan:

- Websites and web applications (HTTP security checks, exposed files, security
  headers, cookies, forms, and optional active checks).
- Servers and network services (TCP port discovery, service banners, risky
  ports, and optional Nmap/NSE enrichment).
- Local source repositories and GitHub repositories (secrets, dependency
  vulnerabilities, source-code review, optional Gitleaks/Semgrep/osv-scanner/Nuclei).
- Linux and Windows endpoints through an outbound-polling agent.
- Active Directory configuration from a read-only JSON report produced by the
  bundled PowerShell collector or the Windows agent.

It is designed for a single analyst workstation or a small authorised team. It
does not require a separate database server, a Node.js build step, or any
inbound firewall rules on scanned endpoints.

> **Authorised use only.** Only scan systems you own or have explicit written
> permission to test. See [AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md).

## Quick start

Requirements: Python 3.11 or newer (3.14 is used by the project virtual
environment), and optionally Git, Nmap, Nuclei, Gitleaks, Semgrep and
osv-scanner.

Linux/macOS:

```bash
cp .env.example .env
./run.sh
```

Windows:

```bat
copy .env.example .env
run.bat
```

The launcher creates `.venv`, installs the runtime dependencies, and starts
Uvicorn. Open <http://127.0.0.1:8765>.

Manual installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

The API reference is available at <http://127.0.0.1:8765/api/docs>. The full
user manual is at <http://127.0.0.1:8765/manual> and in
[docs/USER_MANUAL.md](docs/USER_MANUAL.md).

## First scan

1. Open **Customers**, create a customer, and add a group such as `webserver`.
2. Add an asset in that group, for example a website URL or a hostname.
3. Open **Scans**, choose **New scan**, select the customer/group/asset and the
   scan type, then start the scan.
4. Open the scan to follow progress, review findings, change finding status, and
   export JSON, CSV or a printable HTML report.

Scans run in background worker threads, up to `VS_SCAN_WORKERS` at the same
time (default 4). You can leave the page and return later; all results are
persisted in SQLite.

## Scan types

| Type | Target | Main checks |
| --- | --- | --- |
| Web | `https://example.com` or a hostname | HTTP security headers, cookies, TLS/redirect behaviour, exposed paths, forms, optional active payload checks, optional Nuclei |
| Network | Hostname, IP address or CIDR (`/30` to `/24` by default) | TCP ports, dangerous services, banners, optional Nmap service/version detection and NSE CVEs |
| Local repository | Absolute path on the server | Secrets, dependency manifests/OSV, source review, optional Gitleaks/Semgrep/osv-scanner |
| GitHub repository | `https://github.com/owner/repo` or `owner/repo` | Clone plus the same repository checks; private repositories can use a scan-only token |
| Active Directory | JSON report path or import API | Guest account, password policy, lockout, krbtgt age, delegation, Kerberoasting, AS-REP roasting, stale accounts, privileged groups, AdminCount, machine account quota, recycle bin, functional level |

Optional CLI tools never replace the built-in checks. If a tool is absent, the
scan continues with the built-in engine and records a log message.

## Endpoint agents

Agents enrol with a one-time token and then poll the server over outbound
HTTP(S), so no inbound firewall port is needed. They collect endpoint checks and
can run delegated network scans from their own network position.

Windows has two supported agents:

- `VulnScannerAgent.ps1` - native PowerShell agent for Windows client and server
  editions. No Python required. Install with `install-windows-agent.ps1`
  (auto-restarting scheduled task, interactive or `-Configure` post-install
  configuration).
- `vulnscanner_agent.py` - the Python agent used on Linux/macOS and by existing
  Windows deployments. Install with `install-linux.sh` or
  `install-windows.ps1`.

Typical use:

- Create an enrolment token on the **Agents** page.
- Install on Linux with `install-linux.sh` (systemd, dedicated service account by
  default).
- Install on Windows with `install-windows-agent.ps1` (recommended) or
  `install-windows.ps1` for the Python agent.
- Start a scan from **Agents**: system baseline, packages, listening ports,
  selected-path secrets/repository inventory, a network scan from the agent, and
  on Windows, Active Directory.
- When starting a network scan, choose an agent under **Run from** to scan a
  subnet that only the endpoint can reach.
- Open **Manage** to monitor an agent, review jobs/scans, rename or move it,
  rotate its token and run service commands.
- Use the **Server** page for health checks, database/storage status, queue
  monitoring, runtime toggles, database backups and diagnostics.

See [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md).

## Configuration

Copy `.env.example` to `.env`. `run.sh` and `run.bat` load it automatically.
Environment variables can also be exported directly.

| Variable | Default | Purpose |
| --- | --- | --- |
| `VS_HOST` | `127.0.0.1` | Bind address. Keep loopback unless protected by a firewall/reverse proxy. |
| `VS_PORT` | `8765` | HTTP port. |
| `VS_ADMIN_USER` | `admin` | HTTP Basic auth username. |
| `VS_ADMIN_PASSWORD` | empty | Enables HTTP Basic auth for the dashboard and API when set. |
| `VS_DATA_DIR` | `./data` | Database, reports and temporary clone directory. |
| `VS_DATABASE` | `$VS_DATA_DIR/vulnscanner.db` | Explicit SQLite database path. |
| `VS_ENABLE_EXTERNAL_APIS` | `true` | Allow OSV.dev, CISA KEV, GitHub, Nuclei, Semgrep and osv-scanner outbound calls. |
| `VS_NMAP_PATH` etc. | empty | Absolute paths for optional CLI tools; empty searches `PATH`. |
| `VS_MAX_REPO_BYTES` | `536870912` | Maximum cloned repository size. |
| `VS_MAX_SOURCE_FILE_BYTES` | `1048576` | Maximum file size read by source scanners. |
| `VS_MAX_SCAN_FILES` | `20000` | Maximum files visited per scan. |
| `VS_MAX_CIDR_HOSTS` | `256` | Maximum addresses expanded from one CIDR target. |
| `VS_AGENT_JOB_TIMEOUT` | `3600` | Seconds before an agent job is considered stale. |
| `VS_SCAN_WORKERS` | `4` | Parallel server-side scan workers (1-32). Requires a restart. |

## Data and backup

Everything is local by default:

- Database: `data/vulnscanner.db` (SQLite WAL mode).
- Reports are generated on demand; no external report service is used.
- GitHub clones are temporary and removed after the scan.

Stop the server before copying the database, or use **Server → Back up
database** in the UI for a consistent online copy under
`data/reports/backups/`. You can also copy the database plus its `-wal` and
`-shm` files while the server is stopped. See
[docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md).

## Security

- The default bind address is `127.0.0.1`.
- Set `VS_ADMIN_PASSWORD` before exposing the service beyond localhost.
- Agent tokens are stored as SHA-256 hashes. Enrolment tokens are one-time and
  expire.
- Findings retain acknowledgement, false-positive and accepted status across
  rescans of the same asset.
- Active Directory collection is read-only and never modifies directory
  objects.

Read [docs/AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md) and
[docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md) before
scanning a production network.

## Documentation

- [User manual](docs/USER_MANUAL.md)
- [Agent guide](docs/AGENT_GUIDE.md)
- [API reference](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security and deployment](docs/SECURITY_AND_DEPLOYMENT.md)
- [Authorised use](docs/AUTHORIZED_USE.md)
- [Integrations](docs/INTEGRATIONS.md)

## Development and tests

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Tests run offline (`VS_ENABLE_EXTERNAL_APIS=false`), use a temporary database,
and do not start background scan workers.
