# VulnScanner

VulnScanner is a local-first vulnerability scanner and management platform. It
stores customers, asset groups, assets, scans, findings and endpoint agents in a
single SQLite database, and it provides a  web interface for running
and reviewing scans.

VulnScanner can scan:

- Websites and web applications (HTTP security checks, exposed files, security
  headers, cookies, forms, and optional active checks).
- Servers and network services (TCP port discovery, service banners, risky
  ports, built-in web checks on discovered HTTP ports, and optional Nmap/NSE
  enrichment).
- Linux and Windows hosts over SSH/WinRM with a high-privilege account
  (patch level, package CVEs, configuration and inventory), in addition to
  unauthenticated network checks.
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
<img width="3433" height="1084" alt="image" src="https://github.com/user-attachments/assets/e7508247-6842-44d4-b1e7-7886436b26cb" />

## Quick start

Requirements: Python 3.11 or newer (the universal lock is tested on 3.11 and
3.14; Ubuntu/Debian also need `python3-venv`), and optionally Git, Nmap, Nuclei,
testssl.sh, Trivy, Subfinder,
Gitleaks, Semgrep and osv-scanner. Authenticated host scans use `paramiko`
(SSH) and `pywinrm` (WinRM), which are installed from the hashed
`requirements.txt` lock.

Linux/macOS:

```bash
./run.sh
```

Windows:

```bat
run.bat
```

The launcher creates `.env` from `.env.example` if it does not exist, creates
`.venv`, installs the hashed runtime dependencies, and starts Uvicorn. Open
<https://127.0.0.1:8765> and accept the self-signed certificate warning on first
use.

The default listener is HTTPS on loopback with a self-signed certificate, which
is suitable for a single-user workstation. The certificate and key are created
under `$VS_DATA_DIR/certs/` (default `./data/certs/`) on first start. Set
`VS_SSL=false` in `.env` for plain HTTP,
for example when a TLS-terminating reverse proxy is in front of the app. For
anything reachable from another machine, use a reverse proxy for production TLS
(see [docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md)).

All application configuration is available from the GUI. **Settings** covers
integration toggles, SMTP and notifications, scan guardrails, tool paths,
credentials, certificates, the subdomain wordlist, advanced runtime options and
security. Listener, HTTPS and scan-worker changes are stored and mirrored to
`.env`; restart with `./run.sh` or `run.bat` to apply them. The dashboard
password is stored as a salted hash in SQLite and applies immediately.

Storage paths are editable under **Settings → Advanced runtime → Storage
location** with a guarded relocation workflow. The credential encryption key is
copied automatically when the data directory changes; rotating the key itself
still requires a planned migration. See [docs/UPGRADING.md](docs/UPGRADING.md)
and [docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md).

If the browser reports `SSL_ERROR_RX_RECORD_TOO_LONG`, you are using `https://`
against a server that is running plain HTTP. Start the server with `./run.sh`
(the default is HTTPS) or browse `http://127.0.0.1:8765` when `VS_SSL=false`.

Manual installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
cp .env.example .env
.venv/bin/python -m app.main
```

The `run.sh`/`run.bat` launchers perform the `.env` and dependency steps
automatically; the manual commands are for custom service managers.

`python -m app.main` honors `VS_SSL`; use `VS_SSL=false .venv/bin/python -m app.main`
for plain HTTP. The API reference is available at
<https://127.0.0.1:8765/api/docs>. The full user manual is at
<https://127.0.0.1:8765/manual> and in
[docs/USER_MANUAL.md](docs/USER_MANUAL.md).

## Optional external tools

VulnScanner works without these tools. They add coverage only; if a tool is
missing, the scan continues with the built-in checks and logs a warning. The
Settings page shows whether each tool is available, its version and its path.
For a service installation, use an absolute `VS_*_PATH` when the service user
cannot see your shell `PATH`.

### Ubuntu and Fedora prerequisites

```bash
# Ubuntu 22.04/24.04
sudo apt update
sudo apt install -y curl git unzip tar nmap python3 python3-venv pipx

# Fedora
sudo dnf install -y curl git unzip tar nmap python3 python3-pip pipx
```

Nmap and Git are now installed. The remaining tools are not in the standard
Ubuntu repositories, so install the official release binaries. The commands
below are the same on Ubuntu and Fedora and use x86_64 packages; replace
`amd64` with `arm64` (and `Linux-64bit` with `Linux-ARM64` for Trivy) on ARM
servers.

```bash
TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"

# Nuclei
NUCLEI_VERSION=3.11.1
curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip -q "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" nuclei
sudo install -m 0755 nuclei /usr/local/bin/nuclei

# Subfinder
SUBFINDER_VERSION=2.17.0
curl -fsSLO "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"
unzip -q "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" subfinder
sudo install -m 0755 subfinder /usr/local/bin/subfinder

# OSV-Scanner
OSV_VERSION=2.3.8
curl -fsSL -o osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64"
sudo install -m 0755 osv-scanner /usr/local/bin/osv-scanner

# Gitleaks
GITLEAKS_VERSION=8.30.0
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
tar xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks
sudo install -m 0755 gitleaks /usr/local/bin/gitleaks

# Trivy
TRIVY_VERSION=0.69.3
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
tar xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy
sudo install -m 0755 trivy /usr/local/bin/trivy
```

Fedora also packages Gitleaks, so `sudo dnf install -y gitleaks` is an
alternative to the binary above.

### testssl.sh

```bash
# Runtime dependencies
# Ubuntu
sudo apt install -y bash openssl procps dnsutils bsdextrautils socat
# Fedora
sudo dnf install -y bash openssl procps-ng bind-utils util-linux socat

# Install the script (both distributions)
sudo git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh
sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

### Semgrep

Semgrep is a Python package. For a service installation, use a dedicated
virtual environment so its dependencies cannot change VulnScanner's own
packages:

```bash
sudo python3 -m venv /opt/semgrep
sudo /opt/semgrep/bin/python -m pip install --upgrade pip semgrep
sudo ln -sf /opt/semgrep/bin/semgrep /usr/local/bin/semgrep
```

If `/usr/local/bin` is not on the service's `PATH`, set
`VS_SEMGREP_PATH=/usr/local/bin/semgrep` in `.env` or the systemd environment
file. For a per-user installation, `pipx install semgrep` is also supported;
set `VS_SEMGREP_PATH` to the absolute path printed by `command -v semgrep` if
the service does not inherit your shell `PATH`.

### Verify and enable

```bash
nmap --version
nuclei -version
testssl.sh --version
trivy --version
subfinder -version
osv-scanner --version
gitleaks version
semgrep --version
git --version

# One-time Nuclei template download
nuclei -update-templates
```

Then open **Settings → Optional command-line tools**, confirm each tool is
detected and enable the integrations you need. Nuclei, Semgrep, Subfinder and
Trivy database updates also require external APIs to be enabled. See the
[user manual](docs/USER_MANUAL.md#2a-installing-optional-external-tools-ubuntu-and-fedora)
for the full integration behaviour and scan options.

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
| Web | `https://example.com` or a hostname | HTTP security headers, cookies, TLS/redirect behaviour, exposed paths, forms, optional active payload checks, optional Nuclei and testssl.sh |
| Network | Hostname, IP address or CIDR (`/30` to `/24` by default) | TCP ports, dangerous services, banners, web checks on discovered HTTP ports, optional Nmap service/version detection and NSE CVEs, optional testssl.sh; optional SSH/WinRM authenticated patch, package-CVE, configuration and inventory checks |
| Local repository | Absolute path on the server | Secrets, dependency manifests/OSV, source review, optional Gitleaks/Semgrep/osv-scanner and Trivy |
| GitHub repository | `https://github.com/owner/repo` or `owner/repo` | Clone plus the same repository checks; private repositories can use a scan-only token |
| Domain | `example.com` | Passive Subfinder enumeration plus local DNS wordlist discovery from an editable SecLists list; discovered hosts are reported, not scanned |
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
  subnet that only the endpoint can reach. Delegated scans are unauthenticated;
  authenticated checks run from the VulnScanner server and never receive
  credentials through an agent.
- Open **Manage** to monitor an agent, review jobs/scans, rename or move it,
  rotate its token and run service commands.
- Use the **Server** page for health checks, database/storage status, queue
  monitoring, runtime toggles, database backups and diagnostics.

See [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md).

## Configuration

`run.sh` and `run.bat` create `.env` from `.env.example` if it is missing and
load it automatically. Explicit process environment variables take precedence
over `.env`. The Settings page is the normal way to change application
configuration; the table below documents the underlying variables and the few
deployment-level values that remain outside the GUI.

| Variable | Default | Purpose |
| --- | --- | --- |
| `VS_ENV_FILE` | `./.env` | Environment file written by the Settings GUI. Service deployments can point this at the systemd `EnvironmentFile` so GUI changes survive restarts. |
| `VS_HOST` | `127.0.0.1` | Bind address. Editable in Settings → Security; stored in SQLite and mirrored to `.env`. Keep loopback unless protected by a firewall/reverse proxy. |
| `VS_PORT` | `8765` | HTTP/HTTPS port. Editable in Settings → Security; stored in SQLite and mirrored to `.env`. |
| `VS_SSL` | `true` | Enable the built-in HTTPS listener with a self-signed certificate under `$VS_DATA_DIR/certs/`. Editable in Settings → Security; stored in SQLite and mirrored to `.env`. |
| `VS_ADMIN_USER` | `admin` | Dashboard administrator username. Editable in Settings → Security. |
| `VS_ADMIN_PASSWORD` | empty | Legacy/initial password fallback. The Settings page stores a salted password hash in SQLite; an environment password is migrated on startup and the plaintext line is removed from the environment file. |
| `VS_SESSION_TTL_HOURS` | `12` | Absolute browser session lifetime (1–168 hours). |
| `VS_SESSION_IDLE_MINUTES` | `30` | Browser session idle timeout (5–1440 minutes). |
| `VS_TRUST_PROXY` | `false` | Trust `X-Forwarded-For`/`X-Forwarded-Proto` from a reverse proxy. Enable only when the app is unreachable except through that proxy. |
| `VS_DATA_DIR` | `./data` | Persistent data root: database, certificates, reports, wordlists, backups and temporary clones. Editable in Settings → Advanced runtime → Storage location. Use an absolute path **outside the Git checkout** for production. |
| `VS_DATABASE` | `$VS_DATA_DIR/vulnscanner.db` | Explicit SQLite database path. Editable in Settings → Advanced runtime → Storage location. |
| `VS_CREDENTIAL_KEY` | generated in `$VS_DATA_DIR/credential.key` | Fernet key for encrypting saved scan credentials and the SMTP password. Back it up with the database. |
| `VS_ENABLE_EXTERNAL_APIS` | `true` | Process-level master switch for OSV.dev, CISA KEV, GitHub, Nuclei, Semgrep, osv-scanner, Subfinder, Trivy database updates and the SecLists download. Editable in Settings → Advanced runtime; restart required. |
| `VS_NMAP_PATH` etc. | empty | Absolute paths for optional CLI tools (`nmap`, `nuclei`, `testssl`, `trivy`, `subfinder`, `osv-scanner`, `gitleaks`, `semgrep`, `git`); empty searches `PATH`. Editable in Settings and stored in SQLite. |
| `VS_SUBFINDER_WORDLIST` | `$VS_DATA_DIR/wordlists/subdomains.txt` | Subdomain wordlist used for local DNS discovery. Editable in Settings → Advanced runtime; files outside the data directory are read-only in the editor. |
| `VS_SECLISTS_SUBDOMAIN_URL` | SecLists `subdomains-top1million-5000.txt` | Source used by **Load SecLists list**. Editable in Settings → Advanced runtime. |
| `VS_MAX_REPO_BYTES` | `536870912` | Maximum cloned repository size. Editable in Settings → Scan guardrails. |
| `VS_MAX_SOURCE_FILE_BYTES` | `1048576` | Maximum file size read by source scanners. Editable in Settings → Scan guardrails. |
| `VS_MAX_SCAN_FILES` | `20000` | Maximum files visited per scan. Editable in Settings → Scan guardrails. |
| `VS_MAX_CIDR_HOSTS` | `256` | Maximum addresses expanded from one CIDR target. Editable in Settings → Scan guardrails. |
| `VS_AGENT_JOB_TIMEOUT` | `3600` | Seconds before a running agent job is marked failed and its scan is closed. Editable in Settings → Scan guardrails. |
| `VS_SCAN_WORKERS` | `4` | Parallel server-side scan workers (1-32). Editable in Settings → Advanced runtime; restart required. |
| `VS_SSH_KNOWN_HOSTS` | empty | Optional known_hosts file. When set, authenticated SSH scans verify the remote host key before sending credentials. Editable in Settings → Advanced runtime. |

## Data, backup and upgrades

Everything is local by default:

- Database: `$VS_DATA_DIR/vulnscanner.db` (SQLite WAL mode; default `data/vulnscanner.db`).
- Credential key: `$VS_DATA_DIR/credential.key` (or `VS_CREDENTIAL_KEY`). A
  restored database needs the same key to decrypt saved credentials.
- Certificates: `$VS_DATA_DIR/certs/`.
- Reports are generated on demand; backups are written to the chosen path or,
  by default, under `$VS_DATA_DIR/reports/backups/`.
- GitHub clones are temporary and removed after the scan.

### Does `git pull` delete scans?

**No.** The database, WAL files, credential key, certificates, `.env` and
backups are ignored by Git. `git pull`, `git checkout` and `git reset --hard`
only touch tracked files.

The dangerous command is:

```bash
git clean -fdx
```

The `-x` flag deletes ignored files, including the entire data directory. A
delete-and-reclone of the project directory does the same. Do not run
`git clean -fdx` against a production checkout.

For production, put data outside the Git checkout:

```bash
VS_DATA_DIR=/var/lib/vulnscanner
VS_DATABASE=/var/lib/vulnscanner/vulnscanner.db
```

Then a code update or a new checkout cannot touch the scans. Back up the whole
data directory — not just the `.db` file — before every update. The database,
`-wal`, `-shm`, `credential.key` and `certs/` belong together; back up `.env`
separately.

Use **Server → Back up database** in the UI for a consistent online copy. The
destination can be an absolute directory or a `.db` file path; leave it empty
to use `$VS_DATA_DIR/reports/backups/`. The database contains the scan history,
customers/assets, agents, credentials, schedules and the Settings-page
configuration, including integration toggles, SMTP, notifications, guardrails,
tool paths, listener/HTTPS choices and a salted admin password hash.
Keep the matching `credential.key`/`VS_CREDENTIAL_KEY` with the backup; it is
still required to decrypt stored target credentials and the SMTP password. The
editable subdomain wordlist and certificates are files under `$VS_DATA_DIR`, not
database rows; back up the data directory if you need them too.

**Server → Restore database** accepts a backup path and offers three modes:

- **Everything** - full database, including settings, agents and credentials.
- **Scan data only** - replaces scan history while keeping the current settings,
  agents and credentials. Customers, groups and assets are merged by name.
- **Settings only** - restores settings without changing scans.

A safety backup is written before every restore. Active scans must be cancelled
or finished first. Restores are validated with SQLite's integrity and
foreign-key checks and roll back on failure. Older backups are upgraded in a
temporary copy before restore, and a backup that predates newer optional tables
is accepted; those tables are restored empty. A backup from a newer schema is
rejected rather than silently downgraded. The GUI can inspect a backup before
restoring it. See [docs/UPGRADING.md](docs/UPGRADING.md) for the safe update and
rollback procedure, and
[docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md) for
deployment hardening.

`scripts/update.sh` performs a backup and a `git pull --ff-only`; it never runs
`git clean` or deletes the data directory.

### Database and data-directory relocation

**Settings → Advanced runtime → Storage location** can validate and relocate the
live SQLite database and data directory without editing files. The workflow:

1. Validates that the target paths are absolute, writable and safe.
2. Writes a safety backup of the current database.
3. Copies the database with SQLite's online backup API and verifies its
   integrity.
4. Copies `credential.key`, certificates, wordlists, reports and backups when
   requested.
5. Updates `VS_DATA_DIR` and `VS_DATABASE` in `VS_ENV_FILE` and switches the
   running process to the new database.
6. Leaves the old location untouched.

Restart VulnScanner afterwards so certificate paths and the launcher are fully
consistent. Relocation is refused while scans are active unless explicitly
forced, and an existing target database is only replaced when overwrite is
confirmed.

## Security

- The default bind address is `127.0.0.1`.
- Set a dashboard password in **Settings → Security** (stored as a salted
  PBKDF2 hash in SQLite) or with `VS_ADMIN_PASSWORD` before exposing the
  service beyond localhost.
- Browsers use a session cookie with `HttpOnly`, `SameSite=Strict` and a secure
  flag on HTTPS. Session tokens are stored as SHA-256 hashes; the absolute
  lifetime and idle timeout are configurable.
- **Authenticator MFA** (TOTP, RFC 6238) is available under **Settings →
  Security**. Enrolment displays a manual setup key and `otpauth://` URI, then
  ten one-time recovery codes. MFA is enforced for browser sessions and for
  Basic-auth API clients, which must send `X-VS-MFA` (TOTP) or
  `X-VS-Recovery-Code`.
- State-changing cookie-authenticated requests require an `X-CSRF-Token`
  header. Login attempts are rate-limited per source IP and per username.
- **Audit trail** records authentication, configuration, maintenance and every
  mutating API request. The Audit page supports filtering and CSV export.
- Agent tokens are stored as SHA-256 hashes. Enrolment tokens are one-time and
  expire.
- Saved target credentials are encrypted with Fernet and never returned by the
  API. Each host receives at most one authentication attempt per scan to reduce
  account-lockout risk.
- Webhook and SecLists URLs are SSRF-validated. Loopback, RFC1918, link-local,
  multicast and reserved destinations are rejected unless the administrator
  explicitly enables private-network outbound URLs.
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
- [Dependency and supply-chain policy](docs/DEPENDENCIES.md)
- [Upgrading safely](docs/UPGRADING.md)
- [Security and deployment](docs/SECURITY_AND_DEPLOYMENT.md)
- [Authorised use](docs/AUTHORIZED_USE.md)
- [Integrations](docs/INTEGRATIONS.md)

## Dependency locking and supply chain

Dependency versions are locked for reproducible installs:

- `pyproject.toml` is the human-edited source of truth.
- `uv.lock` is the universal lock for Linux, Windows and Python 3.11+.
- `requirements.txt` is the generated runtime lock with SHA-256 hashes.
- `requirements-dev.txt` is the generated runtime + test lock.

The launchers install with `pip install --require-hashes -r requirements.txt`,
so a modified or unexpected package artifact is rejected. Do not edit the
generated requirements files directly.

Install `uv` 0.13 or newer for dependency maintenance. Then:

```bash
# Developer environment
uv sync --frozen --no-install-project --group dev

# Regenerate after changing pyproject.toml
./scripts/lock-dependencies.sh

# CI check: lock and generated files must be current
./scripts/check-dependencies.sh
```

Run a vulnerability audit (`pip-audit` or OSV) against the lock on every change
and on a scheduled basis. See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for
the update, hash-pinning, mirror and air-gap procedures.

The GitHub Actions workflow in `.github/workflows/ci.yml` runs the test suite on
Python 3.11 and 3.14, verifies the generated dependency locks, runs Ruff and
Bandit, and checks that the application compiles.

## Inventory and finding history

Network scans populate the **Inventory** page with discovered hosts, open ports,
device-type/OS hints and first/last-seen timestamps. Per-asset finding history is
recorded for every scan that has an asset, and network scans without an asset
link discovered hosts to automatically created inventory assets. Open an
inventory row to review that asset's history and finding trend.

## Development and tests

```bash
uv sync --frozen --no-install-project --group dev
.venv/bin/python -m pytest -q
```

Tests run offline (`VS_ENABLE_EXTERNAL_APIS=false`), use a temporary database,
and do not start background scan workers. The CI workflow is the authoritative
validation gate; run the same commands locally before pushing:

```bash
uv run pytest -q
uv run ruff check app tests agent
uv run bandit -q -r app agent/vulnscanner_agent.py
```
