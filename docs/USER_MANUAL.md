# VulnScanner User Manual

This manual describes day-to-day operation of the VulnScanner web interface and
the behaviour of each scan type. Read [AUTHORIZED_USE.md](AUTHORIZED_USE.md)
before running any scan.

## 1. Purpose and scope

VulnScanner is a local-first vulnerability management application. It is
intended for:

- Authorised security assessments of systems you own.
- Internal asset inventories and repeatable configuration reviews.
- Tracking remediation of findings over time.
- Collecting endpoint and Active Directory information without deploying an
  inbound listener on every host.

It is not a hosted service, an exploit framework, a password cracker, or a
replacement for a qualified penetration tester. It does not authenticate to
targets, brute force credentials, or modify scanned systems. Active Directory
collection is read-only.

## 2. Starting and stopping

### Linux and macOS

```bash
cp .env.example .env
./run.sh
```

`run.sh` creates `.venv`, installs `requirements.txt` when needed, loads `.env`
and starts Uvicorn on `VS_HOST:VS_PORT` using HTTPS by default with a
self-signed certificate. Set `VS_SSL=false` in `.env` for plain HTTP, for
example when a TLS-terminating reverse proxy is in front of the app.

### Windows

```bat
copy .env.example .env
run.bat
```

### Manual start

```bash
.venv/bin/python -m app.main
```

Use `VS_SSL=false .venv/bin/python -m app.main` for plain HTTP. Starting
`uvicorn app.main:app` directly bypasses the `VS_SSL` handling; pass
`--ssl-certfile` and `--ssl-keyfile` yourself if you start Uvicorn that way.

If the browser reports `SSL_ERROR_RX_RECORD_TOO_LONG`, you are using `https://`
against a plain HTTP listener. Start with `./run.sh` (HTTPS by default) or use
`http://` when `VS_SSL=false`.

Stop the server with `Ctrl+C`. Background scans are marked as interrupted on
the next start; restart the affected scans from the scan page.

### First login

If `VS_ADMIN_PASSWORD` is empty, no login is required. This is convenient on a
single-user workstation bound to `127.0.0.1`, but it is not safe on a shared
network. Set a password from **Settings → Security** (saved to `.env` and
applied immediately) or in `.env`, and preferably place the service behind a TLS
reverse proxy before remote use. The default local listener uses HTTPS with a
self-signed certificate, so browsers will warn; set `VS_SSL=false` to use HTTP
on loopback instead.

## 3. Interface tour

The left navigation contains:

- **Dashboard** - risk score, severity totals, recent scans, top findings and a
  14-day trend.
- **Customers** - customers, groups and assets.
- **Scans** - scan list, new scan dialog, scan detail, findings, reports.
- **Agents** - endpoint enrolment, per-agent monitoring/configuration, token
  rotation and agent-started scans.
- **Active Directory** - import a read-only AD JSON report and review AD risk.
- **Server** - service health, uptime, database/storage status, scan queue,
  runtime configuration, backups and diagnostics.
- **Settings** - external API/tool status, database information, KEV catalogue.
- **Help** - this manual rendered inside the application.

The header shows the active-scan indicator, a global search shortcut on the scan
page, and a theme control. The interface is a single-page application with hash
routes; reloading a route is safe.

## 4. Customers, groups and assets

### Customers

A customer is the top-level ownership boundary. Creating a customer also creates
a default group named **General**. Customer names are case-insensitive and
unique.

Deleting a customer deletes its groups, assets, agents and scans, and all
findings belonging to those scans. Export anything you need first.

### Groups

Groups organise assets under a customer, for example:

- `webserver`
- `database`
- `workstations`
- `domain-controllers`
- `branch-office`

Group names are unique within a customer. Every asset belongs to exactly one
group.

### Assets

An asset records the thing being assessed. The asset kind is descriptive and
does not restrict scan types, but it controls the default identifier copied into
the scan dialog.

Common identifiers:

| Kind | Example identifier |
| --- | --- |
| Web | `https://www.example.com` |
| Host | `web01.example.com` or `192.0.2.10` |
| Repo | `/srv/src/payments` |
| GitHub | `https://github.com/example/payments` |
| Domain | `corp.example.com` |
| Agent | assigned automatically at enrolment |

The asset detail page shows recent scans, the latest completed scan's findings,
and metadata such as owner, environment, platform or last agent heartbeat.

### Ad-hoc scans

You can start a scan without creating an asset. The scan is still associated
with the selected customer and group. Findings from ad-hoc scans are not linked
to an asset, so finding-status carry-over across rescans does not apply. Use an
asset when you want durable tracking.

## 5. Running scans

Open **Scans -> New scan**. Choose a customer, optionally a group and asset, a
scan type, a target, and type-specific options. Only authorised targets should
be entered.

Server-side scans run concurrently up to `VS_SCAN_WORKERS` (default 4, range
1-32). Additional scans wait in the queue. Agent jobs are not limited by that
pool; each agent claims one job at a time.

Progress, stage and a timestamped event log are shown on the scan page. Scans
can be cancelled while queued or running. Cancelling a running built-in scan
saves partial findings where the engine has already produced them. A cancelled
queued scan is closed immediately. A scan that is still queued can be deleted;
cancel it first if it is active.

Rescan creates a new scan with the same target and options. It does not reuse
the old result. Finding status is propagated by fingerprint when the scan is
attached to the same asset.

### 5.1 Web scan

Target forms:

- `https://example.com`
- `http://example.com:8080/app`
- `example.com` (normalised to `https://example.com`)

Checks include, where applicable:

- HTTP status, redirects, TLS-related observations and response headers.
- Missing or weak security headers (HSTS, CSP, frame options, content type
  options, referrer policy, permissions policy).
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`) and cookie scope.
- Information disclosure such as server banners, stack traces, directory
  listings and common sensitive files.
- HTML forms and link/parameter inventory.
- Mixed content and insecure transport references.
- Reflected input and other non-destructive active checks when **Active checks**
  is enabled.
- Optional Nuclei templates when **External tools** is enabled and Nuclei is
  installed.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| Active checks | on | Send a small number of non-destructive test requests. Disable for a purely passive review. |
| External tools | off | Run Nuclei if installed and allowed in Settings. |

Web scanning does not log in, submit destructive forms, brute force, or exploit
SQL injection/XSS. It reports indicators that require manual validation.

### 5.2 Network scan

Targets:

- Hostname or IP: `web01.example.com`, `192.0.2.10`
- CIDR: `192.0.2.0/30` (up to `VS_MAX_CIDR_HOSTS`, default 256 addresses)
- IPv6 literals are accepted where the network stack supports them.

The built-in engine performs TCP connect checks against a configured port list
and reads service banners. It flags risky exposed services such as Redis,
MongoDB, Elasticsearch, SMB, RDP, Telnet, VNC, unauthenticated Docker API and
database ports.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| Run from | VulnScanner server | Run on the server, or delegate to an enrolled agent from its network position. |
| Port profile | `common` | `common`, `web`, `top1000` or `all` (1-10000). |
| Ports | profile | Explicit list/ranges, for example `22,80,443,8000-8100`. Overrides the profile. |
| Connect timeout | 0.45 s | Per-port TCP connect timeout, clamped to 0.1-3.0 s. |
| External tools | off | Run Nmap service/version detection if installed (server-side scans only). |
| NSE vulners | off | With external tools, run the Nmap `vulners` script (server-side scans only). |

Port ranges are limited to 5000 ports per range and the UI/API validate the
input. A network scan creates an informational finding for each open service
and higher-severity findings for dangerous exposures.

**Run from an agent** delegates the scan to an endpoint. Choose an agent in
**Run from** when starting a network scan, or use **Scan now** on the agent
detail page. The scan is queued as `waiting_agent` and an online agent starts it
on its next poll; an offline agent holds it until it reconnects. Delegated scans
use TCP connect probes from the endpoint and do not run Nmap. The agent must
belong to the selected customer/group and advertise the `network` module. This
is useful for private subnets that the VulnScanner server cannot reach.

### 5.3 Authenticated host checks

Unauthenticated scans only see exposed ports. An authenticated scan logs in with a
high-privilege account to inventory the host and report missing patches,
vulnerable packages and insecure configuration. Windows uses WinRM (pywinrm) and
Linux uses SSH (paramiko).

**Configure credentials before scanning.** Open **Settings -> Target
credentials** and choose **Add credential**:

| Field | Notes |
| --- | --- |
| Name | A label such as `Linux server admin`. |
| Operating system | Linux (SSH) or Windows (WinRM). |
| Username | The scan account. Use a dedicated, least-privilege account. |
| Account type | Windows only: **Local account** or **Domain account**. |
| Domain | Windows domain accounts, for example `CORP`. |
| Scope | Global (all customers) or one customer. |
| Password or SSH key | Linux accepts a password or a private key and optional passphrase. Windows requires a password. |
| Default | Use this credential when no asset binding or per-scan credential applies. |

Credentials are encrypted at rest with a key in `VS_CREDENTIAL_KEY` or
`data/credential.key`. Back up that key with the database; without it, saved
credentials cannot be decrypted. The API and scan logs never show the password,
private key or passphrase. Delete or rotate a credential from the same page if an
account changes.

**Scope a credential to an asset.** Edit an asset and choose a **Linux scan
credential** and/or **Windows scan credential**. Resolution for each host is:

1. Per-scan credential entered in the scan dialog.
2. Credential bound to the asset.
3. Customer default for the host operating system.
4. Global default for the host operating system.

**Start the scan.** In a network scan, enable **Authenticated checks**, choose
**Target operating system** (`Auto-detect`, `Linux` or `Windows`) and the maximum
number of hosts to authenticate. Leave the per-scan Linux/Windows fields blank to
use saved credentials, or enter an account to override them for this scan only.
Per-scan secrets are stored encrypted with the scan and are not reused by later
scans unless you use **Rescan**.

Windows accounts:

- **Local account**: a local administrator on each target, for example
  `Administrator`. Set **Account type** to Local.
- **Domain account**: a domain account with local administrator rights on the
  targets, for example `CORP\svc-vulnscan`. Set **Account type** to Domain and
  enter the domain. The account is sent as `DOMAIN\username`.

Requirements on the targets:

- **Windows**: WinRM enabled, port 5985 (HTTP) or 5986 (HTTPS), and the account in
  the local Administrators group. For domain accounts, use a tiered
  administration model rather than Domain Admin everywhere. HTTPS with a trusted
  certificate is recommended; enable **Use HTTPS** and **Verify TLS** in the scan
  options when available.
- **Linux**: SSH reachable, an account with `sudo` rights, and either a password
  or a key. Password authentication and non-interactive `sudo` must be permitted
  for the collector to read protected files and package state.

**Lockout protection.** Each host receives at most one authentication attempt per
scan. The scanner never retries with the same or a different credential, so a
wrong password cannot walk an account through a lockout threshold. A failed
attempt produces a `host` finding that names the host and protocol without
including the secret, and the scan continues with the next host. If a scan hits a
lockout policy, stop it, fix the credential, and start a new scan.

What authenticated scans report:

- **Patch and version level**: Linux distribution end-of-life, pending package
  updates, reboot-required state and kernel version. Windows end-of-support,
  installed hotfix age, and missing update inventory.
- **Package CVEs**: Linux packages are checked against OSV.dev when external APIs
  are enabled. Windows software inventory is checked for known end-of-life
  products such as unsupported Flash, Java, browsers and Office versions.
- **Configuration**: SSH root login, password authentication, empty passwords,
  firewall state, risky listening services, UID 0 accounts, world-writable
  critical files and password policy for Linux; Defender, firewall profiles,
  SMBv1 and SMB signing, RDP/NLA, UAC, autologon, AlwaysInstallElevated,
  PowerShell logging, unquoted service paths, WinRM transport and local
  administrators for Windows.
- **Inventory**: host OS, build, install date, hotfixes, software, users, open
  ports and services, shown in the scan metadata and findings.

An authenticated scan is only available from the VulnScanner server. A delegated
agent scan never receives credentials and performs unauthenticated TCP/web checks
from the agent's network position. To scan a private subnet that only an agent can
reach, run an unauthenticated agent scan; run authenticated scans from a server
that can reach the management ports.

### 5.4 Local repository scan

The target is an absolute path on the VulnScanner server, for example
`/srv/src/payments`. Relative paths are resolved from the server process working
directory; prefer absolute paths.

Checks:

- **Secrets** - private keys, cloud keys, API tokens, database URLs and generic
  credential assignments, with placeholder filtering. `.env` files are flagged.
  Optional Gitleaks runs when external tools are enabled.
- **Dependencies** - package manifests and lockfiles across npm, Python, Go,
  Rust, PHP, Ruby, Java/Maven/Gradle and NuGet. Exact versions are checked
  against OSV.dev when external APIs are enabled. Optional `osv-scanner` runs
  when external tools are enabled.
- **Source review** - risky patterns such as debug mode, permissive CORS,
  disabled TLS verification, weak cryptography, command execution and unsafe
  deserialization. Optional Semgrep runs when external tools are enabled; it
  fetches rules from the Semgrep registry and requires external APIs.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| Secrets | on | Scan for credentials and committed environment files. |
| Dependencies | on | Parse manifests and match known vulnerabilities. |
| Source review | on | Run built-in source heuristics. |
| Git history | off | Clone full Git history for GitHub; otherwise shallow clone. |
| External tools | off | Allow Gitleaks, Semgrep and osv-scanner and other CLI integrations. |

### 5.5 GitHub repository scan

Targets:

- `https://github.com/owner/repo`
- `https://github.com/owner/repo.git`
- `owner/repo` (normalised to GitHub HTTPS)

Git must be installed. Public repositories need no token. For private
repositories, enter a read-only token in the scan dialog. The token is used only
for that clone and is never written to the database. The temporary clone is
removed after the scan, including on failure.

The clone is shallow by default. Enable **Git history** to fetch more history
(and potentially detect more secrets in past commits, at the cost of time and
disk). Repository size is limited by `VS_MAX_REPO_BYTES`.

GitHub scans require outbound network access to GitHub and a token with the
minimum read permission.

### 5.6 Active Directory scan/import

Two supported paths:

1. Run `ad_audit.ps1` on a domain-joined Windows management host with RSAT, then
   import the JSON on the **Active Directory** page.
2. Run an **ad** module scan from a Windows agent, or import a report through
   the API.

The report is read-only. Checks include:

- Guest account enabled.
- Minimum password length and complexity.
- Account lockout threshold.
- Maximum password age.
- krbtgt password age.
- Unconstrained delegation.
- Kerberoastable and AS-REP roastable accounts.
- Stale users and computers.
- Passwords that never expire.
- AdminCount set on non-privileged users.
- Membership of privileged groups.
- Machine account quota.
- Recycle Bin state.
- Domain functional level.
- Custom findings supplied by the collector.

Provider-specific collectors such as PingCastle or Purple Knight can be adapted
to the documented JSON shape. VulnScanner does not modify AD objects and does
not perform LDAP writes.

## 6. Findings

Each finding contains:

- Severity (`critical`, `high`, `medium`, `low`, `info`).
- Title, category, description, evidence and remediation.
- Optional CVE, CWE and CVSS.
- Location and resource.
- A stable fingerprint used for deduplication and status carry-over.
- Raw data for troubleshooting and integrations.

### Status values

| Status | Meaning |
| --- | --- |
| `open` | Not yet reviewed. |
| `acknowledged` | Seen and assigned for remediation. |
| `false_positive` | Not a real issue; hidden from the top-findings risk view. |
| `accepted` | Risk accepted with a documented decision. |
| `fixed` | Remediated or no longer present. |

Status is stored per finding row. When a later scan on the same asset produces
the same fingerprint, the status and original `first_seen` timestamp are carried
forward. The new scan still records its own row and `last_seen`.

### Filtering

The scan page filters by severity and status. The API also supports category
filtering. The dashboard excludes `false_positive` findings from the top-risk
list and counts only the latest completed scan per asset for severity totals.

### Risk score

The dashboard risk score is derived from severity counts with weighting toward
critical/high findings. It is a prioritisation aid, not a certified CVSS score.
Always validate findings and apply business context.

## 7. Reports and exports

From a completed scan you can export:

- **HTML** - standalone printable report, opened in a new tab.
- **JSON** - machine-readable scan, findings and context.
- **CSV** - spreadsheet-friendly finding rows.

Exports are generated on demand. The scan page links to HTML; the API accepts
`?format=json`, `?format=csv` or no format for HTML.

## 8. Agents

The **Agents** page shows enrolled agents, online state, platform, last seen,
customer/group, scan count and queued jobs.

Typical flow:

1. Create an enrolment token for a customer/group and agent name.
2. Copy the generated Linux, Windows installer or Python agent command, or use
   the download links at the top of the Agents page.
3. Enrol the endpoint. The token is single-use and expires.
4. The agent appears in the list. Its asset is created automatically in the
   selected group.
5. Select **Scan** and choose modules, or open **Manage** for the agent detail
   page.

### Installing on Windows

Windows clients and servers can use the native PowerShell agent, which does not
require Python. Run the installer in an elevated PowerShell:

```powershell
Invoke-WebRequest -UseBasicParsing `
  https://scanner.example.com/agent/install-windows-agent.ps1 `
  -OutFile install-windows-agent.ps1
.\install-windows-agent.ps1 `
  -Server https://scanner.example.com `
  -Token vs_enroll_...
```

With no arguments the installer prompts for the server, token, agent name, TLS
verification and poll interval. It installs to `%ProgramFiles%\VulnScanner
Agent`, stores configuration in `%ProgramData%\VulnScanner Agent`, and registers
the **VulnScanner Agent** scheduled task. Reconfigure an existing installation
without reinstalling:

```powershell
.\install-windows-agent.ps1 -Configure -Server https://scanner.example.com -PollInterval 60
.\install-windows-agent.ps1 -Configure -Insecure          # lab/self-signed only
.\install-windows-agent.ps1 -Configure -VerifyTls
.\install-windows-agent.ps1 -Configure -Token vs_agent_... # rotated token
.\install-windows-agent.ps1 -Configure -EnrollAgain -Server ... -Token vs_enroll_...
```

Use `-ServiceAccount` to run the task under a dedicated account instead of
SYSTEM during installation; a custom user account prompts for its password.
Existing Python-based Windows installations can continue to use
`install-windows.ps1`. See [AGENT_GUIDE.md](AGENT_GUIDE.md) for all installer
options.

### Monitoring and configuring an agent

Select **Manage**, or the agent name, to open the agent detail page. It shows:

- Online/offline state, last contact, last IP, hostname, platform and agent
  version.
- Customer, group and linked asset.
- Capabilities reported by the latest heartbeat.
- Queued, running and failed jobs, recent scan jobs and findings.
- Recent scans with their severity summary.
- Status, restart and log commands for the native Windows agent and Python
  agent.

The page actions are:

- **Configure** - rename the agent and move it to another customer/group. The
  linked asset moves with it; historical scans keep their original placement.
- **Rotate token** - replace the agent credential. The old token stops working
  immediately. Copy the generated Linux, Windows installer or Python agent
  command, run it on the endpoint as the service account/Administrator, then
  restart the agent service/task. The new token is shown once.
- **Scan now** - queue a module scan. Jobs wait safely if the agent is offline.
  Selecting the `network` module lets you scan from the endpoint's network
  position; network jobs cannot be combined with other modules.
- **Revoke** - invalidate the token and cancel queued jobs.

Agent modules:

| Module | What it collects |
| --- | --- |
| `system` | OS, hardware, patch/update state, firewall, antivirus, disk encryption, local account and service configuration, platform-specific baseline checks. |
| `packages` | Installed OS packages plus Python/npm/Windows program inventory, matched against OSV. Python agent only. |
| `ports` | Listening TCP/UDP sockets and bind addresses. |
| `network` | TCP connect scan of a host, IP or CIDR from the agent's network position. |
| `secrets` | Secret patterns in selected local paths. Requires at least one path. Python agent only. |
| `repo` | Manifest inventory from selected local paths. Requires at least one path. Python agent only. |
| `ad` | Read-only AD collection on Windows. Requires a Windows agent and the `ad_audit.ps1` collector. |

The native Windows agent advertises `system`, `ports`, `network` and `ad` (when
the collector is installed). The Python agent adds `packages`, `secrets` and
`repo`. The scan dialog disables modules the selected agent did not report in
its latest heartbeat.

Agent results return over outbound HTTPS. An agent can be revoked; revoked
tokens cannot authenticate, queued jobs are cancelled, and waiting scans are
closed. A revocation does not delete historical findings.

See [AGENT_GUIDE.md](AGENT_GUIDE.md) for installation, configuration, proxy/TLS
and uninstall details.

## 9. Settings

The Settings page shows:

- Product version and external API availability.
- Toggles for external APIs, Nuclei and Nmap.
- Optional tool installation status and versions.
- KEV catalogue count and last sync time.
- **Target credentials** for authenticated network scans, with encrypted
  passwords/SSH keys, customer/global scope and default flags.
- Database path, size and reports path.
- Scan limits, including the configured parallel worker count
  (`VS_SCAN_WORKERS`).

Disabling **Allow external APIs** prevents outbound OSV/KEV/GitHub activity
and the Nuclei, Semgrep and osv-scanner integrations, and is appropriate for
air-gapped installations. Built-in checks still run. Disabling Nuclei or Nmap
prevents those tools from being invoked even when installed.
Settings are stored in SQLite and survive restarts.

The CISA KEV catalogue can be synchronised from Settings. Synchronisation is
optional; known-exploited enrichment is skipped if the catalogue is empty or
external APIs are disabled.

### Server monitoring and maintenance

The **Server** page reports the health of the local instance:

- Uptime, version, process ID, Python version, bind address and dashboard auth
  state.
- Database integrity, journal mode, schema version, WAL size, free pages, file
  size and path.
- Disk usage for the data directory and report file counts.
- Scan queue and agent job counts, plus the configured parallel scan worker
  count.
- Health checks for the database, data/report directories, authentication,
  scan workers and external API mode.
- Optional tool availability and versions.
- The same runtime integration toggles as Settings.

Maintenance actions:

- **Back up database** creates a consistent SQLite copy under
  `data/reports/backups/` and records the last backup time.
- **Compact database** runs `VACUUM` to reclaim free pages. This can briefly
  pause scans; run it when the queue is idle.
- **Download diagnostics** saves a JSON snapshot of the status page for
  troubleshooting. It does not include findings, tokens or scan evidence.

Bind address, authentication, paths and `VS_SCAN_WORKERS` are environment
settings and require a service restart. Use the Settings page for integration
toggles.

## 10. Data lifecycle

- Scans and findings remain until deleted with the scan, asset, group or
  customer.
- Deleting a scan deletes its findings and events. Delete completed, failed or
  cancelled scans only.
- Agent revocation preserves history.
- OSV responses and the KEV catalogue are cached in SQLite.
- Saved target credentials are encrypted with `VS_CREDENTIAL_KEY` or
  `data/credential.key`. Back up the key with the database; a database restored
  without the matching key has unreadable credentials and they must be re-entered.
  Per-scan credentials are deleted with the scan.
- Temporary GitHub clones are removed after the scan.
- Reports are generated in memory and streamed; no report file is retained by
  the application. Database backups requested from the Server page are kept
  under `data/reports/backups/`.
- Token rotation invalidates the previous agent token immediately. Revocation
  preserves historical findings.

Back up the data directory before upgrades or bulk deletions.

## 11. Troubleshooting

### The page loads but scans stay queued

Check the server log. A scan worker may have failed at import time, or the
service may have restarted. Interrupted scans are marked failed on startup.
Several scans can run at once up to `VS_SCAN_WORKERS` (default 4); raise it on a
larger host if scans wait behind long-running jobs.

### A delegated network scan stays `waiting_agent`

The selected agent is offline, revoked, or does not advertise the `network`
module. Bring the agent online, pick another agent, or update the agent to a
version that supports delegated network scans.

### A web target is rejected

Use a hostname without spaces. Only `http://` and `https://` are accepted.
Credentials in URLs are not recommended; remove spaces and invalid ports.

### A network scan finds nothing

The host may block TCP connects, the port profile may not include the service,
or the connect timeout may be too short. Try explicit ports and a longer
timeout, and confirm you have authorisation and routing. For a delegated scan,
confirm the endpoint can reach the target range and that it is within the
server host limit.

### An authenticated scan reports "authentication failed"

The account was rejected once and is not retried, by design, to avoid lockouts.
Confirm the username, password/key, domain (`CORP\user`) and account type. For
Windows, confirm WinRM is enabled (`Enable-PSRemoting -Force`), the port is
correct, and the account is a local administrator. For HTTPS, a self-signed
certificate requires **Verify TLS** to be off or the certificate to be trusted on
the server. For Linux, confirm SSH password/key authentication and non-interactive
`sudo` work for that account. Fix the credential in Settings or re-enter a
per-scan credential, then start a new scan.

### OSV lookups are skipped

Confirm `VS_ENABLE_EXTERNAL_APIS=true`, the Settings toggle is on, and the
server can reach `https://api.osv.dev`. Check the scan events for the logged
error.

### Nmap/Nuclei is not used

Install the tool, ensure it is executable, and set the matching path variable
or leave it empty so `PATH` is used. Confirm the scan option and Settings toggle
are enabled. The Settings page shows availability and version.

### GitHub clone fails

Confirm Git is installed and outbound HTTPS works. For private repositories,
verify the token has read access and has not expired. Check the scan events;
the token is redacted from errors and logs.

### Agent is offline

Confirm the endpoint can reach the server URL, the agent service/task is
running, and the system clock is correct. Run the agent manually with `status`
or `run --once`. A revoked agent must be re-enrolled with a new token.

### Windows PowerShell agent will not start

Run an elevated PowerShell and check `VulnScannerAgent.ps1 -Action Status`,
`Get-ScheduledTask -TaskName "VulnScanner Agent"` and
`%ProgramData%\VulnScanner Agent\agent.json`. Reapply the configuration with
`install-windows-agent.ps1 -Configure`. The token may have expired or been
rotated.

### Agent scan reports "Secrets/repository modules requested without paths"

Provide at least one existing absolute path in the agent scan dialog.

### Active Directory import fails

Confirm the file is a JSON object, not an array, and is smaller than 20 MiB.
Validate the report is the output of the bundled collector or matches the
schema in [AGENT_GUIDE.md](AGENT_GUIDE.md). Confirm the customer/group/asset
selection matches.

### Authentication loops

If `VS_ADMIN_PASSWORD` is set, the browser prompts for Basic auth. Ensure the
username matches `VS_ADMIN_USER`. With a reverse proxy, forward the
`Authorization` header and use HTTPS. Do not expose the plain HTTP port directly
to an untrusted network.

## 12. Responsible operation

- Obtain written authorisation and define the target list, time window, rate
  limits, escalation contacts and stop conditions.
- Prefer passive options and narrow scopes first.
- Do not run active web checks or Nmap scripts against third-party systems.
- Treat collected secrets and AD data as sensitive. Restrict access to the data
  directory and reports.
- Report discovered vulnerabilities through the agreed channel; do not publish
  or exploit them.
- Keep the platform patched and the database backed up.

For the full policy guidance, see [AUTHORIZED_USE.md](AUTHORIZED_USE.md) and
[SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md).
