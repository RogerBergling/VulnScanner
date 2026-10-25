# VulnScanner Agent Guide

The VulnScanner agent performs local checks on Linux, Windows and macOS
endpoints. It is a single Python file that uses only the standard library. It
enrols with a one-time token and then polls the VulnScanner server over
outbound HTTP(S), so scanned endpoints do not need an inbound firewall rule.

> Use agents only on endpoints you are authorised to assess. The agent reads
> local configuration, packages, listening sockets and, when requested,
> selected files and Active Directory information. It does not install
> persistence beyond the service/task you explicitly install, and it does not
> modify scanned content.

## 1. How it works

1. An analyst creates an enrolment token in **Agents** for a customer and
   group.
2. The agent exchanges the one-time token for a long-lived agent token. Only a
   SHA-256 hash of the agent token is stored on the server.
3. The agent sends a heartbeat and asks for the next queued job.
4. The server returns a job with a module list, selected paths and options.
5. The agent collects locally and uploads a JSON result.
6. The server normalises, enriches and persists findings, then completes the
   scan.

The agent polls; the server never connects inbound to the endpoint. A typical
poll interval is 30 seconds, and the agent polls again after 5 seconds when it
just completed work. Failed uploads are saved in `pending-result.json` and
retried on the next poll.

## 2. Requirements

- Python 3.8 or newer (the server itself requires Python 3.11+).
- Outbound HTTPS to the VulnScanner server.
- Linux: systemd recommended; curl or wget for the installer.
- Windows: Windows 10/11 or Windows Server with PowerShell 5.1+, Python 3.8+,
  and Administrator rights for installation.
- Active Directory module: RSAT `ActiveDirectory` on the collector host or a
  Windows agent running with sufficient read access.

The agent uses `urllib`, `ssl`, `socket`, `subprocess` and standard library
modules only. It does not need `pip` or third-party packages.

## 3. Enrolment

### 3.1 Create a token

1. Open **Agents -> Enrol agent**.
2. Choose the customer and group. The agent becomes an asset in that group.
3. Optionally set a friendly agent name.
4. Choose expiry (1-168 hours).
5. Copy the generated Linux or Windows commands. The token is shown once.

### 3.2 Manual Linux/macOS enrolment

```bash
curl -fsSL https://scanner.example.com/agent/vulnscanner_agent.py -o vulnscanner_agent.py
python3 vulnscanner_agent.py enroll \
  --server https://scanner.example.com \
  --token vs_enroll_... \
  --name web01
python3 vulnscanner_agent.py run
```

The default configuration path is:

- Linux: `~/.config/vulnscanner/agent.json` (or `$XDG_CONFIG_HOME/vulnscanner/agent.json`)
- macOS: `~/Library/Application Support/VulnScanner/agent.json`
- Windows: `%APPDATA%\VulnScanner\agent.json`

For a system service, use `--config` to point at a protected path.

### 3.3 Manual Windows enrolment

```powershell
Invoke-WebRequest -UseBasicParsing `
  https://scanner.example.com/agent/vulnscanner_agent.py `
  -OutFile vulnscanner_agent.py
py -3 vulnscanner_agent.py enroll `
  --server https://scanner.example.com `
  --token vs_enroll_... `
  --name web01
py -3 vulnscanner_agent.py run
```

### 3.4 Linux installer

Run as root:

```bash
curl -fsSL https://scanner.example.com/agent/install-linux.sh -o install-linux.sh
sudo bash install-linux.sh \
  --server https://scanner.example.com \
  --token vs_enroll_...
```

What it does:

- Downloads and syntax-checks the agent.
- Creates a `vulnscanner` system account unless it already exists.
- Installs the agent in `/opt/vulnscanner-agent`.
- Stores configuration and pending results in `/var/lib/vulnscanner-agent`.
- Enrols the agent as the service account.
- Installs a hardened systemd unit with restart-on-failure.

Options:

| Option | Description |
| --- | --- |
| `--server URL` | Server base URL. Required for installation. |
| `--token TOKEN` | One-time token. Without it the agent is installed but not enrolled/started. |
| `--name NAME` | Friendly name; defaults to the hostname. |
| `--user USER` | Service account; default `vulnscanner`. Use `root` only if privileged paths are required. |
| `--install-dir DIR` | Program directory. |
| `--state-dir DIR` | Configuration/state directory. |
| `--python PATH` | Python interpreter to use. |
| `--insecure` | Skip TLS verification. Lab/self-signed only. |
| `--no-service` | Install/enrol without creating a systemd unit. |
| `--uninstall` | Stop/remove service and program files. |
| `--purge` | With `--uninstall`, also remove state and the service account. |

The default service account is unprivileged. It can read normal application
files, but not `/root`, private keys owned by root, or some system databases. If
the assessment explicitly requires those paths, reinstall with `--user root`
after reviewing the risk. Prefer granting targeted read access over running the
whole agent as root.

### 3.5 Windows installer

Run in an elevated PowerShell:

```powershell
.\install-windows.ps1 `
  -Server https://scanner.example.com `
  -Token vs_enroll_...
```

The installer:

- Validates Python 3.8+.
- Downloads the agent to `%ProgramFiles%\VulnScanner Agent`.
- Stores configuration and pending results in `%ProgramData%\VulnScanner Agent`.
- Restricts file ACLs to SYSTEM and Administrators.
- Registers an auto-restarting scheduled task that runs as SYSTEM at startup.

Options:

| Option | Description |
| --- | --- |
| `-Server URL` | Server base URL. |
| `-Token TOKEN` | One-time token. Without it the agent is installed but not enrolled. |
| `-Name NAME` | Friendly name; defaults to the computer name. |
| `-InstallDir DIR` | Program directory. |
| `-StateDir DIR` | Configuration/state directory. |
| `-Python PATH` | Python executable. |
| `-Insecure` | Skip TLS verification. Lab only. |
| `-NoService` | Install/enrol without registering a task. |
| `-Uninstall` | Remove the scheduled task and program files. |
| `-Purge` | With `-Uninstall`, also remove configuration and pending results. |

The task runs as SYSTEM so it can read system-wide configuration. If that is
not acceptable, use `-NoService`, enrol with a dedicated account, and run the
agent under that account yourself.

## 4. Commands

```text
vulnscanner_agent.py [--config PATH] enroll --server URL --token TOKEN [--name NAME] [--insecure]
vulnscanner_agent.py [--config PATH] run [--once] [--interval SECONDS]
vulnscanner_agent.py [--config PATH] status
vulnscanner_agent.py [--config PATH] update-token --token TOKEN
vulnscanner_agent.py [--config PATH] scan --modules system,packages,ports [--path DIR] [--output FILE]
```

- `enroll` writes the configuration file and token.
- `run` polls continuously. `--once` performs a single heartbeat/poll cycle.
- `status` prints configuration with the token removed and performs a
  heartbeat.
- `update-token` replaces the token in the configuration file after an analyst
  rotates it in the server UI. Restart the agent service afterwards; the
  running process keeps the old token until restarted.
- `scan` runs modules locally and prints JSON. It is useful for testing and
  for importing results elsewhere; it does not require a server once the
  module code is present. Provide `--path` for secrets/repo modules.

## 5. Modules

| Module | What it does | Platform |
| --- | --- | --- |
| `system` | OS/hardware, uptime, patch and update state, firewall, antivirus, disk encryption, local users/groups/services and baseline checks. | All |
| `packages` | OS package database, Python packages, npm globals and Windows installed programs. | All |
| `ports` | Listening TCP/UDP sockets, bind addresses, process names and PIDs where permitted. | All |
| `secrets` | Applies secret rules to selected paths, with entropy checks and placeholder filtering. | All |
| `repo` | Parses package manifests in selected paths for dependency inventory. | All |
| `ad` | Runs the read-only AD collector through PowerShell. | Windows |

`secrets` and `repo` require at least one path. Paths must be readable by the
agent account. The server rejects these modules without paths to avoid an
unintentional full-filesystem walk.

Module output is uploaded as one JSON document. The server applies its own
normalisation, deduplication, OSV/KEV enrichment and severity rules, so an agent
cannot silently lower a severity by sending a different label.

## 6. Active Directory collection

The Windows agent embeds a read-only collector equivalent to
`ad_audit.ps1`. It uses `Get-AD*` cmdlets and never writes to AD. Required:

- Windows with RSAT ActiveDirectory.
- A domain-joined host.
- An account (SYSTEM on a domain controller or a service account with read
  access) that can read users, computers, groups and the domain policy.

For a standalone report:

```powershell
.\ad_audit.ps1 -OutputPath C:\Temp\ad-audit.json
.\ad_audit.ps1 -StaleDays 120 -OutputPath .\ad-audit.json
.\ad_audit.ps1 -NoFile > ad-audit.json
```

Parameters:

- `-OutputPath` - output file; defaults to
  `ad-audit-<domain>-<timestamp>.json` in the current directory.
- `-StaleDays` - stale-account threshold, 30-3650 days (default 90).
- `-NoFile` - write JSON to stdout instead of a file.

Import the report in **Active Directory -> Import report** or through the API.
The report must be a JSON object under 20 MiB. It must not be an array.

Minimal report shape:

```json
{
  "domain": {
    "name": "corp.example",
    "forest": "corp.example",
    "domain_controller": "DC01",
    "functional_level": "Windows Server 2016",
    "machine_account_quota": 10,
    "recycle_bin_enabled": true
  },
  "collected_at": "2026-01-02T03:04:05Z",
  "collector": "ad_audit.ps1",
  "guest_enabled": false,
  "password_policy": {
    "min_length": 14,
    "complexity": true,
    "lockout_threshold": 5,
    "max_age_days": 365
  },
  "krbtgt_password_age_days": 120,
  "unconstrained_delegation": {"count": 0, "accounts": []},
  "kerberoastable": {"count": 1, "privileged": 0, "accounts": ["svc_app"]},
  "asrep_roastable": {"count": 0, "accounts": []},
  "stale_users": {"count": 3, "privileged": 0, "accounts": ["olduser"]},
  "never_expires": {"count": 2, "privileged": 0},
  "admin_count": {"non_privileged": {"count": 0, "accounts": []}},
  "privileged_groups": {"Domain Admins": 4, "Enterprise Admins": 2},
  "stale_computers": 1,
  "counts": {"users": 120, "computers": 30, "groups": 80},
  "findings": []
}
```

`findings` may contain custom entries with `severity`, `title`, `description`,
`key`, `evidence`, `remediation`, `cve`, `cwe`, `cvss` and `location`. Missing
fields are tolerated.

PingCastle and Purple Knight users can map exported values into this shape or
send their own custom findings. Keep the collection read-only and ensure the
tool's licence and authorisation requirements are respected.

## 7. Configuration file

The file contains the server URL, agent token, agent identity and TLS setting:

```json
{
  "server": "https://scanner.example.com",
  "token": "vs_agent_...",
  "agent_id": "…",
  "name": "web01",
  "customer_id": 3,
  "group_id": 7,
  "asset_id": 21,
  "verify_tls": true,
  "enrolled_at": "2026-01-02T03:04:05+00:00",
  "poll_interval": 30
}
```

Protect it as a secret. The installer sets mode `0600` on Linux and restricts
ACLs on Windows. Never copy it between hosts; enrol each host separately.

## 8. TLS, proxies and firewalls

- Prefer HTTPS. `--insecure`/`-Insecure` disables certificate verification and
  should only be used for a controlled lab.
- The agent honours standard proxy environment variables through Python's
  `urllib` on most platforms. Set `HTTPS_PROXY`/`NO_PROXY` in the service
  environment if needed.
- Allow outbound TCP 443 (or the configured server port) from the endpoint to
  the server. No inbound rule is required.
- If the server is behind a reverse proxy, use the external HTTPS URL for
  `--server`; the agent appends `/api/agent/...`.

## 9. Job lifecycle and retries

- A job is queued when an analyst starts an agent scan.
- The agent claims one job at a time.
- The server marks the job `processing` when the result is accepted, then
  `completed` after normalisation.
- A result upload failure is stored in `pending-result.json` and retried.
- Duplicate uploads are idempotent: a terminal job returns a duplicate
  acknowledgement instead of creating a second set of findings.
- If the server restarts before a scan finishes, the scan is marked
  interrupted/failed. Start a new scan.

`VS_AGENT_JOB_TIMEOUT` controls the server-side stale-job limit (default one
hour). The current agent does not kill a local job at that limit, but an analyst
can cancel the scan from the UI.

## 10. Revocation and uninstall

### Revoke

Delete the agent in the UI. The token is invalidated, queued/running jobs are
cancelled, and waiting scans are closed. Historical findings remain.

### Rotate a token

Use **Rotate token** on the agent detail page. The previous token is invalidated
immediately and the new token is shown once with Linux and Windows commands.
The generated commands use the default installer paths. For a custom
installation, run the equivalent command with your configuration path:

```bash
python3 vulnscanner_agent.py --config /path/to/agent.json update-token --token vs_agent_...
sudo systemctl restart vulnscanner-agent
```

On Windows, run PowerShell as Administrator and restart the scheduled task:

```powershell
py -3 vulnscanner_agent.py --config "C:\ProgramData\VulnScanner Agent\agent.json" update-token --token vs_agent_...
Stop-ScheduledTask -TaskName "VulnScanner Agent"
Start-ScheduledTask -TaskName "VulnScanner Agent"
```

The agent remains offline between rotation and restart, so rotate during a
maintenance window. Use revocation instead when the endpoint should never
reconnect.

### Linux uninstall

```bash
sudo bash /opt/vulnscanner-agent/../install-linux.sh --uninstall
# or, if the installer is not available:
sudo systemctl disable --now vulnscanner-agent
sudo rm -f /etc/systemd/system/vulnscanner-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/vulnscanner-agent
# Add --purge equivalent only when you intend to delete /var/lib/vulnscanner-agent
```

The installer's uninstall path is:

```bash
sudo bash install-linux.sh --uninstall
sudo bash install-linux.sh --uninstall --purge
```

`--uninstall` requires `--server` only for installation; the script accepts
uninstall without it.

### Windows uninstall

```powershell
.\install-windows.ps1 -Uninstall
.\install-windows.ps1 -Uninstall -Purge
```

This unregisters the scheduled task and removes program files. `-Purge` also
removes the state directory.

## 11. Troubleshooting

| Symptom | Checks |
| --- | --- |
| `Enrollment failed: HTTP 401` | Token expired or already used. Create a new token. |
| Agent stays offline | Server URL reachable? TLS trusted? Clock correct? Service/task running? |
| `No agent configuration` | Run `enroll` with the same `--config` path used by the service. |
| `Cannot reach` / proxy errors | Set proxy environment variables in the service, check DNS and firewall egress. |
| Job result rejected (413) | Result exceeds 25 MiB. Reduce selected paths or scope. |
| Secrets module error | Provide at least one existing, readable path. |
| AD module error | Windows + RSAT only; verify `Import-Module ActiveDirectory` works for the agent account. |
| Service exits immediately | Run `python3 /opt/vulnscanner-agent/vulnscanner_agent.py --config ... status` and inspect `journalctl -u vulnscanner-agent`. |
| Duplicate findings after retry | The server deduplicates by fingerprint; a duplicate terminal job upload is ignored. |

For server-side problems, inspect the scan event log in the UI and the Uvicorn
log. See [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for hardening.
