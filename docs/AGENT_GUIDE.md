# VulnScanner Agent Guide

The VulnScanner agent performs local checks on Linux, Windows and macOS
endpoints. Agents enrol with a one-time token and then poll the VulnScanner
server over outbound HTTP(S), so scanned endpoints do not need an inbound
firewall rule.

Windows endpoints have two supported agents:

- **Native PowerShell agent** (`VulnScannerAgent.ps1`) - recommended for Windows
  client and server editions. It needs only Windows PowerShell 5.1+ and does not
  require Python.
- **Python agent** (`vulnscanner_agent.py`) - a single standard-library file that
  also runs on Linux and macOS. It remains supported for existing deployments.

Both agents support endpoint checks, delegated TCP network scans and the
read-only Active Directory module (on Windows).

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

- Outbound HTTPS to the VulnScanner server.
- Linux: Python 3.8+ and systemd recommended; curl or wget for the installer.
- Windows (native agent): Windows 10/11 or Windows Server 2016+ with
  PowerShell 5.1+, and Administrator rights for installation.
- Windows (Python agent): the above plus Python 3.8+.
- macOS: Python 3.8+.
- Active Directory module: RSAT `ActiveDirectory` on the collector host or a
  Windows agent running with sufficient read access.

The Python agent uses `urllib`, `ssl`, `socket`, `subprocess` and standard
library modules only. It does not need `pip` or third-party packages. The native
Windows agent uses built-in PowerShell cmdlets and .NET classes.

## 3. Enrolment

### 3.1 Create a token

1. Open **Agents -> Enrol agent**.
2. Choose the customer and group. The agent becomes an asset in that group.
3. Optionally set a friendly agent name.
4. Choose expiry (1-168 hours).
5. Copy the generated Linux, Windows installer or Python agent command. The
   token is shown once.

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

### 3.3 Manual Windows enrolment (Python agent)

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

### 3.4 Windows installer (native PowerShell agent, recommended)

Run in an elevated PowerShell on Windows 10/11 or Windows Server 2016+. No
Python installation is required.

```powershell
Invoke-WebRequest -UseBasicParsing `
  https://scanner.example.com/agent/install-windows-agent.ps1 `
  -OutFile install-windows-agent.ps1
.\install-windows-agent.ps1 `
  -Server https://scanner.example.com `
  -Token vs_enroll_...
```

With no `-Server`/`-Token`, the installer prompts for the server URL, token,
agent name, TLS verification and poll interval. It detects whether the host is a
Windows client or server edition and prints a summary before making changes.

What it does:

- Downloads `VulnScannerAgent.ps1` (and `ad_audit.ps1` when available) to
  `%ProgramFiles%\VulnScanner Agent`.
- Stores configuration and pending results in `%ProgramData%\VulnScanner Agent`.
- Restricts directory and file ACLs to SYSTEM and Administrators with `icacls`.
- Enrols the endpoint with the one-time token.
- Registers the auto-restarting scheduled task **VulnScanner Agent**, which runs
  at startup and restarts after a failure.

Options:

| Option | Description |
| --- | --- |
| `-Server URL` | Server base URL. |
| `-Token TOKEN` | One-time enrolment token, or an existing agent token. |
| `-Name NAME` | Friendly name; defaults to the computer name. |
| `-InstallDir DIR` | Program directory. |
| `-StateDir DIR` | Configuration/state directory. |
| `-ConfigPath FILE` | Explicit configuration path; defaults to `%ProgramData%\VulnScanner Agent\agent.json`. |
| `-PollInterval SECONDS` | Poll interval, 5-3600 seconds. `0` (default) uses the server default for a new install and leaves the value unchanged with `-Configure`. |
| `-VerifyTls` | Explicitly verify the server certificate (default). |
| `-Insecure` | Skip TLS verification. Lab/self-signed only. |
| `-ServiceAccount ACCOUNT` | Account for the scheduled task; default `SYSTEM`. A custom user account prompts for its password. |
| `-SkipAdCollector` | Do not download `ad_audit.ps1`. |
| `-NoService` | Install and enrol without registering the scheduled task. |
| `-ForceDownload` | Re-download the agent even if the local version matches. |
| `-Configure` | Reconfigure an existing installation (see below). |
| `-EnrollAgain` | With `-Configure`, enrol again using a new token. |
| `-Uninstall` | Remove the scheduled task and program files. |
| `-Purge` | With `-Uninstall`, also remove configuration, state and pending results. |
| `-Interactive` | Force the interactive prompts. |

Installing with an existing `vs_agent_...` token skips enrolment and writes the
local configuration; the agent must already exist on the server. Use a
`vs_enroll_...` token for a new host.

#### Post-install configuration

The installer can be rerun in configuration mode without re-enrolling the host.
Supplying `-Server` may also refresh the agent scripts on disk to the server's
current version:

```powershell
# Change the server, poll interval and TLS behaviour
.\install-windows-agent.ps1 -Configure -Server https://scanner.example.com -PollInterval 60

# Trust a self-signed certificate in a lab
.\install-windows-agent.ps1 -Configure -Insecure

# Apply a rotated agent token
.\install-windows-agent.ps1 -Configure -Token vs_agent_...

# Enrol the host again with a fresh one-time token
.\install-windows-agent.ps1 -Configure -EnrollAgain -Server https://scanner.example.com -Token vs_enroll_...
```

`-Configure` updates the existing configuration and restarts the scheduled task.
Values that are not supplied are left unchanged. For a non-default service
account, pass `-ServiceAccount` when installing or reinstalling; a custom user
account prompts for its password, and the task needs the "Log on as a batch
job"/scheduled-task logon rights that Windows grants during registration. The
installer also grants that account read/execute access to the program files and
read/write access to the state directory so it can load its configuration and
write pending results.

The task runs as SYSTEM by default so it can read system-wide configuration.
Use `-NoService` and run the agent under a dedicated account when that is not
acceptable.

#### Native agent commands

```powershell
& "C:\Program Files\VulnScanner Agent\VulnScannerAgent.ps1" -Action Status
& "C:\Program Files\VulnScanner Agent\VulnScannerAgent.ps1" -Action Run
& "C:\Program Files\VulnScanner Agent\VulnScannerAgent.ps1" -Action Configure -PollInterval 60
& "C:\Program Files\VulnScanner Agent\VulnScannerAgent.ps1" -Action Scan -Modules system,ports
```

`-Action Run -Once` performs one heartbeat/poll cycle. `-Action Scan` runs
modules locally and writes JSON to stdout, or to `-Output FILE`; the network
module accepts `-Target`, `-Ports`, `-Profile`, `-TimeoutMs` and `-Workers`.

### 3.5 Linux installer

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

### 3.6 Windows installer (Python agent)

Existing Python-based Windows deployments can keep using `install-windows.ps1`.
Run it in an elevated PowerShell:

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

Python agent:

```text
vulnscanner_agent.py [--config PATH] enroll --server URL --token TOKEN [--name NAME] [--insecure]
vulnscanner_agent.py [--config PATH] configure [--server URL] [--token TOKEN] [--name NAME] [--poll-interval SECONDS] [--insecure|--verify-tls]
vulnscanner_agent.py [--config PATH] run [--once] [--interval SECONDS]
vulnscanner_agent.py [--config PATH] status
vulnscanner_agent.py [--config PATH] update-token --token TOKEN
vulnscanner_agent.py [--config PATH] scan --modules system,packages,ports,network [--path DIR] [--target HOST_OR_CIDR] [--ports PORTS] [--output FILE]
```

- `enroll` writes the configuration file and token.
- `configure` updates an existing configuration without re-enrolling, for
  example to change the server, name, poll interval or TLS setting.
- `run` polls continuously. `--once` performs a single heartbeat/poll cycle.
  `--interval` overrides the configured poll interval.
- `status` prints configuration with the token removed and performs a
  heartbeat.
- `update-token` replaces the token in the configuration file after an analyst
  rotates it in the server UI. Restart the agent service afterwards; the
  running process keeps the old token until restarted.
- `scan` runs modules locally and prints JSON. It is useful for testing and
  for importing results elsewhere; it does not require a server once the
  module code is present. Provide `--path` for secrets/repo modules and
  `--target`/`--ports` for the network module.

Native PowerShell agent: see [3.4](#34-windows-installer-native-powershell-agent-recommended).

## 5. Modules

| Module | What it does | Python agent | Native Windows agent |
| --- | --- | --- | --- |
| `system` | OS/hardware, uptime, patch and update state, firewall, antivirus, disk encryption, local users/groups/services and baseline checks. | All platforms | Windows |
| `packages` | OS package database, Python packages, npm globals and Windows installed programs. | All platforms | Windows |
| `ports` | Listening TCP/UDP sockets, bind addresses, process names and PIDs where permitted. | All platforms | Windows |
| `secrets` | Applies secret rules to selected paths, with entropy checks and placeholder filtering. | All platforms | Not implemented |
| `repo` | Parses package manifests in selected paths for dependency inventory. | All platforms | Not implemented |
| `network` | TCP connect scan from the endpoint's network position. | All platforms | Windows |
| `ad` | Runs the read-only AD collector through PowerShell. | Windows | Windows with RSAT |

The native Windows agent advertises `system`, `ports`, `network` and, when the
AD collector is installed, `ad`. The Python agent additionally advertises
`packages`, `secrets` and `repo`. The UI disables modules an agent has not
reported in its last heartbeat.

`secrets` and `repo` require at least one path. Paths must be readable by the
agent account. The server rejects these modules without paths to avoid an
unintentional full-filesystem walk.

### 5.1 Delegated network scans

A network scan can run on the VulnScanner server or on an enrolled agent. Use
an agent when the target is reachable only from the endpoint's network, for
example a private subnet behind a jump host.

- From **New scan**, choose the scan type **Network** and pick an endpoint under
  **Run from**. The server validates that the agent belongs to the selected
  customer/group, is not revoked, and advertises the `network` capability.
- From the agent detail page, choose **Scan** and select only the **network**
  module, then enter a target and optional ports. A network job cannot be
  combined with other modules in the same job.
- The scan is created with status `waiting_agent` and has no server-side worker.
  An online agent claims it on its next poll; an offline agent holds the job
  until it reconnects.
- The agent performs TCP connect probes (no raw sockets, no Nmap) and uploads
  open ports, service guesses and banners. The server applies the same
  dangerous-port rules, severity grading and fingerprinting as a server-side
  scan.
- The target must be a host, IP address or CIDR. The server rejects CIDR ranges
  above `VS_MAX_CIDR_HOSTS` (default 256), and both agents independently cap a
  delegated range at 256 hosts. Only scan systems you own or have written
  permission to assess.

The native PowerShell agent and Python agent 1.1+ both support delegated
network scans. Older Python agents without the `network` capability cannot be
selected for one.


Module output is uploaded as one JSON document. The server applies its own
normalisation, deduplication, OSV/KEV enrichment and severity rules, so an agent
cannot silently lower a severity by sending a different label.

## 6. Active Directory collection

The Windows agents run the read-only collector `ad_audit.ps1`, which must be
installed next to the agent (the Windows installers download it). It uses
`Get-AD*` cmdlets and never writes to AD. Required:

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

Both agents write the same JSON shape. The native Windows agent uses
`C:\ProgramData\VulnScanner Agent\agent.json`; the Python agent uses its
platform default or `--config`. The file contains the server URL, agent token,
agent identity, TLS setting and poll interval:

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

Change it with `-Configure` (native agent), the Windows installer's
`-Configure` mode, or the Python agent's `configure`/`update-token` commands.
Protect it as a secret. The installer sets mode `0600` on Linux and restricts
ACLs on Windows. Never copy it between hosts; enrol each host separately.

## 8. TLS, proxies and firewalls

- Prefer HTTPS. `--insecure`/`-Insecure` disables certificate verification and
  should only be used for a controlled lab.
- The native Windows agent uses .NET certificate validation; set `-VerifyTls`
  to restore verification after a lab installation, or rerun the installer with
  `-Configure -Insecure`/`-Configure -VerifyTls`.
- The Python agent honours standard proxy environment variables through
  Python's `urllib` on most platforms. Set `HTTPS_PROXY`/`NO_PROXY` in the
  service environment if needed. The native Windows agent follows the
  machine-wide WinHTTP/system proxy configuration.
- Allow outbound TCP 443 (or the configured server port) from the endpoint to
  the server. No inbound rule is required.
- If the server is behind a reverse proxy, use the external HTTPS URL for
  `--server`; the agent appends `/api/agent/...`.

## 9. Job lifecycle and retries

- A job is queued when an analyst starts an agent scan.
- The agent claims one job at a time.
- Delegated network scans are `waiting_agent` scans backed by an `agent_jobs`
  row. They do not occupy a server scan worker; the agent performs the work.
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

Server-side scans run in parallel up to `VS_SCAN_WORKERS` (default 4, range
1-32). The configured value appears in the dashboard and server status. Agent
jobs are bounded by each agent and the per-agent job timeout, not by the server
worker pool.

## 10. Revocation and uninstall

### Revoke

Delete the agent in the UI. The token is invalidated, queued/running jobs are
cancelled, and waiting scans are closed. Historical findings remain.

### Rotate a token

Use **Rotate token** on the agent detail page. The previous token is invalidated
immediately and the new token is shown once with Linux, Windows installer and
Python agent commands. The generated commands use the default installer paths.
For a custom installation, run the equivalent command with your configuration
path.

Native PowerShell agent:

```powershell
# Apply the rotated token and restart the task
.\install-windows-agent.ps1 -Configure -Token vs_agent_...
```

```powershell
& "C:\Program Files\VulnScanner Agent\VulnScannerAgent.ps1" `
  -Action Configure -Token vs_agent_...
Stop-ScheduledTask -TaskName "VulnScanner Agent"
Start-ScheduledTask -TaskName "VulnScanner Agent"
```

Python agent:

```bash
python3 vulnscanner_agent.py --config /path/to/agent.json update-token --token vs_agent_...
sudo systemctl restart vulnscanner-agent
```

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

Native PowerShell agent:

```powershell
.\install-windows-agent.ps1 -Uninstall
.\install-windows-agent.ps1 -Uninstall -Purge
```

Python agent:

```powershell
.\install-windows.ps1 -Uninstall
.\install-windows.ps1 -Uninstall -Purge
```

Both unregister the scheduled task and remove program files. `-Purge` also
removes the state directory and configuration. Revoke the agent in the UI
afterwards if it is no longer needed.

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
| Network job stays `waiting_agent` | The selected agent is offline, revoked, or does not advertise `network`. Bring it online or pick another agent. |
| Network job fails immediately | Check the target syntax and that it is within the server host limit; the endpoint must be able to reach the range. |
| PowerShell agent will not start | Run `VulnScannerAgent.ps1 -Action Status` elevated and check `Get-ScheduledTask -TaskName "VulnScanner Agent"`. |
| Windows installer rejects the token | The token expired or was already used; create a new enrolment token. |

For server-side problems, inspect the scan event log in the UI and the Uvicorn
log. See [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for hardening.
