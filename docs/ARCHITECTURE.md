# VulnScanner Architecture

This document explains how VulnScanner is put together, where data is stored,
and how a scan moves from the web interface to a persisted result. It is meant
for operators who need to deploy or troubleshoot the service and for developers
who want to add a scanner or an agent module.

## 1. Design constraints

VulnScanner is deliberately small and local-first:

- One Python process serves the web interface, the HTTP API and the background
  scan workers.
- All state is stored in one SQLite database. There is no separate database,
  message broker, cache server or worker service to install.
- The browser interface is plain HTML, CSS and JavaScript. There is no Node.js
  build step and no runtime package manager.
- Optional command-line tools are enhancements. If a tool is missing, disabled
  or fails, the built-in scanner continues and records a warning.
- Endpoint agents make only outbound connections. The server never opens a
  connection back to an endpoint.
- Outbound access is limited to features explicitly enabled by the operator:
  OSV.dev, the CISA KEV catalogue, GitHub cloning and optional tools that fetch
  their own data.

## 2. Component map

```text
┌──────────────────────────── Browser ────────────────────────────┐
│  SPA: index.html + app.js + styles.css                          │
│  hash routes: dashboard, customers, scans, agents, AD, server, settings │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTP(S), JSON, Basic auth optional
┌───────────────────────────────▼─────────────────────────────────┐
│                         FastAPI process                          │
│                                                                  │
│  app/main.py       security headers, Basic auth, static files    │
│  app/api.py        REST endpoints, validation, imports           │
│  app/scans.py      lifecycle, persistence, status carry-over     │
│  app/jobs.py       configurable background executor              │
│  app/agents.py     enrolment, heartbeat, jobs, agent scans       │
│  app/security.py   token generation, hashing, agent auth         │
│  app/reporting.py  JSON, CSV and standalone HTML reports         │
│                                                                  │
│  app/scanners/     web, network, repository, dependencies,       │
│                    secrets, source, AD, subdomains, testssl,     │
│                    trivy, agent normalization, OSV client, KEV   │
│                    enrichment, tool wrappers                     │
└───────────────┬─────────────────────────────┬────────────────────┘
                │                             │
      SQLite (WAL)                     outbound requests/subprocess
      data/vulnscanner.db              OSV.dev, CISA, GitHub,
                                       Nmap, Nuclei, testssl.sh,
                                       Trivy, Subfinder, SecLists,
                                       Gitleaks, Semgrep,
                                       osv-scanner, Git
                                                ▲
                                                │ outbound poll only
                                     ┌──────────┴──────────┐
                                     │ Linux/Windows agent │
                                     │ standard library    │
                                     └─────────────────────┘
```

## 3. Runtime components

| Component | Responsibility |
| --- | --- |
| `app/main.py` | Creates the FastAPI application, initialises the database, recovers interrupted scans, applies security headers and optional Basic authentication, and serves the SPA/manual/downloads. |
| `app/api.py` | Defines `/api` routes, request schemas, target validation, option filtering, imports, reports, agent management, server diagnostics, backups and settings. |
| `app/scans.py` | Turns a queued scan into a running scan, dispatches the correct engine, decorates findings with KEV data, persists results, applies finding-status carry-over and handles cancellation/failure. |
| `app/jobs.py` | Small `ThreadPoolExecutor` that runs scan, AD import and agent-result tasks off the request thread. The pool size is `VS_SCAN_WORKERS` (default 4, range 1-32). |
| `app/agents.py` | Creates agents and their assets, processes heartbeats and jobs, creates agent scans, renames/moves agents, rotates tokens and handles revocation. |
| `app/security.py` | Generates enrolment/agent tokens, stores only SHA-256 hashes and authenticates agent requests. |
| `app/credentials.py` | Fernet-encrypted credential profiles, asset bindings, per-scan credentials and resolution order. |
| `app/scanners/` | Independent scan engines and shared finding types. |
| `app/reporting.py` | Builds JSON, CSV, self-contained HTML and PDF reports on demand. |
| `app/backup.py` | Online SQLite backups, selective restores, safety backups and validation. |
| `app/scheduler.py` | Cron-based scheduled scans, notification delivery and stale agent-job expiry. |
| `app/database.py` | SQLite schema, connections, transactions, settings helpers and event logging. |
| `app/static/` | Dependency-free single-page interface. |
| `agent/` | Python and PowerShell agents, installers and read-only AD collector. |

## 4. Request and scan lifecycle

### 4.1 Creating a scan

1. The SPA posts to `POST /api/scans`.
2. `app/api.py` validates the customer/group/asset relationship, normalises the
   target and filters options to those supported by the scan type.
3. A scan row is inserted with `status = "queued"` (or `waiting_agent` for a
   delegated network scan) and an empty summary.
4. The scan is submitted to the background executor up to `VS_SCAN_WORKERS`
   concurrent scans. The HTTP response returns immediately with the queued scan.
5. If an agent module scan or delegated network scan was requested, the scan is
   created with `status = "waiting_agent"` and an `agent_jobs` row is queued
   instead. The server executor does not run it; the endpoint returns without
   waiting for the endpoint.

### 4.2 Executing a built-in scan

1. The worker re-reads the scan row and checks for an early cancellation.
2. It marks the scan `running`, sets the start time and writes a `scan_events`
   entry.
3. A `ScanContext` is created. It provides progress updates, event logging and
   cancellation checks to the engine.
4. The engine returns a `ScanResult` containing findings and scan metadata.
5. `persist_result()` normalises findings, calculates the fingerprint, merges
   duplicates, enriches CVEs with CISA KEV data, calculates severity totals and
   the risk score, and writes all finding rows.
6. The scan is marked `completed` with progress 100, the summary is stored as
   JSON, and a completion event is written.
7. On an exception the scan is marked `failed`, the truncated error is stored,
   and a debug traceback is written to the event log.
8. On cancellation the worker stops at the next engine checkpoint. A built-in
   scan that has already produced a result saves partial findings; a queued or
   waiting scan is closed immediately.

### 4.3 Finding persistence and status carry-over

Findings are stored per scan. A scan therefore remains an immutable historical
snapshot even when a later rescan of the same asset produces different results.

A finding has a stable 32-character fingerprint derived from its category, key,
CVE and location (or from category/title/CVE/location/resource when no key is
provided). When a new scan belongs to an asset, `_save_findings()` looks up the
most recent prior finding on that asset with the same fingerprint and copies:

- `status` (`open`, `acknowledged`, `false_positive`, `accepted`, `fixed`)
- `first_seen`

The new row always gets a fresh `last_seen`. Ad-hoc scans have no asset, so
their status does not carry over.

### 4.4 Deduplication

Each engine returns individual observations. `ScanResult.normalized()`:

1. Normalises severity and text lengths.
2. Computes a fingerprint.
3. Merges identical fingerprints, keeping the highest severity, appending new
   evidence and preserving additional raw occurrences.

This keeps a scan readable when the same rule fires on many pages or files.

## 5. Data model

```text
customers 1──n asset_groups 1──n assets
    │              │              │
    │              │              └──n scans (optional asset link)
    │              └──n agents (optional asset link)
    └──n scans ──n findings
                 └──n scan_events

agents 1──n agent_jobs 1──1 scans (optional)
enrollment_tokens (one-time, customer/group scoped)
settings, osv_cache, kev_catalog
```

| Table | Purpose |
| --- | --- |
| `customers` | Top-level ownership boundary. Case-insensitive unique names. |
| `asset_groups` | Customer-scoped organisation such as `webserver` or `workstations`. |
| `assets` | Durable target record with kind, identifier and JSON metadata. |
| `agents` | Enrolled endpoint identity, platform, capabilities, status and hashed token. |
| `enrollment_tokens` | One-time, expiring tokens bound to a customer and group. |
| `scans` | Scan type, target, status, progress, stage, options, summary and timestamps. |
| `scan_events` | Timestamped log used by the scan detail page and troubleshooting. |
| `findings` | Normalised result rows with severity, evidence, CVE/CWE/CVSS, fingerprint and review status. |
| `agent_jobs` | Queued/claimed/completed work for an agent. |
| `credentials` | Fernet-encrypted reusable Linux/Windows credential profiles. |
| `asset_credential_bindings` | Per-asset credential selection by operating system. |
| `scan_credentials` | Encrypted per-scan credential overrides. |
| `scan_schedules` | Recurring scan definitions, cron expressions and notification targets. |
| `asset_inventory` | Discovered hosts, ports, device type and first/last seen. |
| `finding_history` | Per-asset fingerprint history used for trends. |
| `settings` | Operator toggles, SMTP, scan guardrails, tool paths, listener/HTTPS choices, admin password hash and metadata such as the last KEV sync time. |
| `osv_cache` | Time-limited cache of OSV batch queries and advisory details. |
| `kev_catalog` | Locally cached CISA KEV entries. |

SQLite runs in WAL mode with foreign keys enabled and a 30-second busy timeout.
Scan workers write results while the API reads the database, so the interface
stays responsive during a scan. The database is a single file plus its `-wal`
and `-shm` companions while the server is running.

## 6. Scan engines

All engines implement the same contract: accept a `ScanContext`, return a
`ScanResult`, call `ctx.check_cancel()` regularly and never write to `findings`
directly.

| Engine | Module | Approach |
| --- | --- | --- |
| Web | `scanners/web.py` | HTTP requests, header/cookie/TLS review, exposed-path checks, form and parameter inventory, safe SQL-error and reflected-input probes, optional Nuclei and testssl.sh. |
| Network | `scanners/network.py` | Native Python TCP connect scanning with bounded concurrency, banner reads, dangerous-port rules, built-in web checks on discovered HTTP ports, optional HTTP/TLS inspection, testssl.sh and Nmap XML parsing, plus authenticated host checks via `scanners/authenticated.py`. The same module normalises delegated agent results. |
| Authenticated host | `scanners/authenticated.py` | Chooses SSH or WinRM per host, performs one authentication attempt, collects OS/patch/package/user/configuration inventory, parses it and emits host findings and OSV package CVEs. |
| Repository | `scanners/repository.py` | Local path or GitHub clone, then secrets, dependencies and source review, plus optional Trivy. Temporary clones are deleted in a `finally` block. |
| Dependencies | `scanners/dependencies.py` | Manifest/lockfile parsers for npm, Python, Go, Rust, PHP, Ruby, Java and .NET; OSV.dev batch queries; optional `osv-scanner` supplement. |
| Secrets | `scanners/secrets.py` | Pattern and entropy checks with placeholder filtering; optional Gitleaks. |
| Source | `scanners/source.py` | Transparent heuristic rules for injection sinks, unsafe deserialization, debug mode, weak crypto and similar issues; optional Semgrep. |
| Trivy | `scanners/trivy.py` | Parses Trivy filesystem JSON for dependency, IaC misconfiguration and secret findings; merges and de-duplicates them with built-in repository results. |
| testssl.sh | `scanners/testssl.py` | Parses testssl.sh JSON reports into TLS findings for web and network HTTPS services, with bounded host and finding counts. |
| Subdomains | `scanners/subdomains.py` | Passive Subfinder enumeration plus local wordlist DNS discovery; validates domains, detects wildcard DNS and reports discovered hosts without scanning them. |
| Active Directory | `scanners/ad.py` | Evaluates a read-only JSON report and turns policy/configuration observations into findings. |
| Agent | `scanners/agent.py` | Normalises endpoint-collected system, package, port, secrets and AD data into the same finding model. |

Engines add findings through `ScanResult.add()`. They do not calculate the
final risk score, do not resolve KEV data and do not decide whether a finding is
a false positive; those are platform responsibilities. This keeps results
consistent across scan types and prevents an agent payload from lowering a
severity that the server considers higher.

### 6.1 Optional tools

`scanners/tools.py` resolves tool paths from `VS_*_PATH` or `PATH`, reports
versions for Settings and launches tools with argument arrays (never a shell).
Each integration is gated by the scan's **External tools** option and, where
relevant, by the Settings toggles or `VS_ENABLE_EXTERNAL_APIS`. Tool failures are
logged but do not fail the scan.

### 6.2 Authenticated host scanning

`scanners/authenticated.py` runs after port and web discovery when
`options.authenticated` is true. For each host it selects Linux (SSH) or Windows
(WinRM) from `target_os`, open ports and banners, then resolves credentials in
this order: per-scan override, asset binding, customer default, global default.

- Linux uses `paramiko` to run a read-only POSIX shell collector (`/etc/os-release`,
  package database, pending updates, users, groups, `ss`, `sudo`, SSH config,
  firewall and kernel).
- Windows uses `pywinrm` to run a PowerShell collector that returns one JSON
  document with OS, hotfixes, installed software, local users/administrators,
  listeners, Defender, firewall, SMB, RDP, UAC, autologon, WinRM and service data.
- Each host receives exactly one authentication attempt. Authentication and
  connection failures become findings that name the host/protocol but never the
  secret; the scan continues with the next host.
- Linux package versions are queried against OSV.dev when external APIs are
  enabled. Both platforms also run local end-of-life, patch-age and configuration
  rules.
- Credentials are decrypted only in worker memory. Per-scan credentials are
  copied from `scan_credentials` into the scan context; saved secrets are never
  written to events, findings or API responses.

Authenticated checks are server-side only. A delegated agent job carries no
credentials and returns unauthenticated network results.

### 6.3 Enrichment

- **OSV.dev** is queried in batches of up to 100 packages. Batch responses are
  cached for six hours and advisory details for fourteen days.
- **CISA KEV** is downloaded only when an operator clicks **Sync** in Settings.
  Matching CVEs are annotated at persistence time with the KEV name, due date,
  ransomware flag and required action. Synchronisation is not scheduled
  automatically.
- If enrichment fails, the original finding is still saved.

## 7. Endpoint agent architecture

1. An analyst creates a one-time enrolment token scoped to a customer and
   group. Only its hash and a short prefix are stored.
2. The agent exchanges the token for a long-lived agent token. The server stores
   only the SHA-256 hash and creates an asset in the selected group.
3. The agent calls the heartbeat and next-job endpoints over outbound HTTP(S).
4. A claimed job moves from `queued` to `running` and carries the module list,
   selected paths, target and options.
5. The agent collects data locally and uploads one JSON document.
6. The server validates size and identity, processes the payload through
   `scanners/agent.py` (or `scanners/network.py` for a delegated network scan),
   persists findings and completes both the job and scan.
7. Failed uploads are retried from `pending-result.json`. Terminal jobs return a
   duplicate acknowledgement instead of creating a second finding set.

A delegated network scan is created as a `waiting_agent` scan with an
`agent_jobs` row whose payload has `modules: ["network"]` and a `target`. It does
not enter the server scan pool. The endpoint performs TCP connect probes from
its own network position and uploads open ports, service guesses and banners.

Revoking an agent invalidates its token, cancels queued/running jobs and closes
waiting scans. Historical findings are retained.

There are two agents. `agent/VulnScannerAgent.ps1` is a native PowerShell agent
for Windows client and server editions and does not require Python.
`agent/vulnscanner_agent.py` is the standard-library Python agent for
Linux/macOS and existing Windows deployments. Both use the same enrolment,
heartbeat, job and result contract. See [AGENT_GUIDE.md](AGENT_GUIDE.md).

## 8. Active Directory path

Two paths produce the same finding model:

- `POST /api/ad/import` accepts a JSON object in the request body and creates an
  AD scan. Processing is asynchronous.
- An AD scan can point at a JSON report already present on the server, or a
  Windows agent can run the `ad` module and upload its collector output.

The collector is read-only. The server evaluates the report; it never connects
to LDAP or modifies directory objects.

## 9. Frontend architecture

The interface is a single HTML shell plus one JavaScript file. It uses:

- Hash routing (`#/scans/12`) so browser refreshes work without server-side
  route handling.
- `fetch()` against the same origin.
- DOM construction without inline event handlers, compatible with the strict
  Content Security Policy set in `app/main.py`.
- CSS custom properties for the light/dark theme; no external fonts, scripts or
  CDNs.
- Polling on the scan detail page for progress and events.

Because the SPA is served from the same origin and CSP blocks inline and remote
scripts, no separate frontend build, bundler or CDN is required.

## 10. Background execution and recovery

The executor is in-process. This is intentional: it avoids an extra service and
keeps installation simple. Consequences:

- Server-side scan concurrency is set by `VS_SCAN_WORKERS` (default 4, range
  1-32). Additional scans stay queued.
- Delegated network scans do not use a server worker. They are `waiting_agent`
  scans backed by an `agent_jobs` row; the selected endpoint claims the job on
  its next poll and uploads the result.
- A process crash loses in-flight work.
- On startup, `recover_interrupted_scans()` marks any `queued` or `running` scans
  as failed with an "Interrupted" stage and an explanatory event. Start a new
  scan after a restart.
- There is no distributed queue, so two VulnScanner instances must not share the
  same database file.

## 11. Extension points

### Adding a scan type

1. Add an engine module under `app/scanners/` returning a `ScanResult`.
2. Add a branch in `_dispatch()` in `app/scans.py`.
3. Add validation and option filtering in `app/api.py`.
4. Add the type to the meta endpoint and the SPA scan dialog.
5. Add tests for validation, execution and persistence.

### Adding an agent module

1. Collect data in `agent/vulnscanner_agent.py` (and
   `agent/VulnScannerAgent.ps1` when the module should be available on Windows)
   and include it in the result document.
2. Allow the module in the agent-scan validation in `app/api.py`.
3. Normalise it in `app/scanners/agent.py`, or add a dedicated normaliser such as
   `process_agent_network_payload` in `app/scanners/network.py`.
4. Document the module and retest job retry/idempotency.

### Adding a tool integration

1. Add the tool path to `TOOL_PATHS` and `.env.example`.
2. Use `tool_path()` and `run_tool()` from `scanners/tools.py`.
3. Gate execution on the scan option and relevant setting.
4. Parse structured output, add stable finding keys and cap result counts.
5. Log absence/failure but never fail the whole scan.

## 12. Non-goals and limits

- No multi-tenant server isolation: all data is visible to the single
  authenticated operator.
- No role-based access control, per-user accounts or approval workflow.
- No exploitation, credential brute forcing, authenticated web crawling or
  post-exploitation. Authenticated host scans make a single login attempt per
  host and never enumerate passwords.
- No arbitrary distributed scanning, horizontal worker scaling or external job
  queue. Network scans can be delegated to enrolled agents, but there is no
  central pool of scan workers beyond `VS_SCAN_WORKERS`.
- No automatic remediation.
- Built-in checks are conservative and may miss issues that a dedicated,
  carefully tuned tool would find. Findings require validation.

See [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for the security
model and [INTEGRATIONS.md](INTEGRATIONS.md) for tool-specific behaviour.
