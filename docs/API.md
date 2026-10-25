# VulnScanner HTTP API

The API is served under `/api`. Interactive OpenAPI documentation is available
at `/api/docs` and the schema at `/api/openapi.json`.

- Base URL: `http://127.0.0.1:8765`
- Content type: `application/json` unless noted.
- Timestamps: ISO 8601 UTC with an offset, for example
  `2026-01-02T03:04:05+00:00`.
- Errors: `{"detail": "message"}` or FastAPI validation errors under `detail`.

## 1. Authentication

If `VS_ADMIN_PASSWORD` is set, all dashboard and API routes require HTTP Basic
authentication, except these public prefixes:

- `/api/health`
- `/api/agent/` (agent token endpoints)
- `/agent/` (agent scripts/downloads)
- `/static/`
- `/api/docs`
- `/api/openapi.json`

```bash
curl -u admin:change-me http://127.0.0.1:8765/api/customers
```

Agent endpoints use an agent token instead:

```http
X-Agent-Token: vs_agent_...
```

or:

```http
Authorization: Bearer vs_agent_...
```

Enrolment uses a one-time token in the request body. Agent APIs are not protected
by dashboard Basic auth, so an agent does not need the administrator password.

If `VS_ADMIN_PASSWORD` is empty, dashboard/API authentication is disabled. Keep
the service bound to `127.0.0.1` in that mode.

## 2. Conventions

- IDs are integers except agent/job IDs, which are strings.
- List endpoints return plain arrays unless documented otherwise.
- `PATCH` updates only supplied fields.
- Deleting a customer removes its groups, assets, agents, scans, findings and
  events. Export first.
- A scan is immutable; `rescan` creates a new scan.
- All scan and finding status values are lowercase strings.

## 3. Health, metadata and dashboard

### `GET /api/health`

Public health check.

```json
{
  "status": "ok",
  "product": "VulnScanner",
  "version": "1.0.0",
  "time": "2026-01-02T03:04:05+00:00"
}
```

### `GET /api/meta`

Lists scan types and agent modules.

```json
{
  "product": "VulnScanner",
  "version": "1.0.0",
  "scan_types": [
    {"id": "web", "name": "Website / web application"},
    {"id": "network", "name": "Server / network services"},
    {"id": "repo", "name": "Local source repository"},
    {"id": "github", "name": "GitHub repository"},
    {"id": "ad", "name": "Active Directory report"}
  ],
  "agent_modules": [
    {"id": "system", "name": "System baseline and security configuration"},
    {"id": "packages", "name": "Installed package vulnerabilities (OSV)"},
    {"id": "ports", "name": "Local listening services"},
    {"id": "secrets", "name": "Secrets in selected local paths"},
    {"id": "repo", "name": "Repository inventory in selected paths"},
    {"id": "ad", "name": "Active Directory audit (Windows)"}
  ]
}
```

### `GET /api/dashboard`

Returns counts, severity totals for the latest completed scan per asset,
risk score/label, recent scans, top critical/high findings and a 14-day trend.

```json
{
  "counts": {
    "customers": 2,
    "groups": 5,
    "assets": 18,
    "scans": 42,
    "agents": 3,
    "agents_online": 2,
    "running_scans": 0,
    "waiting_agent_scans": 1,
    "assessed_assets": 14
  },
  "severity": {"critical": 1, "high": 4, "medium": 9, "low": 12, "info": 30, "total": 56},
  "risk": {"score": 72, "label": "High"},
  "recent_scans": [],
  "top_findings": [],
  "trend": []
}
```

## 4. Customers

### `GET /api/customers`

Returns customers with group/asset/scan counts, last completed scan and the
latest severity summary/risk score.

```json
[
  {
    "id": 1,
    "name": "Acme",
    "description": "Primary customer",
    "created_at": "2026-01-02T03:04:05+00:00",
    "groups": 2,
    "assets": 8,
    "scans": 12,
    "last_scan": "2026-01-03T10:00:00+00:00",
    "severity": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 4, "total": 7},
    "risk_score": 45
  }
]
```

### `POST /api/customers`

```json
{"name": "Acme", "description": "Primary customer"}
```

Returns `201` with the customer detail shape (including groups, assets and
`scan_count`). A default group named `General` is created. Duplicate
case-insensitive names return `409`.

### `GET /api/customers/{customer_id}`

Returns the customer plus `groups`, each group's `assets`, each asset's
`last_scan` and `scan_count`, plus customer `scan_count`, `severity` and
`risk_score`.

```json
{
  "id": 1,
  "name": "Acme",
  "groups": [
    {
      "id": 1,
      "customer_id": 1,
      "name": "General",
      "description": "Default asset group",
      "assets": [],
      "scan_count": 0
    }
  ],
  "scan_count": 0,
  "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
  "risk_score": 0
}
```

### `PATCH /api/customers/{customer_id}`

```json
{"name": "Acme Corp", "description": "Updated"}
```

`name` and `description` are optional. Returns the customer row.

### `DELETE /api/customers/{customer_id}`

```json
{"ok": true, "deleted_scan_ids": [4, 5]}
```

## 5. Groups and assets

### `POST /api/customers/{customer_id}/groups`

```json
{"name": "webserver", "description": "Internet-facing hosts"}
```

Returns `201` with the group row. Names are unique per customer (`409`).

### `GET /api/groups/{group_id}`

Returns the group, its `customer` and its `assets`.

```json
{
  "id": 1,
  "customer_id": 1,
  "name": "webserver",
  "description": "Internet-facing hosts",
  "assets": []
}
```

### `PATCH /api/groups/{group_id}`

```json
{"name": "dmz-webserver", "description": "DMZ"}
```

### `DELETE /api/groups/{group_id}`

Returns `{"ok": true, "customer_id": 1, "deleted_scan_ids": []}`.

### `POST /api/groups/{group_id}/assets`

```json
{
  "name": "www01",
  "kind": "web",
  "identifier": "https://www.example.com",
  "description": "Primary web server",
  "metadata": {"owner": "web-team", "environment": "prod"}
}
```

`kind` is one of `host`, `web`, `repo`, `github`, `domain`, `agent`, `other`.
Asset names are unique per group (`409`). Returns `201` with the asset row; the
`metadata` field is returned as an object.

### `GET /api/assets/{asset_id}`

Returns the asset plus `group`, `customer`, the last 50 `scans`, and
`latest_findings` from the latest completed scan for that asset.

### `PATCH /api/assets/{asset_id}`

```json
{
  "name": "www02",
  "kind": "web",
  "identifier": "https://www2.example.com",
  "description": "Updated",
  "metadata": {"tier": 1}
}
```

### `DELETE /api/assets/{asset_id}`

Returns `{"ok": true, "group_id": 2, "deleted_scan_ids": []}`.

## 6. Scans

### `GET /api/scans`

Query parameters:

| Parameter | Type | Meaning |
| --- | --- | --- |
| `customer_id` | int | Filter by customer. |
| `group_id` | int | Filter by group. |
| `asset_id` | int | Filter by asset. |
| `status` | string | `queued`, `running`, `waiting_agent`, `completed`, `failed`, `cancelled`. |
| `scan_type` | string | `web`, `network`, `repo`, `github`, `ad`, `agent`. |
| `active` | bool | Only queued/running/waiting_agent. |
| `q` | string | Search target, stage, customer name or asset name. |
| `limit` | int | 1-500, default 50. |
| `offset` | int | Default 0. |

```json
{
  "items": [
    {
      "id": 12,
      "customer_id": 1,
      "group_id": 1,
      "asset_id": 4,
      "agent_id": null,
      "scan_type": "web",
      "target": "https://www.example.com",
      "status": "completed",
      "progress": 100,
      "stage": "Completed",
      "options": {"active": true, "external_tools": false},
      "summary": {"critical": 0, "high": 1, "total": 5, "risk_score": 42},
      "error": "",
      "requested_by": "local",
      "created_at": "2026-01-02T03:04:05+00:00",
      "started_at": "2026-01-02T03:04:06+00:00",
      "completed_at": "2026-01-02T03:05:00+00:00",
      "cancelled": 0,
      "customer_name": "Acme",
      "group_name": "General",
      "asset_name": "www01",
      "agent_name": null,
      "duration_seconds": null
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### `POST /api/scans`

```json
{
  "customer_id": 1,
  "group_id": 1,
  "asset_id": 4,
  "scan_type": "web",
  "target": "https://www.example.com",
  "options": {"active": true, "external_tools": false},
  "github_token": null,
  "requested_by": "local"
}
```

Notes:

- `customer_id` is required. Provide `group_id` or let the API use the
  customer's first/default group.
- If `asset_id` is supplied, the target may be blank and the asset identifier is
  used. The asset must belong to the selected customer/group.
- `target` is required for every scan type; blank targets fail validation with
  `422`.
- `github_token` is accepted only for `github` scans and is never persisted.
- The response is the created scan detail with `status: "queued"`.
- Scan execution happens in the background. Poll `GET /api/scans/{id}`.

Target normalisation:

| Type | Accepted target |
| --- | --- |
| `web` | Hostname or `http(s)://` URL; hostname gets `https://`. |
| `network` | Hostname, IP or CIDR. |
| `repo` | Existing absolute/relative directory on the server. |
| `github` | `https://github.com/owner/repo` or `owner/repo`. |
| `ad` | Existing JSON report file on the server (prefer `/api/ad/import`). |

Options are filtered per scan type:

```json
{
  "web": {"active": true, "external_tools": false},
  "network": {
    "ports": "22,80,443,8000-8100",
    "profile": "common",
    "connect_timeout": 0.45,
    "external_tools": false,
    "nmap_vulners": false
  },
  "repo": {
    "include_secrets": true,
    "include_dependencies": true,
    "include_source": true,
    "git_history": false,
    "external_tools": false
  },
  "github": {
    "include_secrets": true,
    "include_dependencies": true,
    "include_source": true,
    "git_history": false,
    "external_tools": false
  }
}
```

Invalid port profiles, non-numeric timeouts, missing targets and invalid URLs
return `400`/`422`.

### `GET /api/scans/{scan_id}`

Returns the scan row plus:

- `findings` - sorted by severity.
- `events` - up to 1000 event log rows.
- `agent` - public agent data when the scan belongs to an agent.
- `finding_count`.

### `POST /api/scans/{scan_id}/cancel`

Requests cancellation. Queued/waiting agent scans are closed immediately; running
scans get `stage: "Cancelling…"` and the worker stops at its next cancellation
check. Cancelling a terminal scan returns `409`.

### `POST /api/scans/{scan_id}/rescan`

Creates a new queued scan with the original target and options. Agent scans
cannot be rescanned through this endpoint (`400`); start them from Agents.

Returns `201` with the new scan detail.

### `DELETE /api/scans/{scan_id}`

Deletes a completed, failed or cancelled scan. Active scans return `409`.

### `GET /api/scans/{scan_id}/findings`

Optional filters: `severity`, `category`, `status`.

```json
[
  {
    "id": 99,
    "scan_id": 12,
    "customer_id": 1,
    "asset_id": 4,
    "severity": "high",
    "category": "web",
    "title": "Missing Content-Security-Policy header",
    "description": "…",
    "evidence": "…",
    "remediation": "…",
    "cve": "",
    "cwe": "CWE-693",
    "cvss": null,
    "location": "https://www.example.com/",
    "resource": "https://www.example.com/",
    "fingerprint": "0123456789abcdef0123456789abcdef",
    "status": "open",
    "first_seen": "2026-01-02T03:04:05+00:00",
    "last_seen": "2026-01-02T03:04:05+00:00",
    "raw": {}
  }
]
```

### `PATCH /api/findings/{finding_id}`

```json
{"status": "acknowledged"}
```

Allowed: `open`, `acknowledged`, `false_positive`, `accepted`, `fixed`. Any
other value returns `422`. The scan event log records the change.

### `GET /api/scans/{scan_id}/export`

Query parameter `format`:

- `html` (default) - standalone printable report, served inline.
- `json` - JSON document with `scan`, `findings` and context.
- `csv` - finding rows.

Other values return `400`. JSON/CSV are sent as attachments.

## 7. Agents

### `GET /api/agents`

Returns non-revoked agents with customer/group/asset names, `scan_count`,
`queued_jobs`, `online`, `last_seen_human` and parsed capabilities. `token_hash`
is never returned.

### `GET /api/agents/{agent_id}`

Returns the agent plus `customer_name`, `group_name`, `asset_name`,
`created_human`, `capabilities`, a `stats` object and the 25 most recent jobs
and 15 most recent scans.

```json
{
  "id": "9c1e…",
  "name": "web01",
  "online": true,
  "status": "online",
  "platform": "Linux",
  "version": "1.2.3",
  "hostname": "web01",
  "last_ip": "10.0.0.12",
  "last_seen_human": "12s ago",
  "created_at": "2026-01-02T03:04:05+00:00",
  "created_human": "4d ago",
  "customer_name": "Acme",
  "group_name": "webserver",
  "asset_name": "web01",
  "capabilities": ["system", "packages", "ports"],
  "stats": {
    "scans": 4, "jobs": 4, "queued_jobs": 1, "active_jobs": 0,
    "failed_jobs": 0, "findings": 12, "open_findings": 9
  },
  "jobs": [],
  "scans": []
}
```

Unknown IDs return `404`. Revoked agents remain readable for history.

### `PATCH /api/agents/{agent_id}`

```json
{"name": "web01-renamed", "customer_id": 1, "group_id": 2}
```

All fields are optional. Renaming updates the linked asset. Moving an agent
requires a group that belongs to the target customer; the linked asset moves
with the agent while historical scans keep their original placement. Returns
`{"ok": true, "agent": {…}}`. Revoked agents return `409`; invalid groups return
`400`.

### `POST /api/agents/{agent_id}/rotate-token`

Replaces the agent token and returns the new token once, together with
`linux_command` and `windows_command` that use `update-token` and restart the
installed service. The previous token stops working immediately. Revoked agents
return `409`.

### `POST /api/agents/enrollment-tokens`

```json
{
  "customer_id": 1,
  "group_id": 1,
  "agent_name": "web01",
  "hours": 24
}
```

Returns `201`:

```json
{
  "token": "vs_enroll_...",
  "token_prefix": "vs_enroll_abc…",
  "expires_at": "2026-01-03T03:04:05+00:00",
  "customer": "Acme",
  "group": "General",
  "linux_command": "curl -fsSL …",
  "windows_command": "Invoke-WebRequest …",
  "agent_url": "http://127.0.0.1:8765/agent/vulnscanner_agent.py",
  "note": "The token can be used once and is shown only now. …"
}
```

The token is shown once and expires after 1-168 hours.

### `POST /api/agents/{agent_id}/scan`

```json
{
  "modules": ["system", "packages", "ports"],
  "paths": [],
  "options": {}
}
```

Returns `201` with `scan_id`, `agent_online`, a message and the scan detail.
Modules: `system`, `packages`, `ports`, `secrets`, `repo`, `ad`. `secrets`/`repo`
require paths; `ad` requires a Windows agent. Revoked agents return `409`.

### `DELETE /api/agents/{agent_id}`

Revokes the agent, invalidates its token, cancels queued/running jobs and closes
waiting scans. Returns `{"ok": true}`.

### `POST /api/agent/enroll`

Public agent endpoint; no Basic auth or agent token. Requires a valid one-time
enrolment token.

```json
{
  "enrollment_token": "vs_enroll_...",
  "name": "web01",
  "platform": "Linux",
  "version": "1.0.0",
  "hostname": "web01",
  "capabilities": ["system", "packages", "ports"],
  "ip": ""
}
```

Returns `201` with `agent_id`, `name`, `token`, `customer_id`, `group_id`,
`asset_id` and `poll_interval`. Invalid/expired/used tokens return `401`.

### `POST /api/agent/heartbeat`

Requires `X-Agent-Token` or a Bearer agent token.

```json
{
  "platform": "Linux",
  "version": "1.0.0",
  "hostname": "web01",
  "capabilities": ["system"],
  "ip": ""
}
```

Returns `{"ok": true, "next_poll": 30, "server_time": "…"}`.

### `POST /api/agent/jobs/next`

Requires an agent token. Claims the oldest queued job.

```json
{
  "job": {
    "id": "5f0c…",
    "agent_id": "9c1e…",
    "scan_id": 42,
    "job_type": "scan",
    "payload": {
      "scan_id": 42,
      "modules": ["system", "ports"],
      "paths": [],
      "options": {"exclude_paths": [], "max_files": 20000}
    },
    "status": "running",
    "created_at": "…",
    "claimed_at": "…",
    "completed_at": null,
    "error": ""
  },
  "next_poll": 5
}
```

When no job is available: `{"job": null, "next_poll": 30}`.

### `POST /api/agent/jobs/{job_id}/result`

Requires an agent token.

```json
{
  "status": "completed",
  "results": {
    "system": {"hostname": "web01", "os": "Linux"},
    "packages": [],
    "listening_ports": [],
    "checks": [],
    "secrets": [],
    "source_findings": [],
    "modules": ["system", "ports"]
  },
  "error": ""
}
```

`status` may be `completed`, `failed` or `cancelled`. Results over 25 MiB return
`413`. A completed upload returns `{"ok": true, "accepted": true, "scan_id": 42}`
and the server processes the report asynchronously. A failed/cancelled upload
returns `accepted: false` and closes the scan. Re-uploading to a terminal job
returns `{"ok": true, "duplicate": true}`.

## 8. Active Directory import

### `POST /api/ad/import`

```json
{
  "customer_id": 1,
  "group_id": 1,
  "asset_id": null,
  "report": {
    "domain": {"name": "corp.example"},
    "guest_enabled": true,
    "password_policy": {"min_length": 6, "complexity": false},
    "findings": [
      {"severity": "high", "title": "Custom issue", "key": "custom-issue"}
    ]
  }
}
```

Returns `201` with the created AD scan detail. The report must be a JSON object
under 20 MiB. Customer/group/asset relationships are validated. Processing is
asynchronous; poll the scan.

## 9. Server status and maintenance

### `GET /api/server/status`

Returns runtime, database, storage, queue and health information for the local
instance. The response contains no findings, tokens or scan evidence, so it can
be downloaded as a diagnostics snapshot.

```json
{
  "status": "ok",
  "product": "VulnScanner",
  "version": "1.0.0",
  "started_at": "2026-01-02T03:04:05+00:00",
  "uptime_seconds": 3600,
  "uptime_human": "1h",
  "process": {
    "pid": 1234,
    "python": "3.11.9",
    "platform": "Linux-6.8.0-x86_64",
    "host": "127.0.0.1",
    "port": 8765,
    "auth_enabled": true,
    "admin_user": "admin",
    "external_api_environment": true
  },
  "database": {
    "path": "/path/to/data/vulnscanner.db",
    "size": 123456,
    "wal_size": 4096,
    "shm_size": 32768,
    "journal_mode": "wal",
    "page_count": 30,
    "page_size": 4096,
    "free_pages": 0,
    "schema_version": 1,
    "integrity": "ok",
    "writable": true
  },
  "paths": {
    "data_dir": "/path/to/data",
    "reports_dir": "/path/to/data/reports",
    "reports_count": 2,
    "reports_size": 8192
  },
  "disk": {"path": "/path/to/data/reports", "total": 0, "used": 0, "free": 0, "percent": 0},
  "counts": {
    "customers": 1, "groups": 1, "assets": 1, "scans": 0, "findings": 0,
    "agents": 1, "agents_online": 1, "agents_offline": 0, "agents_revoked": 0,
    "scans_queued": 0, "scans_running": 0, "scans_waiting_agent": 0,
    "scans_active": 0, "jobs_queued": 0, "jobs_running": 0, "jobs_failed": 0
  },
  "queue": {
    "scans_queued": 0, "scans_running": 0, "scans_waiting_agent": 0,
    "jobs_queued": 0, "jobs_running": 0, "jobs_failed": 0
  },
  "settings": {"allow_external_apis": true, "nuclei_enabled": true, "nmap_enabled": true},
  "tools": {},
  "limits": {"top_ports": 58, "agent_job_timeout_seconds": 3600},
  "checks": [
    {"id": "database", "label": "Database", "status": "ok", "detail": "ok · wal journal"}
  ],
  "last_backup_at": "",
  "last_backup_path": ""
}
```

`status` is `ok` or `degraded`. Check statuses are `ok`, `warning`, `info` or
`error`.

### `POST /api/server/database/backup`

Creates a consistent SQLite backup under `<reports>/backups/` using SQLite's
online backup API, records the path in settings and returns `201`:

```json
{"ok": true, "path": "/path/to/data/reports/backups/vulnscanner-20260102-030405.db", "size": 123456, "created_at": "…"}
```

### `POST /api/server/database/vacuum`

Runs `VACUUM` and returns the size before and after:

```json
{"ok": true, "before": 200000, "after": 180000, "saved": 20000}
```

The database may be locked briefly; run it when scans are idle. Errors return
`409`.

## 10. Settings and KEV

### `GET /api/settings`

```json
{
  "product": "VulnScanner",
  "version": "1.0.0",
  "allow_external_apis": true,
  "nuclei_enabled": true,
  "nmap_enabled": true,
  "external_apis_available": true,
  "kev_last_sync": "",
  "kev_count": 0,
  "database_path": "/path/to/data/vulnscanner.db",
  "database_size": 123456,
  "reports_path": "/path/to/data/reports",
  "tools": {
    "nmap": {"available": false, "path": "", "version": ""}
  },
  "limits": {"top_ports": 58, "agent_job_timeout_seconds": 3600}
}
```

### `PATCH /api/settings`

```json
{
  "allow_external_apis": false,
  "nuclei_enabled": false,
  "nmap_enabled": true
}
```

All fields optional. Returns the updated settings object.

### `POST /api/settings/kev/sync`

Downloads and caches the CISA KEV catalogue. Returns the sync result on success;
returns `400` if external APIs are disabled, and `502` if the download fails.
This endpoint requires outbound network access.

## 11. Non-API routes

| Route | Description |
| --- | --- |
| `GET /` | SPA shell. |
| `GET /manual` | Markdown user manual, inline. |
| `GET /agent/download/vulnscanner_agent.py` | Agent script (allow-listed). |
| `GET /agent/download/install-linux.sh` | Linux installer. |
| `GET /agent/download/install-windows.ps1` | Windows installer. |
| `GET /agent/download/ad_audit.ps1` | AD collector. |
| `GET /agent/{other-file}` | Read-only static agent directory. |
| `GET /static/*` | CSS/JavaScript assets. |

Only the four allow-listed names are served through `/agent/download/`;
unknown names return `404`.

## 12. Status codes

| Code | Meaning |
| --- | --- |
| `200` | Success. |
| `201` | Created. |
| `204` | No content (`/favicon.ico`). |
| `400` | Invalid business input, target, option or state. |
| `401` | Basic auth or agent token required/invalid. |
| `404` | Object or route not found. |
| `405` | Method not allowed. |
| `409` | Duplicate name, terminal scan or revoked agent. |
| `413` | Agent result too large. |
| `422` | Schema validation failed. |
| `502` | KEV download failed. |

## 13. Example client flow

```bash
BASE=http://127.0.0.1:8765

# 1. Create a customer
curl -s -X POST "$BASE/api/customers" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Acme"}'

# 2. Resolve the default group
curl -s "$BASE/api/customers/1"

# 3. Start a network scan
curl -s -X POST "$BASE/api/scans" \
  -H 'Content-Type: application/json' \
  -d '{
    "customer_id": 1,
    "group_id": 1,
    "scan_type": "network",
    "target": "192.0.2.10",
    "options": {"ports": "22,80,443", "profile": "common"}
  }'

# 4. Poll the scan
curl -s "$BASE/api/scans/1"

# 5. Export results
curl -s "$BASE/api/scans/1/export?format=json" -o scan-1.json
curl -s "$BASE/api/scans/1/export?format=csv" -o scan-1.csv
```

For agent and AD examples, see [AGENT_GUIDE.md](AGENT_GUIDE.md) and the OpenAPI
UI at `/api/docs`.
