# Security and Deployment

VulnScanner stores vulnerability data, customer information, endpoint inventory,
collected secrets and Active Directory configuration. Treat the server, its
database and its reports as sensitive security data.

This document describes the supported deployment models, the security controls
that exist, the controls that do **not** exist, and a practical hardening and
backup checklist. Read [AUTHORIZED_USE.md](AUTHORIZED_USE.md) before scanning
anything.

## 1. Security model and threat model

### Assets to protect

- The SQLite database, which contains customers, assets, scans, findings,
  evidence, agent records and cached vulnerability data.
- Certificates and the credential encryption key under `VS_DATA_DIR`.
- Agent tokens, even though only their SHA-256 hashes are stored.
- API responses and exported reports.
- Secrets discovered in repositories or endpoint files, which may appear in
  finding evidence (normally redacted, but treat all evidence as sensitive).
- Active Directory reports and findings, which describe domain weaknesses.
- The server host and the credentials used to operate optional tools.

### Relevant threats

| Threat | Examples | Primary controls |
| --- | --- | --- |
| Unauthorised network access | Someone reaches port 8765 on a shared network | Loopback bind by default, HTTP Basic auth, firewall, TLS reverse proxy |
| Credential guessing | Repeated Basic auth attempts | Strong password, network allow-list, reverse-proxy rate limiting (not built in) |
| Stolen agent token | Token copied from an endpoint | Hashed storage, TLS, file permissions, revocation, re-enrolment |
| Malicious scanned content | A web page, repository file or AD report crafted to attack the scanner | Bounded parsing, size limits, no shell interpolation, read-only collection |
| Unsafe optional tools | A malicious Nuclei template, Semgrep rule or executable path set in Settings | Install from trusted sources, pin versions, restrict who can change tool directories, enable dashboard authentication |
| Third-party enumeration | Subfinder queries passive sources about a domain | Authorise the disclosure, or disable passive enumeration and use the local wordlist only |
| Local privilege abuse | Another user reads the database or `.env` | Dedicated service account, restrictive file modes, host access control |
| Data loss | Disk failure, accidental deletion, upgrade | Backups of the database plus WAL/SHM, tested restore |
| CSRF/XSS in the interface | A malicious site causes state changes | Same-origin SPA, strict CSP, no inline handlers, JSON APIs; see limitations |

### Trust boundaries

- The browser is trusted only after authentication. The SPA has no separate
  privilege model; every authenticated user can do everything.
- Endpoints are untrusted data sources. Agent payloads are normalised and
  severity-checked server-side.
- Scanned systems and repositories are untrusted. Their content is parsed but
  never executed by the scanner.
- Optional command-line tools run as the VulnScanner service account and
  therefore inherit its access. Install only tools you trust.
- Python dependencies are installed from a hashed lock; see
  [DEPENDENCIES.md](DEPENDENCIES.md) for the update and audit process.
- The host operating system is the final security boundary. VulnScanner does not
  provide a sandbox.

## 2. Authentication and transport

### HTTP Basic authentication

Set a dashboard password in **Settings → Security** to enable HTTP Basic
authentication for the dashboard and `/api` routes. It is stored as a salted
PBKDF2 hash in SQLite and included in database backups. For initial
provisioning, `VS_ADMIN_PASSWORD` is also accepted and migrated to the database
on startup:

```bash
VS_ADMIN_USER=admin
VS_ADMIN_PASSWORD='a-long-random-password'
```

If no password is configured, authentication is disabled. The server logs a
warning at startup. This is acceptable only for a single-user workstation bound
to `127.0.0.1`.

HTTP Basic authentication sends the password with every request. It is **not**
encrypted by itself. Always use HTTPS when the service is reachable over a
network.

The following paths remain public even when Basic auth is enabled:

- `/api/health`
- `/api/agent/*` (these require an agent token where appropriate)
- `/agent/*` (agent scripts and installers)
- `/static/*`
- `/api/docs` and `/api/openapi.json`
- `/` and `/manual` are protected because they are not in the public list

Protect `/api/docs` at the reverse proxy if you do not want the schema exposed.

### What authentication does not provide

VulnScanner has:

- One administrator identity, not user accounts or groups.
- No role-based access control (RBAC).
- No per-user audit trail.
- No login lockout or built-in rate limiting.
- No application-level CSRF tokens.

VulnScanner includes a built-in HTTPS listener that is **enabled by default**
(`VS_SSL=true`) and uses a self-signed certificate. It is intended for local
testing and small trusted networks, not as a replacement for a managed
certificate. The certificate and key are created under `data/certs/` and the
browser will show a self-signed warning. The launchers `run.sh` and `run.bat`
enable it automatically. Set `VS_SSL=false` when a TLS-terminating reverse proxy
handles HTTPS, or when you deliberately want plain HTTP on loopback. For any
service reachable from another machine, use a TLS-terminating reverse proxy for
certificate management, access control, rate limiting and request logging. Do
not expose plain HTTP to an untrusted network.

### Reverse proxy example

Bind VulnScanner to loopback and let a TLS-terminating proxy publish it:

```bash
VS_HOST=127.0.0.1
VS_PORT=8765
```

Minimal nginx server block (TLS certificate configuration omitted):

```nginx
server {
    listen 443 ssl;
    server_name scanner.example.com;

    client_max_body_size 30m;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
        proxy_read_timeout 120s;
    }
}
```

The `client_max_body_size` allowance covers agent result uploads, which are
limited to 25 MiB by the application. Agent reports are uploaded over normal
HTTP; scans themselves run asynchronously, so a long scan does not require a
long-lived browser connection.

If agents connect through the proxy, use the public HTTPS URL when enrolling:

```bash
--server https://scanner.example.com
```

Do not put an additional authentication layer in front of `/api/agent/*` unless
the agent supports it; those endpoints authenticate with agent tokens.

## 3. Supported deployment patterns

### A. Single analyst workstation

- Bind to `127.0.0.1`.
- Basic auth is optional but recommended.
- Use the default HTTPS listener with a self-signed certificate, or set
  `VS_SSL=false` for plain HTTP on loopback.
- Keep the project directory and data directory readable only by your account.
- Run scans locally. Optional tools can be installed per user.
- Back up `data/` before upgrades.

This is the default configuration and the lowest-risk deployment.

### B. Small team server behind a reverse proxy

- Bind to `127.0.0.1`, not `0.0.0.0`.
- Terminate TLS at nginx, Caddy, Traefik or an equivalent proxy.
- Require VPN or an IP allow-list for analyst access.
- Use a dedicated service account and a data directory outside the web root.
- Add reverse-proxy rate limiting and logging.
- Protect backups and exports as sensitive data.
- Agents connect to the proxy over HTTPS.

### C. Air-gapped or restricted-egress installation

- Set `VS_ENABLE_EXTERNAL_APIS=false`.
- Leave **Allow external APIs** off in Settings.
- Expect no OSV lookups, no GitHub cloning and no KEV sync. Built-in header,
  port, secret, source and configuration checks continue to work.
- Pre-install optional tools only if you have a trusted offline source. Nuclei
  templates and Semgrep registry rules would also need to be available locally;
  the current integrations expect their normal online configuration.
- If you need OSV or KEV data offline, synchronise it on a connected instance
  and transfer the database or build a controlled mirror through your normal
  change process. Do not copy an untrusted production database without review.

VulnScanner does not ship a container image, Kubernetes manifests or a
multi-node deployment. Running two server instances against one SQLite file is
not supported.

## 4. Host and service hardening

### Dedicated account and file permissions

Run VulnScanner as a dedicated, unprivileged account:

```bash
sudo useradd --system --home /opt/vulnscanner --shell /usr/sbin/nologin vulnscanner
sudo install -d -o vulnscanner -g vulnscanner -m 0750 /var/lib/vulnscanner
sudo install -d -o vulnscanner -g vulnscanner -m 0750 /var/lib/vulnscanner/reports
```

The database, certificates and reports should not be world-readable:

```bash
chmod 700 /var/lib/vulnscanner
chmod 600 /var/lib/vulnscanner/vulnscanner.db
```

Agent state files and `.env`/environment files contain credentials. Restrict
them to the service account and administrators.

The service account needs read access to every path you ask it to scan. Do not
solve this by running the whole server as root unless the assessment explicitly
requires privileged file access and you have reviewed the risk. Prefer:

- A dedicated account with targeted group membership.
- Copies of source repositories with appropriate ownership.
- Agent-side secrets scanning for paths that only the endpoint can read.

### systemd unit example

```ini
[Unit]
Description=VulnScanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vulnscanner
Group=vulnscanner
WorkingDirectory=/opt/vulnscanner
EnvironmentFile=/etc/vulnscanner/vulnscanner.env
ExecStart=/opt/vulnscanner/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vulnscanner
UMask=0077

[Install]
WantedBy=multi-user.target
```

Adjust `ReadWritePaths` if scans must write temporary clones elsewhere. If
repository scanning requires reading a path under `/home` or another protected
location, grant it explicitly rather than disabling hardening globally.

Environment file:

```bash
sudo install -d -m 0750 /etc/vulnscanner
sudo sh -c 'umask 077; cat > /etc/vulnscanner/vulnscanner.env <<EOF
VS_HOST=127.0.0.1
VS_PORT=8765
VS_SSL=false
VS_ADMIN_USER=admin
# Initial password; migrated to the database hash on first start.
VS_ADMIN_PASSWORD=replace-with-a-long-random-password
VS_DATA_DIR=/var/lib/vulnscanner
VS_ENABLE_EXTERNAL_APIS=true
EOF'
sudo chown root:vulnscanner /etc/vulnscanner/vulnscanner.env
sudo chmod 640 /etc/vulnscanner/vulnscanner.env
```

Do not commit the environment file to source control.

### Network exposure

| Direction | Default | Needed for |
| --- | --- | --- |
| Inbound to server | `127.0.0.1:8765` only | Browser/API on the same host |
| Inbound through proxy | 443/tcp from analysts and agents | Team deployment |
| Outbound from server | 443/tcp to `api.osv.dev` | OSV dependency lookups |
| Outbound from server | 443/tcp to `www.cisa.gov` | Manual KEV sync |
| Outbound from server | 443/tcp to `github.com` | GitHub repository scans |
| Outbound from server | 443/tcp to the Semgrep registry | Semgrep `--config auto` |
| Outbound from server | 443/tcp to OSV/package sources | `osv-scanner` |
| Outbound from server | Target ports/hosts | Authorised web and network scans |
| Outbound from agent | 443/tcp to the server/proxy | Enrolment, heartbeat, jobs, results |

Nmap, Nuclei, Gitleaks and local repository scans do not require a VulnScanner
cloud service. They may still contact their own update sources if configured to
do so.

## 5. Data protection and backup

### What is stored

- Customer, group and asset metadata.
- Scan options, events, findings, evidence and raw tool output.
- Agent identity, hashed tokens and endpoint metadata.
- Cached OSV responses and the KEV catalogue.
- Settings, including tool paths, listener/HTTPS choices, SMTP, notifications,
  scan guardrails, a salted admin password hash and finding review status.

Temporary GitHub clones live under the data directory while a scan runs and are
removed afterwards. Report exports are generated in memory and streamed; they
are not retained by the application.

### Backup

### Keep data outside the Git checkout

For any deployment that uses Git, set `VS_DATA_DIR` to an absolute path outside
the repository, for example:

```bash
VS_DATA_DIR=/var/lib/vulnscanner
VS_DATABASE=/var/lib/vulnscanner/vulnscanner.db
```

`data/`, `*.db`, `*.db-wal`, `*.db-shm`, `.env` and `reports/` are ignored by
Git, so a normal `git pull` does not remove them. However, `git clean -fdx`
deletes ignored files and will remove the database, certificates, credential key
and backups. Never use `git clean -fdx` on a production checkout. See
[UPGRADING.md](UPGRADING.md) for the safe update procedure.

The safest backup is taken while the service is stopped:

```bash
sudo systemctl stop vulnscanner
sudo cp -a /var/lib/vulnscanner/vulnscanner.db \
           /var/lib/vulnscanner/vulnscanner.db-wal \
           /var/lib/vulnscanner/vulnscanner.db-shm \
           /secure/backup/
sudo systemctl start vulnscanner
```

The `-wal` and `-shm` files are part of a consistent live database. Copying only
the `.db` file while the server is running can lose recent commits. If the
SQLite CLI is available and you need an online backup, use SQLite's backup
mechanism:

```bash
sqlite3 /var/lib/vulnscanner/vulnscanner.db \
  ".backup '/secure/backup/vulnscanner-$(date +%F).db'"
```

The **Server** page exposes the same online backup API. It writes a consistent
copy to the chosen absolute directory/file path, or to
`<data>/reports/backups/` when no path is given, and records the last backup
time. The database contains all application settings, including tool paths,
listener/HTTPS choices and a salted admin password hash. Move backups to
encrypted, access-controlled storage on a schedule; the application does not
rotate or encrypt them.

Encrypt backups at rest and restrict who can restore them. A backup contains
secrets and AD findings.

### Restore

Use **Server → Restore database** and select:

- **Everything** for a full database restore, including settings, agents and
  credentials.
- **Scan data only** to replace scan history while keeping current settings,
  agents and credentials. Customers, groups and assets are merged by name.
- **Settings only** to restore settings without changing scans.

A safety backup is written first, active scans block scan-data restores, and
SQLite integrity/foreign-key checks run before commit. A failed restore rolls
back. If listener settings changed, restart the service. If the admin password
changed, sign in with the restored password.

For an offline/manual restore:

1. Stop the service.
2. Keep a copy of the current database for investigation.
3. Replace the database (and remove stale `-wal`/`-shm` files from the old
   database).
4. Restore ownership and mode.
5. Start the service and verify `/api/health`, the dashboard, recent scans and
   scan event history.

Test a restore on a non-production copy before relying on the procedure.

### Retention

Deleting a customer removes its groups, assets, agents, scans and findings.
Deleting an asset or group also removes linked scans. Revoking an agent preserves
historical findings. Define a retention period for evidence and exports and
delete data you no longer need.

## 6. Agent security

- Agents use outbound polling; no inbound endpoint port is required.
- Enrolment tokens are single-use and expire after 1-168 hours.
- Agent tokens are stored as SHA-256 hashes. A stolen token is still a bearer
  credential until the agent is revoked.
- Use HTTPS. `--insecure`/`-Insecure` disables certificate checking and is for
  controlled labs only.
- The Linux installer defaults to a dedicated unprivileged `vulnscanner`
  account. Using `--user root` increases the impact of a compromised agent.
- The Windows installers run the scheduled task as SYSTEM by default so it can
  read system configuration and AD. Pass `-ServiceAccount` on the native
  installer, or use `-NoService`, a dedicated account and your own scheduler if
  that is not acceptable.
- The native Windows installer downloads the agent from the server over HTTPS
  and restricts the program and state ACLs with `icacls`. Review the script
  before running it and verify the server URL.
- Delegated network scans originate from the endpoint's network position. Only
  authorised agents should be allowed to run them, and the server enforces the
  host limit and agent customer/group scope.
- Scope `secrets` and `repo` modules to explicit paths. The server rejects those
  modules without paths.
- Revoke lost or decommissioned endpoints. Re-enrolment requires a new one-time
  token.
- Treat `pending-result.json` and the agent configuration as secrets.

See [AGENT_GUIDE.md](AGENT_GUIDE.md) for installation and file locations.

## 7. Optional tools

Optional tools run as the VulnScanner service account. They can read scanned
repositories, make outbound connections and consume significant CPU or memory.

- Install from official releases or your distribution's package manager.
- Record versions and update them deliberately.
- Do not let untrusted users modify tool binaries, template directories or
  plugin paths.
- Review Nuclei templates and Semgrep rules before use. They are executable
  scanning logic, even when they do not run arbitrary code.
- Use `VS_*_PATH` to pin the exact executable in a service deployment. Settings
  can also edit these paths and applies them immediately; anyone who can reach
  an unauthenticated dashboard can therefore choose which executable the scanner
  runs. Set `VS_ADMIN_PASSWORD` before exposing the UI beyond loopback.
- Nmap's `vulners` script sends service/version information to a third-party
  service. Use it only when that disclosure is authorised.
- Subfinder sends the scanned domain to passive public sources. Use the local
  wordlist-only mode when that disclosure is not authorised.
- Trivy may download its vulnerability database when external APIs are enabled.
  In air-gapped deployments, pre-populate `data/trivy-cache` and leave external
  APIs disabled (`--skip-db-update` is then used).
- **Load SecLists list** downloads a wordlist over HTTPS from GitHub. The
  download is explicit; scans never fetch wordlists automatically.
- Semgrep `--config auto` contacts the Semgrep registry. Provide local rules or
  disable external tools in restricted environments.
- Gitleaks and Trivy findings may contain credential fragments; evidence is
  redacted but should still be handled as sensitive.

The built-in scanners remain available if a tool is missing or disabled.

## 8. Logging and monitoring

- Uvicorn logs requests, startup information and unhandled errors to stdout or
  the service journal.
- Each scan has a timestamped event log in the database. Finding status changes
  are also recorded there.
- Settings changes, logins and agent heartbeats do not have a separate
  tamper-evident audit trail.
- Protected resources and evidence are not encrypted at rest by the
  application.

For a team deployment:

- Ship service logs to your normal log platform.
- Alert on repeated 401 responses, unexpected outbound destinations, disk-space
  pressure and database errors.
- Monitor backup success.
- Restrict and review access to the data directory.
- Periodically review agent inventory and revoke unknown agents.

## 9. Hardening checklist

Before exposing the service beyond localhost:

- [ ] `VS_HOST=127.0.0.1` and a TLS reverse proxy in front for remote access.
      Verify the active bind address in **Settings → Security** or on the
      **Server** page after any change.
- [ ] `VS_SSL=false` when the reverse proxy terminates TLS; leave the default
      `true` only for the local self-signed listener.
- [ ] Dashboard password configured with a long, unique value.
- [ ] Reverse proxy requires HTTPS and restricts source networks.
- [ ] Firewall allows only the proxy and required agent paths.
- [ ] Dedicated unprivileged service account.
- [ ] Data directory mode `0700`, database and environment file mode `0600`
      or stricter.
- [ ] Backups configured, encrypted and restore-tested.
- [ ] `VS_ENABLE_EXTERNAL_APIS` set according to policy.
- [ ] Optional tools installed from trusted sources and pinned by path.
- [ ] Agent installers reviewed; SYSTEM/root use approved or avoided.
- [ ] KEV sync policy agreed; the catalogue is refreshed before relying on KEV
      annotations.
- [ ] Retention and authorised-use rules documented.
- [ ] Host and Python dependencies patched.
- [ ] Agent inventory reviewed and stale agents revoked.

## 10. Known limitations and residual risk

- Basic auth is the only built-in authentication mechanism.
- There is no RBAC, no per-user attribution and no approval workflow.
- The built-in TLS listener uses a self-signed certificate and is enabled by
  default for local use; disable it with `VS_SSL=false` behind a TLS reverse
  proxy. There is no WAF, rate limiter or account lockout. Use a reverse proxy
  for production TLS and edge controls.
- There are no application-level CSRF tokens. The JSON API, same-origin design
  and CSP reduce exposure, but a proxy with strict origin policy is recommended.
- Scan workers are in-process and are lost on restart.
- SQLite supports one writer at a time; very large concurrent workloads are not
  the target use case.
- Findings can contain sensitive evidence. Database access equals finding
  access.
- Built-in checks are not exploit-grade and can produce false positives or miss
  issues.
- Optional tools and their rules are outside VulnScanner's trust boundary.
- The agent can read anything its service account can read.

## 11. Incident response

If you suspect the server or an agent is compromised:

1. Stop the VulnScanner service or isolate the host.
2. Preserve a copy of the database and logs for investigation. Do not keep
   operating on the only copy.
3. Rotate the administrator password and any credentials found in scan evidence
   or agent configuration.
4. Revoke affected agents and re-enrol them with new one-time tokens.
5. Review recent scans, targets, agent jobs, settings changes and outbound
   connections for unauthorised activity.
6. Check whether exported reports or backups were accessed.
7. Restore from a known-good backup if integrity is in doubt.
8. If secrets were exposed, rotate them at the source; deleting a finding does
   not revoke a credential.
9. Follow your organisation's incident, privacy and customer-notification
   obligations.

If a scan accidentally touched an unauthorised target, stop the scan, preserve
the evidence, notify the target owner and your authorising contact, and document
the scope and impact. See [AUTHORIZED_USE.md](AUTHORIZED_USE.md).
