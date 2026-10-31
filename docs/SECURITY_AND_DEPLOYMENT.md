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
| Unauthorised network access | Someone reaches port 8765 on a shared network | Loopback bind by default, session auth, MFA, CSRF tokens, login rate limiting, firewall, TLS reverse proxy |
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

### Session authentication, MFA and CSRF

Set a dashboard password in **Settings → Security** to enable authentication.
It is stored as a salted PBKDF2 hash in SQLite and included in database backups.
For initial provisioning, `VS_ADMIN_PASSWORD` is also accepted and migrated to
the database on startup; the plaintext line is then removed from the environment
file:

```bash
VS_ADMIN_USER=admin
VS_ADMIN_PASSWORD='a-long-random-password'
```

Browsers sign in at `/login` and receive an HttpOnly, SameSite=Strict session
cookie. Session tokens are stored as SHA-256 hashes with an absolute lifetime
(`VS_SESSION_TTL_HOURS`, default 12) and an idle timeout
(`VS_SESSION_IDLE_MINUTES`, default 30). Set `VS_TRUST_PROXY=true` only when the
app is reachable exclusively through a TLS-terminating reverse proxy that sets
`X-Forwarded-Proto` and `X-Forwarded-For`.

**Authenticator MFA** (TOTP) is available under **Settings → Security**. Enrolment
returns a manual key, an `otpauth://` URI and ten one-time recovery codes. MFA is
required for browser sessions and for Basic-auth API clients, which must send
`X-VS-MFA` or `X-VS-Recovery-Code`. TOTP replay is prevented by storing the last
accepted timestep. Enabling or disabling MFA revokes other sessions.

Cookie-authenticated state-changing requests require `X-CSRF-Token`; the token
is delivered in a non-HttpOnly `vs_csrf` cookie and in the login response.
Login attempts are rate-limited per source IP and per username (five failures per
five minutes per username; twenty per IP). A `429` response includes
`Retry-After`. Basic-auth API clients are stateless and exempt from CSRF.

Every mutating API request is recorded in the audit trail together with
authentication, MFA, settings, backup, restore and storage-relocation actions.
The Audit page supports filtering and CSV export.

The following paths remain public even when authentication is enabled:

- `/api/health`
- `/api/auth/login` and `/api/auth/status`
- `/api/agent/*` (these require an agent token where appropriate)
- `/agent/*` (agent scripts and installers)
- `/static/*`
- `/login`
- `/api/docs` and `/api/openapi.json`
- `/` and `/manual` are protected because they are not in the public list

Protect `/api/docs` at the reverse proxy if you do not want the schema exposed.

If no password is configured, authentication is disabled. The server logs a
warning at startup. This is acceptable only for a single-user workstation bound
to `127.0.0.1`.

### What authentication does not provide

VulnScanner has:

- One administrator identity, not multiple user accounts or groups.
- No role-based access control (RBAC) or SSO.
- No per-user audit trail (the audit trail records the single admin actor).
- No hardware-key (WebAuthn) support; MFA is TOTP and recovery codes.
- In-memory rate limiting, which resets on restart and is per process. Move the
  limiter to shared storage before running multiple Uvicorn workers.

### SSRF protection

Webhook URLs and the SecLists download URL are validated before every request.
The default policy rejects loopback, RFC1918, link-local, multicast and reserved
addresses, embedded credentials, non-HTTP(S) schemes and redirects to unsafe
destinations. Enable **Allow private-network outbound URLs** only for an
internal webhook or mirror. DNS rebinding remains a residual risk because the
hostname is resolved before the request; restrict egress at the network layer
for high-assurance deployments.

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
Environment=VS_ENV_FILE=/etc/vulnscanner/vulnscanner.env
ExecStart=/opt/vulnscanner/.venv/bin/python -m app.main
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vulnscanner /etc/vulnscanner
UMask=0077

[Install]
WantedBy=multi-user.target
```

Adjust `ReadWritePaths` if scans must write temporary clones elsewhere. If
repository scanning requires reading a path under `/home` or another protected
location, grant it explicitly rather than disabling hardening globally.

Environment file:

```bash
sudo install -d -o vulnscanner -g vulnscanner -m 0750 /etc/vulnscanner
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
sudo chown vulnscanner:vulnscanner /etc/vulnscanner/vulnscanner.env
sudo chmod 600 /etc/vulnscanner/vulnscanner.env
```

The service account must be able to rewrite this file because the GUI writes
listener, tool-path and advanced runtime changes to `VS_ENV_FILE`. Restart the
service after changing those values. Keep the directory and file access
restricted to the service account and administrators. Do not commit the
environment file to source control.

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
  scan guardrails, a salted admin password hash, encrypted TOTP secret, recovery
  code hashes and finding review status.
- The security audit trail and notification delivery history.
- Discovered inventory and per-asset finding history.

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
listener/HTTPS choices, a salted admin password hash, the encrypted TOTP secret
and recovery code hashes. Move backups to encrypted, access-controlled storage
on a schedule; the application does not rotate or encrypt them.

Encrypt backups at rest and restrict who can restore them. A backup contains
secrets, MFA material, audit history and AD findings. The credential key is a
separate file; a restored database without it cannot decrypt saved credentials
or the SMTP password.

### Storage relocation

**Settings → Advanced runtime → Storage location** validates absolute paths and
performs a guarded relocation: safety backup, online SQLite copy, integrity
check, credential-key and supporting-directory copy, environment-file update and
live process switch. The old location is retained. Active scans block relocation
unless forced, and an existing target database requires overwrite confirmation.
Restart afterwards so the launcher and certificate paths are consistent. The
same operation can be performed manually while the service is stopped by moving
the data directory and updating `VS_DATA_DIR`/`VS_DATABASE`.

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
- Authentication, MFA, settings, backup, restore, storage relocation and every
  mutating API request are recorded in the audit trail. The trail is not
  cryptographically tamper-evident; ship it to an append-only log platform if
  your policy requires that property.
- Protected resources and evidence are not encrypted at rest by the
  application. The TOTP secret, SMTP password and saved target credentials are
  encrypted with the credential key.

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
- [ ] Authenticator MFA enrolled and recovery codes stored offline.
- [ ] Reverse proxy requires HTTPS and restricts source networks.
- [ ] `VS_TRUST_PROXY` set only when the app is reachable exclusively through a
      trusted proxy that sets `X-Forwarded-Proto`/`X-Forwarded-For`.
- [ ] Login rate limits and audit alerts monitored.
- [ ] Firewall allows only the proxy and required agent paths.
- [ ] Dedicated unprivileged service account.
- [ ] Data directory mode `0700`, database and environment file mode `0600`
      or stricter.
- [ ] Backups configured, encrypted and restore-tested.
- [ ] `VS_ENABLE_EXTERNAL_APIS` set according to policy.
- [ ] Optional tools installed from trusted sources, pinned by path and covered
      by the tool version policy.
- [ ] Private-network outbound URLs left disabled unless required.
- [ ] Agent installers reviewed; SYSTEM/root use approved or avoided.
- [ ] KEV sync policy agreed; the catalogue is refreshed before relying on KEV
      annotations.
- [ ] Retention and authorised-use rules documented.
- [ ] Host and Python dependencies patched.
- [ ] Agent inventory reviewed and stale agents revoked.

## 10. Known limitations and residual risk

- There is one administrator identity. Session auth, TOTP MFA, recovery codes,
  CSRF tokens, login rate limiting and an audit trail are built in, but there is
  no RBAC, SSO/WebAuthn, per-user attribution or approval workflow.
- The built-in TLS listener uses a self-signed certificate and is enabled by
  default for local use; disable it with `VS_SSL=false` behind a TLS reverse
  proxy. Use a reverse proxy for production TLS and edge controls. Login rate
  limiting is in-memory and per process.
- SSRF validation covers webhook and SecLists URLs, but DNS rebinding is a
  residual risk; restrict egress at the network layer for high-assurance
  deployments.
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
