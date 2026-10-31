# Enterprise Readiness Review

**Product:** VulnScanner 1.1.0  
**Review date:** 2026-10-31  
**Scope:** application code, API, authentication, scanner runtime, agent model,
database, backup/restore, deployment scripts, CI, tests and documentation.

This is a working backlog for making VulnScanner suitable for a regulated
enterprise deployment. It is intentionally blunt: the product is a strong
local-first scanner, but it is not yet a multi-user, multi-tenant or
high-availability platform.

## 1. Executive assessment

VulnScanner has a good security baseline for a single-analyst workstation:

- hashed Python dependency locks and a working CI pipeline;
- session login, TOTP MFA, recovery codes, CSRF tokens and login rate limiting;
- parameterised SQL, Fernet-encrypted credentials, SSRF-validated webhooks;
- online SQLite backups, guarded restore and a migration ledger;
- audit trail, inventory/history and a clean modular split of routers/pages.

It is **not yet enterprise-ready** for a shared service because the largest
gaps are organisational and operational rather than individual code defects:

1. **No RBAC or per-user identity.** There is one administrator. Audit records
   cannot distinguish two humans, and there is no read-only auditor or
   customer-scoped operator.
2. **No tenant isolation.** Customers are labels, not access boundaries.
3. **No high availability.** Scans, scheduling and notifications run inside one
   Python process with an in-process thread pool and SQLite.
4. **No protected backup/key lifecycle.** Backups and the live database are
   plaintext; the Fernet key has no rotation or KMS/HSM integration.
5. **Local file permissions are not hardened by default.** The data directory
   and database are created with the caller's umask (typically `0775`/`0644`).
6. **Scanner trust defaults are too permissive.** Web scans disable TLS
   verification and can silently downgrade HTTPS to HTTP; SSH host-key
   verification is optional.
7. **Observability and operational controls are thin.** No metrics, tracing,
   request IDs, readiness probe, structured audit shipping or graceful scan
   drain.
8. **Supply-chain and compliance artefacts are incomplete.** No SBOM, signed
   releases, `LICENSE`, `SECURITY.md`, dependency audit in CI or Windows CI.

## 2. Scorecard

| Area | Current grade | Enterprise target |
| --- | --- | --- |
| Authentication | B− | SSO/OIDC/SAML, WebAuthn, per-user MFA, password recovery |
| Authorization / tenancy | D | RBAC, per-customer scopes, service accounts, API scopes |
| Session / CSRF | B+ | Add Origin checks, `__Host-` cookies, HSTS, no-store, trusted hosts |
| Secrets / credentials | B− | KMS/HSM, key rotation, envelope encryption, mTLS |
| Data protection | C+ | Encryption at rest, encrypted backups, retention/legal hold |
| Audit | B− | Tamper-evident/WORM, read/export events, retention, SIEM shipping |
| Scanning safety | C+ | TLS verification by default, approval workflow, egress policy, rate limits |
| Agent security | C | mTLS, signed updates, version policy, least privilege, attestation |
| Reliability / HA | D+ | Queue/worker split, PostgreSQL option, distributed scheduler lock, drain |
| Observability | D | Metrics, tracing, request IDs, structured logs, readiness/liveness |
| Supply chain | B | SBOM, dependency audit, secret scanning, signed artefacts |
| Deployment | C | Docker/K8s/Helm/systemd artefacts, backup/DR runbooks |
| Compliance / docs | C+ | License, security policy, SOC 2/ISO mapping, DPIA, data-processing docs |

## 3. P0 — must fix before a shared or regulated deployment

### 3.1 Add users, roles and tenant scoping

**Current state:** one `admin_user` and one password hash
(`app/security.py`, `app/sessions.py`). All authenticated users are
administrators. Customer records are not access boundaries.

**Risk:** an auditor, service desk operator or customer-facing user cannot be
given least-privilege access. Audit attribution is weak because every human is
`admin`. A compromised operator account is a full compromise.

**Recommended change:**

- Add a `users` table: id, username, password hash, role, disabled flag, MFA
  state, created/last-login, failed-attempt counters.
- Roles: `admin`, `operator`, `auditor`, `viewer`; optional `customer_admin`
  scoped to one or more customer IDs.
- Enforce authorization in one dependency/middleware layer, not per-route
  ad-hoc checks. Cover every route, including exports, credentials, agents and
  server maintenance.
- Add OIDC/SAML SSO with group-to-role mapping and SCIM or a documented manual
  provisioning process.
- Add scoped API tokens (read-only, scan-run, admin) with hashed storage,
  expiry, last-used and revocation. Keep Basic auth only for bootstrap.
- Record the authenticated user ID, role and customer scope in every audit row.

**Acceptance criteria:** two users with different roles see different actions;
a customer-scoped user receives `403` for another customer’s objects; audit
rows identify the human; API tokens cannot exceed their scopes.

### 3.2 Harden filesystem permissions

**Current state:** `app/config.data_dir()` uses `mkdir()` with the process
umask; `app/database.connect()` lets SQLite create the database with the umask.
On a typical Linux host this produces a `0775` data directory and `0644`
database. `scripts/update.sh` writes a plaintext `.tgz` backup with the default
umask (`0664` in the review environment).

**Risk:** any local user can read findings, audit history, password hashes,
agent metadata and the encrypted credential blobs. A world-readable update
archive contains the database and credential key.

**Recommended change:**

- Set `umask 077` at the top of `run.sh` and `scripts/update.sh`; set restrictive
  ACLs in `run.bat` or document Windows ACL steps.
- After creating the data directory/database, enforce `0700` on the directory
  and `0600` on the database, `-wal`, `-shm`, credential key, `.env` and
  backups.
- `chmod 600` the update archive and use `umask 077` inside the backup step.
- Add a startup check that refuses to run with a world-readable database or
  key file, or logs a prominent warning with remediation.
- Add a test that asserts the modes on a fresh database.

**Acceptance criteria:** a fresh install creates `0700` directories and `0600`
database/backup files; CI verifies it; the hardening checklist matches reality.

### 3.3 Verify TLS during web scans and make downgrade explicit

**Current state:** `app/scanners/web.py` sets `session.verify = False` for every
web scan and `_resolve_web_target()` silently retries HTTPS over HTTP when the
HTTPS request fails.

**Risk:** a network attacker can alter responses, inject false findings, hide
real findings or observe probe traffic. Silent downgrade weakens the
authorisation boundary and can make a scan report look authoritative when it is
not.

**Recommended change:**

- Default to `verify=True` with the system trust store.
- Add an explicit per-scan `ignore_tls_errors` option (default `false`) with a
  visible warning in the UI and a scan event when enabled.
- Make HTTPS-to-HTTP fallback opt-in (`allow_http_fallback`, default `false`).
- Record the final scheme, certificate verification result and downgrade event
  in scan metadata.
- Apply the same default to WinRM (`verify_tls` currently defaults false in
  `app/scanners/authenticated.py`) and document the trade-off.

**Acceptance criteria:** a scan against a self-signed target fails with a clear
message unless the operator opts in; no silent scheme downgrade occurs.

### 3.4 Enforce SSH host-key verification

**Current state:** `app/scanners/authenticated.py` verifies SSH host keys only
when `VS_SSH_KNOWN_HOSTS` is configured; otherwise it logs the fingerprint and
continues.

**Risk:** credential disclosure to an impersonated SSH endpoint. This is
especially serious because authenticated scans use high-privilege accounts.

**Recommended change:**

- Default to `RejectPolicy` when a known_hosts file exists.
- For first contact, implement explicit trust-on-first-use: show the fingerprint
  in the UI, require an operator approval, then persist it.
- Refuse authenticated SSH scans with `verify_host_key=false` unless a
  deliberate “lab mode” setting is enabled and audited.
- Provide a GUI action to import/update known_hosts and show key changes.

**Acceptance criteria:** an unknown host key blocks the scan by default; the
operator can approve it once; a changed key is treated as a security event.

### 3.5 Encrypt and rotate backups and the credential key

**Current state:** `app/backup.py` writes a plaintext SQLite snapshot. The
credential key is a local Fernet key file or `VS_CREDENTIAL_KEY`; there is no
rotation workflow. Backups contain credentials, MFA secrets, audit history and
findings.

**Risk:** one stolen backup equals full compromise. Key compromise requires
re-entering every credential. Compliance frameworks generally require
encryption, key custody and tested restore procedures.

**Recommended change:**

- Encrypt backups with an operator-supplied passphrase or KMS key; use a
  streaming AEAD format with an authenticated header and version.
- Store backup metadata (hash, size, schema version, creation time) and verify
  it before restore.
- Implement key rotation: decrypt with old key, re-encrypt with new key, keep a
  key version identifier in the database.
- Prefer envelope encryption with a KMS/HSM or OS keyring; document an
  air-gapped offline-key procedure.
- Add backup retention, offsite copy, restore drills and RTO/RPO targets.
- Ensure update archives are encrypted too.

**Acceptance criteria:** a backup cannot be read without the backup key; key
rotation is tested; restore drills are documented and pass.

### 3.6 Add automatic pre-migration backup and upgrade gates

**Current state:** `init_db()` applies pending migrations on startup. A backup
is not automatically taken first. A failed migration can leave the process
unable to start.

**Risk:** an upgrade on a production host can destroy or partially migrate the
only database copy.

**Recommended change:**

- Before applying any pending migration, create a consistent backup and write a
  marker containing the from/to schema versions.
- Abort startup if the backup cannot be created or verified.
- Add a `--check`/`--dry-run` migration command that reports pending migrations.
- Add a tested downgrade/rollback path or a documented restore-only rollback.
- Include the migration ledger and pre-migration backup path in server status.

**Acceptance criteria:** starting an older database creates a verified backup
first; a deliberately broken migration aborts without changing the live data.

### 3.7 Add global request-size and body limits

**Current state:** FastAPI/Pydantic parses JSON and multipart bodies before
route-level size checks. Agent result and AD report limits are applied after
parsing. Agent capability/path lists are not length-bounded.

**Risk:** unauthenticated or low-privilege requests can exhaust memory/CPU with
oversized bodies. A compromised agent token can send a very large result before
the 25 MiB check runs.

**Recommended change:**

- Add ASGI middleware that rejects `Content-Length` over a configurable limit
  and counts streamed bytes.
- Use per-route limits: login/auth small, JSON API medium, agent result and AD
  import large but bounded.
- Bound all list fields (`capabilities`, `paths`, `modules`, references) in
  Pydantic.
- Return `413` with a stable error envelope and log the rejection in audit.

**Acceptance criteria:** a 100 MiB request is rejected before JSON parsing;
oversized agent results are rejected without memory growth; tests cover each
limit.

### 3.8 Make the audit trail defensible

**Current state:** `app/audit.py` records mutating API requests and explicit
security events. It is a normal SQLite table; administrators can edit/delete it
with database access. Reads and report exports are not recorded. Audit CSV
export does not neutralise spreadsheet formulas.

**Risk:** an insider can alter the trail. Sensitive report downloads have no
attribution. Opening an exported CSV in Excel can execute a formula injected
through a username, user-agent or target field.

**Recommended change:**

- Add a hash chain or signed batches, or ship each event to an append-only
  external SIEM/WORM store.
- Record report exports, credential reads, backup downloads and agent token
  events.
- Add retention/legal-hold policy and a purge job with audit of the purge.
- Apply the same CSV formula neutralisation used in `app/reporting.py` to
  `app/audit.py`.
- Add structured domain events (`scan.created`, `credential.updated`,
  `customer.deleted`, `settings.changed`) with object IDs and before/after
  summaries, not only `POST /api/...`.

**Acceptance criteria:** audit export cannot execute formulas; an auditor can
verify event integrity; report downloads appear in the trail; retention is
configurable.

## 4. P1 — required for a serious team deployment

### 4.1 Authentication and session hardening

- Add WebAuthn/passkeys and a password-recovery/reset CLI for the single-admin
  bootstrap case.
- Replace the in-memory login limiter with a persistent, shared limiter and
  add progressive delays, CAPTCHA or IP allowlisting. The current per-username
  limit allows an attacker to lock the administrator out for five minutes.
- Add `Origin`/`Referer` validation on state-changing requests in addition to
  CSRF tokens.
- Use `__Host-` cookie prefixes, `Cache-Control: no-store` on auth/API
  responses, HSTS on HTTPS, `TrustedHostMiddleware`, `Cross-Origin-Opener-Policy`
  and `Cross-Origin-Resource-Policy`.
- Add a session list/“sign out everywhere” UI and periodic expired-session
  cleanup.
- Rehash legacy PBKDF2 hashes to Argon2id on successful login; add breached
  password checks if policy requires it.

### 4.2 Agent security

- The internal CA/certificate UI claims mTLS, but the agent API authenticates
  with bearer tokens only. Either implement mTLS or remove the claim.
- Sign agent installers and update payloads; add an agent version policy and a
  controlled auto-update path.
- Add replay protection/timestamps and request signing for agent results.
- Enforce least-privilege service accounts and document endpoint hardening.
- Add rate limits and audit events for enrollment, heartbeat and job result
  submission.

### 4.3 Reliability and scale

- Split the in-process `ThreadPoolExecutor`/APScheduler from the web process.
  Use a durable queue (Redis/RQ, Celery, Dramatiq or a database-backed queue)
  and a separate worker.
- Add a distributed scheduler lock so multiple replicas do not run the same
  cron job.
- Add graceful shutdown: stop accepting new scans, let running scans finish or
  checkpoint, then exit. `shutdown(wait=False)` currently kills running work.
- Add queue depth/backpressure and per-scan/global timeouts.
- Add a PostgreSQL option with SQLAlchemy/Alembic or a repository abstraction.
  SQLite is excellent for a workstation but a single-writer bottleneck for a
  team.
- Add connection pooling and tune WAL/synchronous settings.
- Add scan retry/backoff and a dead-letter state.

### 4.4 Observability

- Add structured JSON logs with request IDs, user ID, route, status, duration
  and scan/job IDs; redact secrets and evidence.
- Add `/health/live` and `/health/ready` (DB, migrations, queue, scheduler).
- Export Prometheus metrics: request latency/errors, scan queue depth, scan
  duration, agent online/offline, notification failures, DB size/WAL, backup
  age, audit write failures.
- Add OpenTelemetry tracing across API → job → scanner → notification.
- Add alerting for repeated 401/403/429, backup failures, disk pressure,
  migration failures and agent token anomalies.
- Cache expensive status checks (`PRAGMA quick_check`, tool `--version`) instead
  of running them on every settings/status request.

### 4.5 Supply chain and CI

- Add `pip-audit`/OSV dependency audit and `gitleaks` to CI.
- Add SBOM generation (CycloneDX/SPDX) and attach it to releases.
- Add a coverage threshold and an integration test that exercises a real
  backup → migrate → restore cycle.
- Add Windows CI for the PowerShell/Python agents.
- Add container/Kubernetes manifests and a signed image pipeline if that is the
  target deployment model.
- Pin and verify external tool versions/checksums; the tool policy currently
  compares versions but does not verify provenance.
- Verify the SecLists download against a pinned hash/signature.
- Add a `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md` and a vulnerability
  disclosure process. Enterprise procurement will ask for these first.

### 4.6 Scanning safety and governance

- Add an approval workflow for new targets/customers and a scan window/maintenance
  calendar.
- Add a per-target/global rate limit and a maximum concurrent connection budget.
  Network scans can request up to 600 workers per scan; multiple scans can
  multiply that.
- Add an egress allowlist/proxy for scanner and notification traffic.
- Make “active checks” and “external tools” explicitly opt-in per scan policy,
  not just per dialog.
- Add a signed “rules of engagement” acknowledgement and target ownership
  metadata.
- Add a scan cancellation SLA and audit every cancellation.

### 4.7 Data lifecycle

- Add retention policies for scans, findings, scan events, audit, notification
  history, OSV cache and expired enrollment/session rows.
- Add legal hold and customer deletion/export workflows.
- Add a “delete all data for customer” operation with a two-person approval.
- Add indexes for common finding queries (customer/status/severity) and monitor
  slow queries.
- Add DB integrity/backup verification jobs.

### 4.8 Certificates and TLS

- Monitor certificate expiry and warn in the UI/server status.
- Support ACME or documented reverse-proxy certificate management; the built-in
  self-signed listener is for local use only.
- Use at least RSA-3072 or ECDSA P-256 for generated certificates; document
  cipher/TLS minimum policy.
- Remove or gate the unused internal CA until mTLS is implemented.

## 5. P2 — polish and operational maturity

- Add browser E2E tests for login, MFA, CSRF, storage relocation and audit.
- Add accessibility review (focus trap in modals, labels, keyboard navigation,
  contrast).
- Add API versioning (`/api/v1`) and a consistent error envelope with request
  IDs.
- Add idempotency keys for scan creation, restore and storage relocation.
- Add pagination to `/customers`, `/agents`, `/credentials` and other list
  endpoints that currently return full arrays.
- Add OpenAPI security schemes so generated clients understand session/Basic/
  MFA/API-token auth.
- Add notification delivery history UI and webhook HMAC signing with secret
  rotation, retries and backoff.
- Add SMTP TLS verification with an explicit CA/trust configuration.
- Add a management CLI (`vulnscanner backup`, `restore`, `migrate`,
  `reset-password`, `rotate-key`, `health`).
- Add Docker/Compose and Kubernetes/Helm examples, plus a systemd unit file in
  the repository rather than only documentation.
- Add a disaster-recovery runbook with RTO/RPO, restore drills and contact
  matrix.
- Add data-processing/compliance documentation: DPIA template, subprocessors,
  data residency, retention schedule, SOC 2/ISO 27001 control mapping.
- Add internationalisation and timezone-aware schedules if the product is sold
  outside one locale.

## 6. Quick wins (1–3 days each)

These are low-risk changes that materially improve the security posture:

1. `umask 077` in `run.sh` and `scripts/update.sh`; `chmod 0700` data dir,
   `0600` DB/WAL/SHM/backups; add a startup permission check.
2. Default web-scan TLS verification to on; make insecure/downgrade explicit
   and audited.
3. Neutralise formulas in `app/audit.py` CSV export.
4. Escape certificate paths in the Settings UI (currently inserted raw).
5. Add `Cache-Control: no-store` for `/api/` and `/login`, HSTS when HTTPS,
   `object-src 'none'`, `TrustedHostMiddleware` and an Origin check.
6. Add a global request-body limit middleware.
7. Take a verified backup automatically before migrations.
8. Cache tool-version checks and `PRAGMA quick_check` for server status.
9. Add `LICENSE`, `SECURITY.md` and a short vulnerability-disclosure policy.
10. Add `pip-audit` and `gitleaks` to CI.

## 7. Suggested roadmap

### 0–30 days

- Filesystem permissions, TLS verification defaults, audit CSV fix, security
  headers, body limits, pre-migration backup, license/security policy.
- Add CI dependency audit, secret scanning and coverage reporting.
- Write the RBAC/tenant data model and migration plan.

### 30–90 days

- Users/roles/OIDC, scoped API tokens, per-customer authorization, WebAuthn.
- Encrypted backups, key rotation, audit hash chain/SIEM shipping.
- Durable job queue, distributed scheduler lock, graceful drain.
- Metrics/readiness/structured logs.

### 90–180 days

- PostgreSQL option, HA deployment, container/K8s artefacts.
- mTLS/signed agent updates, agent version policy.
- Scan approval/egress/rate-limit governance.
- SOC 2/ISO 27001 evidence, DPIA, disaster-recovery drills.
- SBOM/signed releases and a supported upgrade/downgrade matrix.

## 8. What is already good

Do not lose these properties while adding enterprise features:

- Local-first operation with no mandatory cloud dependency.
- Hashed, universal dependency locks and reproducible installs.
- Parameterised SQL and a small, understandable schema.
- Fernet-encrypted credentials, hashed tokens and no secret values in API
  responses.
- Session auth with TOTP MFA, recovery codes, CSRF and rate limiting.
- Online SQLite backups, safety backups and transactional restore.
- SSRF validation for webhook/SecLists URLs.
- A useful audit trail, inventory/history and migration ledger.
- Clear authorised-use, security and upgrade documentation.
- A fast test suite (249 passing, 1 skipped at review time) and a working CI
  workflow.

## 9. Evidence map

| Finding | Evidence |
| --- | --- |
| Single administrator, no RBAC | `app/security.py`, `app/sessions.py`, docs known limitations |
| Data dir/DB permissions | `app/config.py` (`data_dir`, `database_path`), `run.sh`, `scripts/update.sh` |
| Update archive permissions | `scripts/update.sh` (`tar -czf`) |
| Web TLS verification disabled | `app/scanners/web.py` (`session.verify = False`) |
| Silent HTTPS→HTTP fallback | `app/scanners/web.py` (`_resolve_web_target`) |
| Optional SSH host-key verification | `app/scanners/authenticated.py` |
| Internal CA not used for mTLS | `app/certs.py`, `app/api.py` cert endpoints, UI claim |
| Plaintext backups | `app/backup.py` (`create_backup`) |
| No key rotation | `app/credentials.py` |
| In-process jobs/scheduler | `app/jobs.py`, `app/scheduler.py`, `app/main.py` shutdown |
| No request body limit | `app/main.py` middleware, `app/api.py` agent/AD routes |
| Audit CSV raw cells | `app/audit.py` (`export_csv`) |
| No read/export audit | `app/main.py` middleware logs only mutating requests |
| No metrics/tracing/readiness | absence of modules; `app/main.py` `/api/health` only |
| CI gaps | `.github/workflows/ci.yml` |
| No license/security policy | repository root |
| Tool/SecLists provenance | `app/tool_policy.py`, `app/scanners/subdomains.py` |
| Missing retention | no purge jobs for scans/audit/OSV/enrollment |

## 10. Definition of “enterprise ready”

A deployment should not be called enterprise-ready until all of the following
are true:

- [ ] Multiple named users with RBAC and per-customer scoping.
- [ ] SSO (OIDC/SAML) and WebAuthn or an approved compensating control.
- [ ] Scoped, expiring API tokens; no shared administrator credential.
- [ ] Tamper-evident audit export to an append-only system, with retention.
- [ ] Encrypted backups and a tested key-rotation/restore procedure.
- [ ] Data directory and database permissions enforced by code and CI.
- [ ] Scanner TLS verification on by default; explicit, audited insecure mode.
- [ ] SSH host-key verification enforced or explicitly approved.
- [ ] Durable job queue, graceful drain and a documented HA topology.
- [ ] Metrics, tracing, structured logs and readiness/liveness probes.
- [ ] SBOM, dependency/secret scanning, signed releases and a security policy.
- [ ] Disaster-recovery runbook with RTO/RPO and restore drills.
- [ ] License, security contact and compliance documentation available.

Until then, treat VulnScanner as a strong single-analyst workstation tool or a
small trusted-team deployment behind a hardened reverse proxy, not as a
multi-tenant enterprise platform.
