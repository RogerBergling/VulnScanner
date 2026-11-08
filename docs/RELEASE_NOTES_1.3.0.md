# VulnScanner 1.3.0 — scan depth, offline data and distributed correctness

This release focuses on the difference between a port scan and a vulnerability
scan, and on making the DMZ/satellite path dependable.

## Scan depth

- **Scan readiness diagnostics** before and after every web/network scan: which
  APIs, signature engines, tools, TLS trust settings and executor capabilities
  are available, and which stages were skipped and why.
- **Nuclei network-protocol templates** (`-pt tcp`) add signature coverage for
  SMB, RDP, SSH, databases, mail and other non-HTTP services.
- **Nuclei OAST** support through a self-hosted Interactsh server, opt-in per
  scan.
- **Authenticated web sessions**: HTTP Basic, bearer token, cookie header and
  custom headers. Secrets are encrypted and passed to Nuclei through a private
  temporary config file, not argv.
- **Agent CVE depth**: agent-uploaded service banners are fingerprinted and
  matched against NVD server-side.
- **Native Windows agent package inventory** plus local end-of-life checks;
  Python/npm packages still use OSV.
- **Visible self-signed/private-CA failures**: a web service that cannot be
  inspected now produces an explanatory finding instead of silently looking
  like an open port.
- **Custom CA bundle** for HTTPS targets and service probes.
- Scan guardrails are now editable for TCP connect timeout, testssl/OpenVAS host
  caps and Nuclei network target caps. Web CVE scanning honours the global CVE
  limits.

## Offline vulnerability data

- **Settings → Vulnerability data** synchronises product-level NVD records for
  every product in the fingerprint registry, the full EPSS score table and the
  CISA KEV catalogue.
- Cached NVD `configurations` are evaluated locally, so CVE matching and risk
  scoring continue during an internet outage or on an air-gapped network.
- OSV remains a live/cached per-package lookup; previously queried packages are
  reusable offline.

## Satellites and agents

- Satellite runner initialises its local cache/settings database, so CVE
  matching and Nmap no longer fail with `no such table: settings`.
- Satellite enrolment pins the master certificate SHA-256 fingerprint, so a
  default self-signed master works without `--insecure`.
- Optional dedicated **mTLS satellite listener** (`VS_SATELLITE_PORT`) requires
  the internal-CA client certificate and serves only the satellite API.
- Auto-routing resolves **CIDRs, single IPs, hostnames and web URLs** to
  advertised satellite subnets.
- Stale satellites are no longer treated as online; scheduled scans route to
  satellites and deliver schedule notifications through the satellite result
  path.
- Satellite bearer-token rotation from the GUI (token shown once).
- Satellite job claiming is transactional; satellite job expiry runs from the
  scheduler.
- Satellite endpoints are public only with their own bearer token, not dashboard
  Basic auth.

## Tool management

- Per-tool source selection: **System PATH**, **Explicit path**, **Managed
  download** or **Disabled**.
- Checksum-verified managed installs for Nuclei, Subfinder, Trivy, Gitleaks and
  OSV-Scanner under `$VS_DATA_DIR/tools/`.
- The release checksum file is mandatory; managed installation is refused when
  no checksum is published.

## Security and operations

- Optional **AES-256-GCM encrypted database backups** with an operator-supplied
  passphrase; the passphrase is never stored.
- **Credential-key rotation** re-encrypts every credential, web session and
  encrypted secret, keeps the previous key as `credential.key.old`, and refuses
  to run while scans are active.
- Scan readiness, NVD API key, custom CA, Interactsh, satellite listener and
  tool sources are all editable in the GUI.
- Backup/restore supports passphrase-protected `.vsenc` files and the
  `X-Backup-Passphrase` inspection header.

## Fixes

- A default scan policy only applies to its own scan type; it no longer breaks
  web scans.
- Wildcard scans that discover zero hosts complete with an explanatory finding
  instead of failing on the literal `*.domain` name.
- Service probes verify TLS by default and use the custom CA bundle.
- Dashboard/Server queue counters include `waiting_satellite`.
- Database backup/restore now includes scan policies, satellites, NVD/EPSS
  caches and satellite jobs.

## Remaining by design

- **RBAC/multi-user** is not included; this remains a single-analyst
  deployment.
- **Purple Knight native HTML/PDF import** is not included. Purple Knight values
  can be mapped to the documented AD JSON shape; PingCastle XML remains native.
- Form-login web macros, signed agent auto-updates and a full external
  plugin-pack format remain future work.
