# VulnScanner Distributed Scanning and Vulnerability Depth — Roadmap

**Status:** approved direction (2026-11-06). Implementation happens in phases;
this document records the decisions so the code and the docs stay aligned.

## 1. Goal

Turn VulnScanner from a strong port/configuration scanner into a
Nessus-class vulnerability scanner with:

- A real vulnerability-signature engine (not just port rules).
- Distributed scanning across master and satellite servers, so a DMZ can be
  scanned while only VulnScanner-server to VulnScanner-server traffic is
  permitted.
- Everything driven from one GUI (the master), with all tuning available in
  the GUI.

## 2. Locked decisions

| Topic | Decision |
| --- | --- |
| Server-to-server topology | Satellites poll the master over outbound HTTPS — the same proven model as endpoint agents. The master never opens an inbound connection to a satellite. |
| Results ownership | Single pane of glass: the master owns all data. Satellites execute scans and stream results back to the master's database. |
| S2S authentication | Mutual TLS using an internal CA, plus a one-time pairing code for authorisation. Certificates already exist per install (`app/certs.py`); pairing issues/rotates them. |
| Vulnerability signatures | Four layers: (1) Nuclei promoted to a default-on built-in engine with automatic template updates; (2) built-in banner/CPE → CVE matching against a local NVD/OSV cache with CVSS/KEV/EPSS scoring; (3) new built-in network service probes (SMB signing, SNMP defaults, unauthenticated Redis/Mongo/Elastic/Docker, RDP NLA, VNC, safe default-credential checks); (4) Greenbone/OpenVAS as an optional external engine. |
| SQL injection | `sqlmap` becomes an optional external tool integration (GPL-2.0; invoked as a subprocess, never linked or bundled — compatible with the MIT license of this project). GUI toggle + path setting like the other optional tools. Typically present on Kali; documented install for other distributions. |
| Internet access | Scanner servers have internet access. External APIs (OSV.dev, NVD, Nuclei templates, EPSS, CISA KEV) are used online, with local caches. |
| PingCastle / Purple Knight | Native file import: upload provider report files in the GUI and the server parses them into findings. The existing JSON import remains for custom reports. |
| Licensing | All newly integrated external tools run as separate processes or HTTP clients. Their licenses (GPL for sqlmap and GVM components, MIT for Nuclei templates) do not affect VulnScanner's MIT license as long as nothing is bundled, linked or redistributed. |

## 3. Phases

### Phase 1 — Real vulnerability results (addresses "it looks like a port scan")

1. **Nuclei as a default-on engine.** — **done** (`app/scanners/nuclei.py`:
   default-on per scan with an opt-out option, tag selection per scan and a
   Settings default, daily 03:30 UTC template auto-update plus a Settings
   "update now" action, last-update status in the GUI).
2. **Banner/CPE → CVE matching.** — **done** (`app/scanners/cpe.py`: fingerprint
   registry for SSH/web/database banners and headers, NVD API 2.0 client with
   SQLite cache and self-throttling, CPE range evaluation, EPSS enrichment,
   per-scan toggle and Settings guardrails; live-verified against NVD/EPSS).
3. **Network service probes.** — **done** (`app/scanners/services.py`: raw-socket
   SMB2 signing negotiation, SNMPv1/v2 default-community detection over UDP,
   unauthenticated Redis/MongoDB/Elasticsearch/Docker/Memcached/Kibana
   detection, RDP NLA negotiation parsing and VNC security-type handshake;
   read-only; per-scan toggle in the network scan dialog).
4. **Scan policies** (GUI-defined, reusable). — **done**
   (`app/policies.py` + migration 7: five built-in presets — Discovery,
   Basic network scan, Web application, PCI-DSS, OWASP Top 10 — plus
   operator-defined policies with JSON options, managed in Settings; a
   policy dropdown on the scan dialog; an optional default policy; policy
   options merge with explicit scan options winning).
5. **sqlmap integration.** — **done** (`app/scanners/sqlmap.py`, double-gated:
   Settings → Dangerous tools switch plus a per-scan option; runs against
   parameterized URLs discovered by the built-in injection probes, bounded by
   `max_sqlmap_targets`; GPL tool invoked as a separate process, never
   linked/bundled).
6. **Risk scoring upgrade.** EPSS enrichment — **done**; KEV/EPSS-weighted
   risk score — **done** (`utils.context_risk_score`: boosts critical/high
   findings that are KEV-listed or high-EPSS, capped to the 0-100 scale);
   MITRE ATT&CK mapping — **done** (`app/scanners/attack.py`: curated
   CWE/category → technique mapping attached as `raw.attack`, shown as
   ATT&CK/KEV/EPSS tags in the findings table).

### Phase 2 — Master / satellite architecture (DMZ scanning)

1. Satellite enrolment with one-time pairing code + mTLS (internal CA). —
   **done** (pairing codes, CA-signed client certs with pinned fingerprints,
   hashed bearer tokens, revocation).
2. Satellites advertise network position (subnets they can reach) and poll
   the master for jobs; results stream back to the master DB. — **done**
   (`app/satellite.py` runner: enroll/run, outbound polling over HTTPS,
   database-free local execution of web/network engines).
3. **Automatic executor selection** — **done** (CIDR overlap between target
   and advertised subnets routes to the satellite; per-scan Executor
   dropdown: auto / server / specific satellite).
4. Satellite health, offline queueing, job timeout, revocation and key
   rotation from the master GUI. — **done** (health/offline/revocation/timeout
   plus one-click token rotation from the satellite edit dialog).
5. Multi-hop support later (satellite → satellite) if needed. (open)

### Phase 3 — AD report import and intelligence

1. Native PingCastle XML report parsing — **done** (parser, import API, GUI
   upload and tests). Purple Knight native import — **skipped** per operator
   decision.
2. Delta/trend reporting — **done** (scan detail now offers **Delta vs
   previous**: new/fixed/severity-changed findings and an improved badge,
   backed by `/api/trends/compare`).
3. Compliance mapping packs — **done**
   (`app/scanners/compliance.py`: curated PCI DSS 4.0, ISO/IEC 27001:2022
   and CIS Controls v8 subsets; the scan page's **Compliance** button maps
   findings to controls with severity counts, guidance and samples).

### Phase 4 — Greenbone/OpenVAS optional engine

1. Optional external engine using the GVM stack — **done**
   (`app/scanners/openvas.py`: gvm-cli task flow — create target/task,
   start, poll, fetch report, parse results into findings with GMP severity
   mapping; gated by a Settings toggle plus a per-scan option, encrypted
   GVM credentials, per-scan host cap). Requires a working GVM stack
   (PostgreSQL, gvmd, ospd-openvas, community feed).

### Phase 5 — Scan depth, offline operation and usability

1. **Scan readiness diagnostics** — done (`app/scan_diagnostics.py` and the scan
   dialog/detail panels show missing tools, disabled stages, offline APIs, TLS
   trust and executor limitations).
2. **Offline vulnerability data** — done (`app/vulnerability_data.py`: NVD
   product cache, full EPSS table, KEV sync; Settings → Vulnerability data).
3. **Nuclei network-protocol templates** — done (`app/scanners/nuclei.py` runs
   `network` templates against open non-HTTP services; per-scan opt-out).
4. **Agent depth** — done for banner/CPE → NVD CVE enrichment and Windows
   package inventory/EOL checks; web/Nuclei remain server/satellite-only.
5. **Satellite correctness** — done (local cache DB init, certificate
   fingerprint pinning, dedicated mTLS listener, IP/hostname/URL routing).
6. **Custom CA and self-signed UX** — done (custom CA bundle setting; visible
   finding when a web service cannot be inspected).
7. **Authenticated web sessions** — done for Basic/bearer/cookie/custom headers;
   form-login macros remain open.
8. **Tool source manager** — done (system/path/managed/disabled, checksum-
   verified managed installs for five tools).
9. **Encrypted backups and key rotation** — done (AES-256-GCM backup
   passphrase; credential-key rotation keeps the old key).
10. **OAST support** — done (per-scan Interactsh opt-in and Settings).
11. **RBAC/multi-user** — open; deliberately skipped for the current
    single-analyst deployment.
12. **Purple Knight native import** — skipped per operator decision.
13. **Signed agent/satellite auto-updates**, a signed custom plugin-pack format
    and form-login web macros — open; the current web session support covers
    Basic, bearer, cookie and custom-header authentication.

## 4. Suggested next-level features (candidates, not yet committed)

- **Live exposure monitoring:** frequent lightweight port watches on critical
  assets that alert on new/changed services within minutes.
- **TLS fingerprinting (JA3/JARM)** on discovered HTTPS services to spot
  outdated or anomalous TLS stacks.
- **EPSS + KEV risk prioritisation** on the dashboard ("what is most likely
  to be exploited this week").
- **MITRE ATT&CK overlay** on findings and the dashboard.
- **DefectDojo-compatible export** for interoperability with existing vuln
  management stacks.
- **Ticketing integrations** (Jira / ServiceNow / TheHive) for findings.
- **Certificate expiry monitoring** with alerts before expiration.
- **Auto-chaining:** domain enumeration → automatically schedule network
  scans for newly discovered hosts (already partially present as manual step).
- **Attack-surface timeline:** visual history of exposure changes per asset.

## 5. Open inputs needed from the operator

- Sample PingCastle XML and Purple Knight report files (Phase 3). **PingCastle
  received and implemented; Purple Knight skipped per operator decision.**
- Confirmation of which Phase 1 items to build first if scope must be cut.
- Whether `sqlmap` should ship in the UI as a per-scan toggle plus a global
  "dangerous tools" settings gate (recommended). **Implemented.**

## 6. Wildcard domain targets

**Done.** `*.example.com` in a network scan job now runs subdomain discovery
(Subfinder passive + SecLists wordlist) and scans every discovered host
automatically in the same job. Bounded by `max_wildcard_hosts` (default 1000)
and the server host limit; expansion metadata is recorded on the scan.
