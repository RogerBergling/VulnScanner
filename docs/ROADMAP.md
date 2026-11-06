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
4. **Scan policies** (GUI-defined, reusable). (open)
5. **sqlmap integration.** (open)
6. **Risk scoring upgrade.** EPSS enrichment — **done**; KEV-weighted risk
   score and MITRE ATT&CK tags remain open.

### Phase 2 — Master / satellite architecture (DMZ scanning)

1. Satellite enrolment with one-time pairing code + mTLS (internal CA).
2. Satellites advertise network position (subnets they can reach) and poll
   the master for jobs; results stream back to the master DB.
3. **Automatic executor selection:** a network scan whose target CIDR
   overlaps a registered satellite's advertised subnet runs on that satellite
   automatically; the GUI shows the chosen executor and allows overriding it
   (server or any satellite/agent).
4. Satellite health, offline queueing, job timeout, revocation and key
   rotation from the master GUI.
5. Multi-hop support later (satellite → satellite) if needed.

### Phase 3 — AD report import and intelligence

1. Native PingCastle XML report parsing — **done** (parser, import API, GUI
   upload and tests). Purple Knight native import still needs a sample file
   from the operator.
2. Delta/trend reporting: new, resolved and changed findings between scans
   of the same asset.
3. Compliance mapping packs (CIS, ISO 27001, PCI DSS 4.0) reporting findings
   against controls.

### Phase 4 — Greenbone/OpenVAS optional engine

1. Optional external engine using the GVM stack (ospd-openvas) or
   `gvm-cli`, like the other external tools: GUI toggle, path setting, feed
   status, result normalisation into the same finding model.

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

- Sample PingCastle XML and Purple Knight report files (Phase 3).
- Confirmation of which Phase 1 items to build first if scope must be cut.
- Whether `sqlmap` should ship in the UI as a per-scan toggle plus a global
  "dangerous tools" settings gate (recommended).
