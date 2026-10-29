# Integrations

VulnScanner combines built-in scanners with optional open-source tools and
public vulnerability data. The built-in engines are always the baseline; an
optional integration adds coverage, context or a second opinion. A missing or
failing tool never aborts a scan.

This document covers:

- OSV.dev (built-in HTTP integration)
- CISA Known Exploited Vulnerabilities (KEV)
- `osv-scanner`
- Nmap
- Nuclei
- testssl.sh
- Trivy
- Subfinder and the SecLists subdomain wordlist
- Gitleaks
- Semgrep
- Git and GitHub
- External Active Directory collectors (PingCastle, Purple Knight and custom
  reports)

See [USER_MANUAL.md](USER_MANUAL.md) for scan options and
[the Ubuntu/Fedora installation commands](USER_MANUAL.md#2a-installing-optional-external-tools-ubuntu-and-fedora),
and [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for network and
hardening requirements.

## 1. Integration model

| Integration | Type | Activated by | Needed for |
| --- | --- | --- | --- |
| OSV.dev | Built-in HTTP API | Dependency scan, external APIs enabled | Known vulnerabilities in package versions |
| CISA KEV | Built-in catalogue sync + local lookup | Manual **Sync** in Settings | Known-exploited and ransomware annotations |
| `osv-scanner` | Optional CLI | Repository scan with **External tools**, external APIs enabled | Supplemental dependency analysis |
| Nmap | Optional CLI | Network scan with **External tools**, Nmap enabled in Settings | Service/version detection and optional NSE CVEs |
| Nuclei | Optional CLI | Web scan with **External tools**, Nuclei enabled in Settings, external APIs enabled | Additional web templates |
| testssl.sh | Optional CLI | Web or network scan with **External tools** and **Use testssl.sh**, testssl enabled in Settings | Deep TLS protocol, cipher and certificate review |
| Trivy | Optional CLI | Repository scan with **External tools** and **Use Trivy**, Trivy enabled in Settings | Supplemental dependency, IaC and secret coverage |
| Subfinder | Optional CLI | Domain scan with **Passive enumeration**, Subfinder enabled in Settings, external APIs enabled | Passive subdomain enumeration |
| SecLists wordlist | Local file (optional download) | Domain scan with **Wordlist DNS discovery** | Local DNS brute-force names |
| Gitleaks | Optional CLI | Repository scan with **External tools** | Supplemental secret detection |
| Semgrep | Optional CLI | Repository scan with **External tools**, external APIs enabled | Additional SAST rules |
| Git | Required for GitHub scans | GitHub scan | Repository cloning |
| PingCastle / Purple Knight / `ad_audit.ps1` | External collector + JSON import | AD import or Windows agent `ad` module | Read-only Active Directory assessment |

The two main gates are:

1. The scan's **External tools** option. Nmap, Nuclei, testssl.sh, Trivy and
   Subfinder also have a Settings enable switch, which can disable them but
   does not turn them on by itself.
2. `VS_ENABLE_EXTERNAL_APIS` plus the **Allow external APIs** setting. This
   controls OSV.dev, KEV sync, GitHub-related outbound calls, Nuclei, Semgrep,
   `osv-scanner`, Subfinder and Trivy database updates.

Gitleaks, testssl.sh, local Git operations, Nmap and the built-in scanners do
not require `VS_ENABLE_EXTERNAL_APIS`. Gitleaks, Semgrep and `osv-scanner` have
no separate Settings toggle; the scan's **External tools** option is their only
gate. Wordlist DNS discovery is local and does not require external APIs.

Tool paths are resolved in this order:

1. The matching `VS_*_PATH` environment variable, if it points to an existing
   file.
2. The executable found on `PATH` (`testssl.sh` or `testssl` for testssl.sh).
3. Not available: the scan logs a warning and continues.

Settings shows availability, path and version for `nmap`, `nuclei`, `testssl`,
`trivy`, `subfinder`, `osv-scanner`, `gitleaks`, `semgrep` and `git`. Paths can
be edited in Settings; they are written to `.env` and applied immediately.

## 2. OSV.dev

OSV.dev is the primary vulnerability database for dependency and package
results. It aggregates advisories from ecosystems including PyPI, npm, Go,
RustSec, Maven, NuGet, Packagist, RubyGems, Debian, Ubuntu, OSS-Fuzz and GitHub
advisories.

### How it is used

- The built-in dependency parser extracts exact package versions from
  lockfiles and manifests. Open ranges and unresolved placeholders are not
  queried because OSV needs a concrete version.
- Packages are queried in batches of up to 100 with
  `POST https://api.osv.dev/v1/querybatch`.
- Full advisory details are fetched from
  `GET https://api.osv.dev/v1/vulns/{id}`.
- Batch responses are cached for six hours. Advisory details are cached for
  fourteen days.
- If the API is unavailable, an expired cache entry is used when possible. If
  there is no cache, the scan logs the failure and continues with the
  dependency inventory and other checks.
- A vulnerability becomes a `dependency` finding with the package, version,
  ecosystem, manifest, advisory ID, aliases, fixed versions and OSV severity.
- CVEs from the advisory are later matched against the local KEV catalogue.

### Activation

- `VS_ENABLE_EXTERNAL_APIS=true` at process start.
- **Allow external APIs** enabled in Settings.
- The dependency module enabled in a repository or GitHub scan, or the
  `packages` module enabled for an agent scan.

No API key is required. The server must be able to reach `api.osv.dev` over
HTTPS. Package names and versions are disclosed to the service; account for that
in your data-handling rules.

### Limitations

- OSV only knows about the ecosystems and advisories it indexes.
- A package without an exact version cannot be matched reliably.
- Dev dependencies are included unless the parser can identify and mark them;
  they are still returned with a `dev` flag in the raw data.
- OSV severity is used when present. It is not a substitute for environmental
  risk assessment.

## 3. CISA KEV

The CISA Known Exploited Vulnerabilities catalog identifies CVEs that are known
to be exploited in the wild. VulnScanner uses it as enrichment, not as a
separate scan.

### Synchronisation

Open **Settings -> Sync KEV catalogue**, or call:

```bash
curl -k -u admin:password -X POST https://127.0.0.1:8765/api/settings/kev/sync
```

The server downloads:

```text
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Entries are stored in the `kev_catalog` table with CVE ID, vendor, product, name,
date added, due date, ransomware flag, required action and sync time. The
catalogue is replaced/updated in place; the last sync time is stored in
Settings.

Synchronisation requires external APIs to be enabled. It is manual by design:
VulnScanner does not schedule automatic KEV downloads. Run it as part of your
vulnerability-management routine.

### Enrichment

When a scan is persisted, each finding's CVE list is checked against the local
catalogue. A match:

- Appends `(CISA KEV)` to the title.
- Adds the required action and, where applicable, known ransomware use to the
  description.
- Stores KEV metadata under `raw.kev`.
- Does not overwrite the finding's original severity or CVSS.

If the catalogue is empty or the CVE is not listed, the finding is unchanged.
KEV status is a prioritisation signal; it does not prove that the target is
currently exploitable.

## 4. Optional command-line tools

### 4.1 osv-scanner

`osv-scanner` is a supplemental dependency scanner from Google. It can find
lockfiles that the built-in parser does not understand and can provide its own
view of OSV data.

- Run only for repository/GitHub scans with **External tools** enabled.
- Requires external APIs; there is no separate Settings toggle.
- Command used (v2 syntax first, legacy syntax as fallback):

  ```text
  osv-scanner scan --recursive --format json <repo>
  osv-scanner --recursive --format json <repo>
  ```

- Results are parsed from JSON. Findings already produced by the built-in OSV
  client for the same advisory, package and version are skipped.
- Supplemental findings are marked with `raw.detected_by = "osv-scanner"`.
- A missing binary or failed lookup is logged and ignored.
- Set `VS_OSV_SCANNER_PATH` to pin an exact binary.

`osv-scanner` may be slower than the built-in batch lookup and may contact
package registries or OSV.dev. Scope it to repositories where the extra
coverage is worth the time.

### 4.2 Nmap

Nmap adds service/version detection and, optionally, NSE vulnerability data to a
network scan.

- Run only when **External tools** is enabled in the network scan.
- Requires the **Nmap** setting to be enabled.
- Does not require `VS_ENABLE_EXTERNAL_APIS`.
- Only open ports discovered by the built-in TCP scan are passed to Nmap, up to
  500 ports.
- Base command:

  ```text
  nmap -Pn -sV --version-light -T4 -p <open-ports> -oX - <host>
  ```

- With **NSE vulners**, `--script vulners` is added. This sends
  service/version information to a third-party service and runs NSE logic;
  obtain explicit authorisation first.
- XML output is parsed for service names, versions, products and CVE IDs found
  in NSE script output.
- Nmap failures are logged; the built-in port result is still saved.
- Set `VS_NMAP_PATH` for a service installation.

Nmap is invoked without a shell. Do not pass untrusted arguments through
configuration; the scanner builds the argument list itself.

### 4.3 Nuclei

Nuclei adds template-driven web checks.

- Run only for web scans with **External tools** enabled.
- Requires **Nuclei** enabled in Settings and external APIs enabled.
- The integration runs non-interactively with no OAST/interactsh callbacks and
  no automatic update check:

  ```text
  nuclei -u <url> -jsonl -silent -no-interactsh \
    -disable-update-check -severity critical,high,medium \
    -timeout 10 -retries 1
  ```

- Only critical/high/medium templates are requested.
- JSONL output is converted into `web` findings. Template ID, matcher, matched
  URL, CVE/CWE, CVSS, tags and remediation are retained when present.
- Findings are keyed by template and matcher so repeated matches deduplicate.
- A missing binary or failed run is logged; built-in web checks continue.
- Templates are not updated by VulnScanner. Update them through your normal
  tool-management process and review the template source.
- Set `VS_NUCLEI_PATH` to pin a version.

Nuclei templates can be intrusive and change over time. Use them only against
authorised targets and with an agreed rate and time window.

### 4.4 Gitleaks

Gitleaks supplements the built-in secret patterns.

- Run only for repository/GitHub scans with **External tools** enabled.
- Does not require external APIs.
- Command used:

  ```text
  gitleaks detect --source <repo> --report-format json \
    --report-path <temporary-file> --no-banner --redact
  ```

- With **Git history**, `--log-opts --all` is added. Without a `.git` directory,
  the history scan is skipped with a warning.
- Findings are imported at high severity with rule ID, file, line and redacted
  evidence. The temporary report file is removed afterwards.
- A missing binary or failed run is logged; built-in secret checks continue.
- Set `VS_GITLEAKS_PATH` to pin a version.

Secret evidence is sensitive. Restrict access to the database and reports and
rotate any real credential that is found.

### 4.5 Semgrep

Semgrep adds rule-based source review.

- Run only for repository/GitHub scans with **External tools** enabled.
- Requires external APIs because `--config auto` fetches rules from the Semgrep
  registry.
- Command used:

  ```text
  semgrep scan --config auto --json --quiet --metrics off \
    --disable-version-check --timeout 10 \
    --max-target-bytes 1048576 <repo>
  ```

- Exit codes and JSON are parsed. Rule severity maps as `ERROR` -> high,
  `WARNING` -> medium, `INFO` -> low.
- CWE values, remediation, confidence and the matching source line are kept when
  present.
- Findings are keyed by Semgrep rule and capped at 300; the built-in source
  review is capped separately.
- A missing binary, registry failure or invalid JSON is logged; built-in source
  review continues.
- Set `VS_SEMGREP_PATH` to pin a version.

If your environment cannot reach the Semgrep registry, use a local rules
configuration in your own wrapper or disable external tools. The current
integration intentionally uses `auto` and does not manage rule bundles.

### 4.6 Git and GitHub

Git is required for GitHub repository scans.

- Public repositories need no token. Private repositories can use a read-only
  token in the scan dialog.
- The clone is shallow (`--depth 1 --single-branch`) unless **Git history** is
  enabled, in which case the default branch/history is fetched.
- The token is supplied through Git's environment-based configuration
  (`GIT_CONFIG_*`) rather than the command line, is not written to the database
  and is redacted from clone errors.
- Interactive prompts are disabled (`GIT_TERMINAL_PROMPT=0`,
  `GCM_INTERACTIVE=never`).
- Clones time out after 300 seconds and are limited by `VS_MAX_REPO_BYTES`.
- Temporary clones live under `VS_DATA_DIR/clones` and are removed after the
  scan, including on failure.

The cloned code is treated as untrusted data. It is parsed and read, not
executed. Respect the repository licence and the owner's authorisation when
cloning private or third-party code.

### 4.7 testssl.sh

testssl.sh adds a deep TLS review that the built-in socket inspection does not
attempt. It runs only when **External tools** and **Use testssl.sh** are enabled
for a web or network scan, and **Enable testssl.sh integration** is on in
Settings.

- Runs against HTTPS endpoints only: the web scan target, or HTTPS services
  discovered by a network scan.
- Network scans use `max_testssl_hosts` (default 5, range 0-50) to cap slow
  handshakes.
- Command shape:

  ```text
  testssl.sh --jsonfile <temp>/testssl.json --color 0 --quiet <host>:<port>
  ```

- The JSON report is parsed defensively. `OK`, `INFO` and informational test
  records are ignored; `WARN`, `LOW`, `MEDIUM`, `HIGH` and `CRITICAL` records
  become TLS findings. At most 500 findings are kept.
- testssl.sh is invoked without a shell and with a 600-second timeout. A
  missing binary, timeout, malformed report or non-zero exit is logged and the
  built-in TLS findings remain.
- It connects directly to the target and does not require
  `VS_ENABLE_EXTERNAL_APIS`.

Set `VS_TESTSSL_PATH` or use Settings when the script is not named
`testssl.sh`/`testssl` on `PATH`. Only run it against endpoints you are
authorised to test.

### 4.8 Trivy

Trivy adds filesystem dependency, infrastructure-as-code and secret coverage to
repository and GitHub scans. It runs only when **External tools** and **Use
Trivy** are enabled and **Enable Trivy integration** is on in Settings.

- Command shape:

  ```text
  trivy fs --format json --scanners vuln,misconfig,secret \
    --exit-code 0 --no-progress --quiet --cache-dir <data>/trivy-cache <repo>
  ```

- Trivy's cache lives under `VS_DATA_DIR/trivy-cache`.
- When external APIs are disabled, `--skip-db-update` is added. Trivy then uses
  an existing local vulnerability database; if none exists, it logs the failure
  and the built-in dependency checks remain the result.
- Findings are de-duplicated against built-in package findings by advisory,
  package and version. At most 1500 Trivy findings are kept.
- Vulnerabilities, misconfigurations and detected secrets get stable keys.
  Detected secret values are truncated in evidence; rotate anything matched.
- A missing binary, timeout or malformed report is logged without failing the
  scan.

Set `VS_TRIVY_PATH` or use Settings to pin a version. Trivy is executed without
a shell.

### 4.9 Subfinder and the subdomain wordlist

The **Domain** scan type has two independent discovery paths:

1. **Passive enumeration** with Subfinder.
2. **Wordlist DNS discovery**, a local brute-force pass using an editable list.

Subfinder does not accept a wordlist, so the two paths are separate. Subfinder
runs only with **Passive enumeration** enabled, external APIs enabled and
**Enable Subfinder integration** on in Settings. Command shape:

```text
subfinder -d example.com -silent -json -all
```

Both JSON-lines and plain host-per-line output are accepted. Only names that
end in the scanned domain are kept.

Wordlist discovery resolves `<name>.<domain>` for each entry. Before scanning it
probes a random name to detect wildcard DNS; if a wildcard resolves, the
brute-force pass is skipped to avoid a flood of false positives.

The default wordlist is `VS_DATA_DIR/wordlists/subdomains.txt`. The GUI can edit
it under **Settings → Subdomain wordlist** while the file is inside the data
directory. A deployment can point `VS_SUBFINDER_WORDLIST` at another file (for
example a SecLists checkout), but the GUI then treats it as read-only.

SecLists is the standard source:

- Repository: <https://github.com/danielmiessler/SecLists>
- Default download: `Discovery/DNS/subdomains-top1million-5000.txt`
- Override the download with `VS_SECLISTS_SUBDOMAIN_URL`.

**Load SecLists list** downloads the file and replaces the editable wordlist.
The download is an explicit action; scans never fetch a wordlist on their own.
The API and GUI cap the editable/downloaded file at 2 MiB and the scan reads at
most `max_words` entries (default 5000, range 1-50000).

Domain scans report discovered hosts as informational findings and do not scan
them automatically. Confirm ownership and scope before adding an asset or
starting a web/network scan against a discovered name.

## 5. Active Directory collectors

VulnScanner does not bundle PingCastle or Purple Knight, and it does not run
them directly. It provides:

- `agent/ad_audit.ps1`, a read-only PowerShell collector.
- The Windows agent's `ad` module, which embeds equivalent read-only collection.
- `POST /api/ad/import` and the **Active Directory -> Import report** page for
  external JSON reports.

PingCastle and Purple Knight outputs can be mapped into the documented report
shape or supplied as custom findings. The important properties are:

- Collection must be read-only. Do not use write-capable cmdlets or remediation
  actions in a collector that feeds VulnScanner.
- Include domain name, collection time and collector identity so the report can
  be traced.
- Include password policy, guest account, krbtgt age, delegation, Kerberoasting,
  AS-REP roasting, stale accounts, privileged groups, AdminCount, machine
  account quota, recycle bin and functional level where available.
- Keep account names and evidence within the agreed data-handling scope.
- Respect the collector's licence and the target owner's authorisation.

The report is evaluated locally by `app/scanners/ad.py`. No AD write or LDAP
connection is made by the server. See [AGENT_GUIDE.md](AGENT_GUIDE.md) for the
minimal JSON shape and collector parameters.

## 6. Failure and fallback behaviour

| Situation | Behaviour |
| --- | --- |
| Optional binary missing | Logged; built-in checks continue. |
| Tool exits non-zero | Logged; any parseable output may still be used. |
| OSV.dev unavailable | Cached data is used if available; otherwise dependency findings are limited to inventory-level checks. |
| KEV catalogue not synced | No KEV annotations; findings are still saved. |
| KEV sync fails | API returns `502`; existing catalogue is unchanged. |
| Semgrep registry unreachable | Logged; built-in source review continues. |
| `osv-scanner` unsupported flags | Legacy command is attempted; failure is logged. |
| GitHub clone fails | Scan fails with a redacted error and the temporary directory is removed. |
| Nmap/Nuclei times out | Logged; the built-in result remains. |
| testssl.sh missing or fails | Logged; built-in TLS observations remain. |
| Trivy database unavailable offline | Logged; built-in dependency/IaC/secret checks remain. |
| Subfinder unavailable or external APIs off | Logged; wordlist DNS discovery still runs. |
| Subdomain wordlist missing or empty | Logged; passive Subfinder results are still reported. |
| Wildcard DNS detected | Wordlist DNS discovery is skipped; passive results remain. |
| SecLists download fails | API returns `502`; the existing wordlist is unchanged. |

The scan event log is the first place to look when an integration is not used.
Settings shows whether the binary is visible and which version it reports.

## 7. Configuration reference

| Variable | Integration | Notes |
| --- | --- | --- |
| `VS_ENABLE_EXTERNAL_APIS` | OSV, KEV, GitHub, Nuclei, Semgrep, osv-scanner, Subfinder, Trivy DB, SecLists download | Process-level switch; disabled in air-gapped deployments. |
| `VS_NMAP_PATH` | Nmap | Absolute path or empty to use `PATH`. |
| `VS_NUCLEI_PATH` | Nuclei | Absolute path or empty to use `PATH`. |
| `VS_TESTSSL_PATH` | testssl.sh | Absolute path or empty to use `PATH` (`testssl.sh` or `testssl`). |
| `VS_TRIVY_PATH` | Trivy | Absolute path or empty to use `PATH`. |
| `VS_SUBFINDER_PATH` | Subfinder | Absolute path or empty to use `PATH`. |
| `VS_SUBFINDER_WORDLIST` | Subdomain wordlist | Defaults to `$VS_DATA_DIR/wordlists/subdomains.txt`; files outside the data directory are read-only in the GUI. |
| `VS_SECLISTS_SUBDOMAIN_URL` | SecLists download | Raw URL used by **Load SecLists list**. |
| `VS_OSV_SCANNER_PATH` | osv-scanner | Absolute path or empty to use `PATH`. |
| `VS_GITLEAKS_PATH` | Gitleaks | Absolute path or empty to use `PATH`. |
| `VS_SEMGREP_PATH` | Semgrep | Absolute path or empty to use `PATH`. |
| `VS_GIT_PATH` | Git/GitHub | Absolute path or empty to use `PATH`. |
| `VS_MAX_REPO_BYTES` | Git/GitHub and repository scans | Clone size limit. |
| `VS_MAX_SOURCE_FILE_BYTES` | Semgrep/built-in source review | File read limit. |
| `VS_MAX_SCAN_FILES` | Built-in repository walkers | File-count guardrail. |

Settings toggles are stored in SQLite and survive restarts. Process environment
variables are read at startup, so restart the server after changing `.env`.
Tool paths and the subdomain wordlist are the exception: the Settings page
writes them to `.env`/disk and applies the change immediately.

## 8. Adding another integration

1. Add a path variable to `app/config.py` and `.env.example`.
2. Add a safe wrapper in `app/scanners/tools.py`; never use a shell.
3. Gate execution on the scan option and relevant setting.
4. Parse structured output, ignore malformed lines, and cap finding counts.
5. Give findings stable keys and redact secrets.
6. Log absence/failure and preserve built-in results.
7. Add unit tests with a fake process result; do not require the real tool in
   the test suite.
8. Document network access, data disclosure and authorisation requirements here.

## 9. Authorised use

Every integration reaches a target or a third-party service. Before enabling
one:

- Confirm the target is in scope.
- Confirm outbound disclosure is allowed.
- Review what the tool sends and where.
- Respect rate limits and fragile services.
- Do not use Nmap NSE scripts, Nuclei templates or Semgrep rules against
  systems you do not own or have permission to test.

See [AUTHORIZED_USE.md](AUTHORIZED_USE.md).
