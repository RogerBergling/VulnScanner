# Authorised Use

VulnScanner is a security testing tool. Using it against a system without
permission can be illegal, can disrupt operations and can damage trust. This
document describes the authorisation, scoping and data-handling practices
expected when operating VulnScanner. It is operational guidance, not legal
advice. Local law, contracts and your organisation's policies always take
precedence.

## 1. The basic rule

Only scan systems that you own or for which you have explicit, verifiable
permission from someone authorised to grant it.

"Publicly reachable" does not mean "authorised to test". A website, IP address,
domain, GitHub repository, cloud account, Active Directory domain and endpoint
all require permission from their owner. Permission to access a system is not
automatically permission to scan it.

If you are unsure whether you have permission, stop and ask before scanning.

## 2. Written authorisation

Prefer written authorisation that identifies:

- The customer or asset owner and the person approving the work.
- The exact targets: hostnames, IP ranges, URLs, repository URLs, cloud
  accounts, domains and endpoint groups.
- Explicit exclusions.
- The permitted scan types and whether active checks, Nmap scripts, Nuclei,
  dependency lookups, secret scanning and AD collection are allowed.
- The testing window and time zone.
- Rate limits and any fragile or off-limits services.
- The person who can authorise changes or an emergency stop.
- Emergency contacts and escalation paths.
- How data will be stored, shared, retained and destroyed.
- Reporting and disclosure requirements.
- Whether third-party hosting providers or cloud terms impose additional
  notice or approval requirements.

A verbal "go ahead" is difficult to verify and easy to misunderstand. Record
approval in a ticket, email or signed document and keep it with the engagement
records.

## 3. Scope and rules of engagement

### Define the target inventory

Create the customer, group and asset records before scanning. Use the asset
identifier field to record the exact URL, host, repository or domain. Avoid
ad-hoc scans against targets that are not on the approved list.

For network ranges:

- Confirm the CIDR is entirely owned or authorised, including every address in
  the range.
- Remember that a `/24` can include infrastructure you did not intend to touch.
- Check for shared hosting, load balancers, NAT and cloud metadata endpoints.

For web applications:

- Confirm whether production, staging and development are all in scope.
- Identify authentication requirements and test accounts. VulnScanner does not
  log in or manage application sessions.
- Identify destructive actions, payment flows, rate limits and third-party
  integrations.

For repositories and GitHub:

- Confirm you may clone the repository and scan its history.
- Respect the repository licence and any third-party code it contains.
- A GitHub token must have the minimum read permission and must not be reused
  for unrelated work.

For endpoints and Active Directory:

- Get approval from the endpoint and domain owners, not only the application
  owner.
- Confirm whether the agent may run as root/SYSTEM and which paths it may read.
- Confirm that read-only AD collection is acceptable and who may receive the
  report.
- Check whether the domain's security monitoring or incident response team
  needs advance notice, because AD queries and endpoint collection can generate
  alerts.

### Agree the testing window

Active scans can be noisy. Agree start/stop times, change freezes, peak periods
and blackout dates. Start with passive or low-impact review and increase
intensity only when the rules allow it.

### Agree stop conditions

Stop immediately if:

- A target becomes unstable, unavailable or unusually slow.
- You encounter data that is clearly outside the agreed scope.
- You trigger a security alert or the target owner asks you to pause.
- You are unsure whether an action is permitted.
- You discover evidence of an active compromise. Preserve evidence, notify the
  owner and do not continue intrusive testing unless explicitly directed.

Record the time, target, action and reason for any stop.

## 4. Feature-specific risk

VulnScanner's built-in checks are designed to be conservative, but "built-in"
does not mean "risk-free".

| Feature | Risk | Minimum practice |
| --- | --- | --- |
| Web scan, passive review | Low request volume, but requests still appear in logs and may trigger WAF/IDS alerts | Confirm scope and expected alerting |
| Web active checks | Sends safe SQL-error and reflected-input probes; may affect fragile applications | Enable only with explicit approval and rate limits |
| Exposed-path checks | Requests common sensitive paths such as `.git`, `.env` and backups | Ensure the target owner expects this traffic |
| Network TCP scan | Connects to many ports; may trip firewalls, IDS or fragile services | Use the narrowest port list and host range that answers the question |
| Nmap service/version detection | More intrusive than a TCP connect and may expose service details | Confirm Nmap is allowed; avoid aggressive timing |
| Nmap `vulners` script | Sends service/version data to a third-party service and runs NSE logic | Requires explicit approval for both the scan and the data disclosure |
| Nuclei | Runs a large template set and may trigger active checks; templates change over time | Pin templates, review severity, do not run against third parties without permission |
| Dependency/OSV lookup | Sends package names and versions to OSV.dev | Confirm outbound disclosure is acceptable; disable external APIs if not |
| GitHub clone | Copies source code, including history if enabled, to the scanner host | Confirm repository permission, storage and deletion requirements |
| Secrets scan | Reads files and may surface live credentials in evidence | Restrict paths, protect the database, rotate any real secret found |
| Gitleaks/Semgrep/osv-scanner | External tools with their own behaviour and network access | Review tool configuration and rule sources |
| Agent system/packages/ports | Reads endpoint configuration, package inventory and listening services | Use least-privilege service accounts and approved paths |
| Agent secrets/repo modules | Reads selected endpoint files and uploads findings | Scope paths tightly; avoid collecting unrelated personal or regulated data |
| AD collection/import | Produces a detailed map of domain weaknesses and privileged accounts | Read-only only; restrict report access and distribution |
| KEV sync | Downloads a public catalogue from CISA | Confirm outbound access policy |

VulnScanner does not exploit vulnerabilities, brute force passwords, bypass
authentication, establish persistence for testing, move laterally, exfiltrate
data or modify Active Directory. Do not use it as if it did.

## 5. Credentials and secrets

- Use dedicated, least-privilege credentials for the scanner and for any
  optional tools.
- Do not put credentials in scan targets, URLs, command lines or the asset
  description. A GitHub token entered in the scan dialog is used only for that
  clone and is not persisted, but it may still appear in process memory.
- Protect `.env`, agent configuration, `pending-result.json`, backups and the
  SQLite database.
- Findings and exported reports can contain secret fragments. Treat them as
  sensitive even when redaction is applied.
- If a real credential is discovered, do not test it, reuse it or share it in
  chat. Report it through the agreed channel and recommend rotation.
- Delete temporary clones and exports when they are no longer needed, subject
  to the engagement's evidence-retention requirements.

## 6. Data handling

VulnScanner is local-first, but local does not mean low impact.

- Classify the data: customer information, vulnerability details, secrets and
  AD structure may be confidential or regulated.
- Store the database and backups on encrypted media where required.
- Restrict access to the service account and authorised analysts.
- Avoid exporting more data than the report requires.
- Define retention and deletion dates. Deleting a finding or a customer does
  not remove copies from backups, browser downloads or email.
- Do not upload scan evidence to public services, issue trackers or AI tools
  without approval.
- If the engagement crosses borders or involves personal data, check
  contractual, privacy and transfer requirements before collection.

## 7. Reporting and disclosure

Reports should be accurate, reproducible and honest about uncertainty.

- Include the target, date, scan type, options, tool versions and limitations.
- Distinguish confirmed issues from heuristic indicators and
  false-positive-prone checks.
- Include the evidence needed to reproduce the issue without including live
  secrets.
- Provide remediation guidance and prioritise by business impact, not only
  severity labels.
- Use the customer's agreed channel and encryption for delivery.
- Do not publish, sell or exploit findings without permission.
- If a vulnerability is severe and the owner is unresponsive, follow the agreed
  escalation and any applicable coordinated-disclosure policy. Do not take
  independent action that could harm third parties.

## 8. Pre-engagement checklist

- [ ] Written authorisation obtained and stored.
- [ ] Target list and exclusions agreed.
- [ ] Scan types and active checks approved.
- [ ] Testing window agreed.
- [ ] Rate limits and fragile services documented.
- [ ] Emergency contacts and stop authority recorded.
- [ ] Credentials and GitHub tokens scoped to minimum permissions.
- [ ] Agent installation method, account and readable paths approved.
- [ ] AD collection and report recipients approved.
- [ ] Outbound API/tool usage approved, including OSV, CISA, GitHub and Nmap
      `vulners`.
- [ ] Data storage, retention and deletion agreed.
- [ ] Reporting and disclosure process agreed.
- [ ] Monitoring/incident-response teams notified where required.
- [ ] Backups and a rollback plan exist for the scanning host.

## 9. During the engagement

- Scan only approved targets. Check the resolved IP/domain if there is any
  ambiguity.
- Start with the least intrusive option. Enable active checks, Nmap scripts and
  external tools only when approved.
- Watch scan events, target health and your own alerting.
- Keep a decision log: who approved what, when, and any scope changes.
- Stop if conditions change or you lose confidence in the authorisation.
- Do not improvise beyond the agreed scope because a finding looks interesting.
- Protect collected data from the moment it arrives.

## 10. After the engagement

- Confirm that all targets are accounted for and no scans are still running.
- Revoke agents that are no longer needed and rotate tokens.
- Remove temporary clones, exports and test credentials.
- Deliver the report through the agreed channel.
- Retain evidence only for the agreed period.
- Record lessons learned and any scope deviations.
- If something went wrong, document it honestly and notify the owner promptly.

## 11. If something goes wrong

1. Stop the activity and make the target safe.
2. Notify the authorising contact and your escalation path.
3. Preserve logs and evidence without continuing intrusive work.
4. Do not attempt to hide, delete or work around the incident.
5. Determine the affected scope, data and systems.
6. Follow legal, contractual, privacy and customer-notification requirements.
7. Cooperate with the target owner's incident response.
8. Fix the process that allowed the mistake.

## 12. Misuse

Do not use VulnScanner:

- Against systems you do not own or have permission to test.
- To harass, stalk, extort, gain unauthorised access or cause damage.
- To scan internet-wide ranges or third-party cloud tenants.
- To collect credentials or personal data beyond the agreed scope.
- To hide activity from the target owner or bypass agreed controls.
- In violation of sanctions, export controls, privacy law or contractual
  restrictions.

Authorisation is not a one-time formality. It applies to every target, every
scan option and every piece of collected data.

See [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for protecting the
scanner and its data.
