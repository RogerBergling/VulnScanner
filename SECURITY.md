# Security policy

VulnScanner is a security testing tool. Please do not test it against systems
you do not own or have explicit written permission to assess.

## Supported versions

Security fixes are provided for the latest release on the `main` branch and the
most recent tagged minor release. Older releases may receive documentation-only
guidance.

| Version | Supported |
| --- | --- |
| 1.3.x | Yes |
| 1.2.x | Best effort |
| Older | No |

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security
Advisories:

<https://github.com/RogerBergling/VulnScanner/security/advisories/new>

Do **not** open a public issue for a vulnerability, and do not include real
credentials, customer data, scan evidence or production database copies in a
report. Use synthetic reproductions and redact secrets.

Include where possible:

- affected version/commit and deployment mode (local, reverse proxy, agent);
- a description of the impact and required preconditions;
- reproduction steps or a minimal proof of concept;
- relevant logs with secrets and personal data removed;
- whether the issue is already public or known to another party.

## What to expect

- Acknowledgement within 3 business days.
- Initial triage and severity assessment within 10 business days.
- A remediation plan or request for more information after triage.
- Coordinated disclosure after a fix is available. We will credit reporters who
  wish to be named.

These are targets, not contractual SLAs.

## Scope

In scope:

- authentication, session management, MFA and CSRF;
- authorization and data isolation;
- SQL injection, command injection and path traversal;
- server-side request forgery and unsafe outbound requests;
- stored/reflected XSS and report-generation injection;
- credential, key, backup and audit-log handling;
- agent enrollment, authentication and job-result handling;
- dependency and supply-chain issues in this repository.

Out of scope:

- findings produced by scanning a target (those are target issues, not
  VulnScanner vulnerabilities);
- denial of service caused by deliberately scanning huge authorised ranges;
- social engineering, physical access or compromised administrator hosts;
- issues that require an already-compromised administrator account, unless the
  issue allows privilege escalation or persistence beyond that account;
- missing hardening that is explicitly documented as a deployment
  responsibility (for example, exposing the app directly to the internet with
  authentication disabled).

## Safe harbour

We will not pursue legal action for good-faith security research that:

- stays within the scope above;
- avoids privacy violations, data destruction and service disruption;
- uses only accounts and data you are authorised to use;
- reports the issue privately and gives us reasonable time to remediate.

## Operational security notes

- Use the latest release and keep dependencies and optional tools patched.
- Run VulnScanner behind a TLS reverse proxy for any non-loopback deployment.
- Enable MFA and use a unique administrator password.
- Keep `VS_DATA_DIR`, the database, `.env`, `credential.key` and backups
  restricted to the service account.
- Encrypt backups and store them separately from the host.
- Review [docs/SECURITY_AND_DEPLOYMENT.md](docs/SECURITY_AND_DEPLOYMENT.md) and
  [docs/ENTERPRISE_READINESS.md](docs/ENTERPRISE_READINESS.md) before exposing
  the service to other users.
