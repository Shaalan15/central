# Security policy

Central is a control plane with root-level reach into the servers it manages. We treat every
vulnerability report as high priority and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/Shaalan15/central/security/advisories/new)
("Security" tab → "Report a vulnerability"). Include:

- the affected component (server, web UI, agent protocol, packaging) and version or commit;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept;
- any suggested remediation.

We aim to acknowledge reports within **3 business days**, provide an initial assessment within
**10 business days**, and coordinate a disclosure date with you. We will credit reporters in the
release notes unless you prefer to stay anonymous.

## Scope

In scope:

- the `central` server and embedded web UI;
- the agent ↔ Central protocol and enrollment flow (`proto/`);
- official container images, packages and install scripts published from this repository.

Out of scope: vulnerabilities in third-party dependencies that are already publicly known
(please still tell us if we ship an affected version), social engineering, and denial-of-service
through raw volumetric traffic.

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Security design

The threat model and security architecture are documented in
[`docs/security/`](docs/security/). Highlights:

- agents connect outbound only, over TLS 1.3 with mutual certificate authentication;
- every command sent to an agent is signed, scoped to one agent, short-lived and replay-protected;
- a root-owned policy file on each server limits what Central can do there, and Central cannot
  change it;
- admin accounts require MFA; sensitive actions require recent re-authentication;
- all state-changing actions are recorded in a tamper-evident (hash-chained) audit log.
