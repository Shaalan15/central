# Threat model

Central gives its operators root-level reach into every enrolled server. A compromise of
Central, an admin account or the agent channel can therefore become a compromise of the whole
fleet. This document lists the assets, trust boundaries, threats (STRIDE) and the controls
that address them. Every security-relevant change should be checked against it.

## Assets

1. Root access to managed servers (the most valuable asset).
2. Agent identities (private keys, certificates) and Central's CA and command-signing keys.
3. The master key (encrypts secrets at rest) and the Appwrite API key.
4. Admin credentials, sessions, MFA secrets, API keys.
5. Fleet data: inventory, metrics, logs, file contents, terminal recordings.
6. The audit log's integrity.

## Actors

- **Admin / operator**: legitimate user with some role in one organization.
- **Machine owner**: local root on a managed server (may be the same person as the admin; in a
  hosted/SaaS deployment they may not trust the Central operator).
- **External attacker**: on the internet; can reach the UI and agent listeners.
- **Malicious tenant**: legitimate user of one organization attacking others (multi-tenant).
- **Compromised server**: an enrolled host under attacker control, speaking to Central.
- **Compromised Central**: attacker controls the Central process or its database.

## Trust boundaries

```
Browser ──(1) HTTPS + session cookie──▶ Central ──(3) HTTPS + API key──▶ Appwrite
Agent   ──(2) mTLS gRPC stream────────▶ Central
Agent process ──(4) Unix socket──▶ privileged helper (root) ──▶ OS
Machine owner ──(5) policy.toml (root-owned)──▶ helper
```

## Threats and controls

### Spoofing

| Threat | Controls |
| ------ | -------- |
| Attacker enrolls a rogue server | Enrollment tokens (hashed, expiring, max uses, IP range, hostname pattern); manual approval by default; approver must **type the pairing code** printed on the host; risk flags; rate limits; pending-request caps; key blocklist on deny. |
| Agent connects to a fake Central | Enrollment key embeds the CA pin; agents trust only the pinned CA for the agent endpoint. |
| Stolen agent certificate | Key never leaves the host (0600, unprivileged user); 30-day certificates; revocation checked on every handshake; one stream per agent (a second connection is visible). |
| Admin impersonation | argon2id passwords; mandatory MFA (passkeys preferred, TOTP); login throttling; no user enumeration; `__Host-` Secure HttpOnly SameSite=Strict cookies; session rotation. |
| First visitor claims a fresh install | One-time setup token printed to the server log / data dir; wizard locked without it. |

### Tampering

| Threat | Controls |
| ------ | -------- |
| Command altered or injected in transit | mTLS + Ed25519 signature over exact bytes, verified by the root helper. |
| Replay of an old command | Unique command IDs, `expires_at` ≤ 24h, helper replay cache. |
| Command meant for host A run on host B | `agent_id` and `org_id` inside the signed command, checked by the helper. |
| Compromised unprivileged agent process fabricates commands | Helper verifies signatures itself; trust anchors are root-owned; key rotation must be signed by a trusted key. |
| Audit log tampering | Hash-chained entries per organization; `VerifyAuditChain`; the agent keeps its own local audit log. |
| Path traversal / symlink attacks via file operations | `openat2` resolution, policy check on resolved paths, fd-based operations, atomic writes. |
| Shell/argument injection | Typed operations with argv only; strict validation regexes. |

### Repudiation

| Threat | Controls |
| ------ | -------- |
| Admin denies running a destructive action | Audit log records actor, IP, user agent, target, parameters (secrets redacted) and result; terminal sessions are recorded; the agent logs the issuer locally. |

### Information disclosure

| Threat | Controls |
| ------ | -------- |
| Secrets leak through logs/errors | Structured logging with redaction; errors to clients never include secrets or internals; passwords only to `chpasswd` stdin. |
| Cross-tenant data access | Every store method requires a `TenantScope`; IDs from other orgs return NOT_FOUND; cross-tenant tests. |
| Database compromise exposes secrets | Secrets encrypted with AES-256-GCM under the master key (kept outside the DB); tokens/sessions/API keys stored as hashes only. |
| XSS steals sessions or drives the UI | Angular auto-escaping; strict nonce-based CSP (no inline scripts, no `unsafe-eval`, no CDNs); HttpOnly cookies; Trusted Types where supported. |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY`. |
| Sensitive file reads through Central | Owner policy read deny list (shadow, private keys, agent state); `files.read` not in `observe`/`operate`. |

### Denial of service

| Threat | Controls |
| ------ | -------- |
| Enrollment/login flooding | Per-IP and per-token/account rate limits; bounded pending queues; request size limits. |
| Malicious agent floods Central | Per-agent message rate and size limits; stream replaced on reconnect; metrics coalescing. |
| Malicious Central exhausts a host | Agent bounds concurrency, output, buffers and timeouts. |
| Network change locks a host out | Commit-confirm with automatic rollback in the helper. |

### Elevation of privilege

| Threat | Controls |
| ------ | -------- |
| Operator exceeds their role | RBAC with fine-grained permissions scoped to agent groups/tags; checked server-side on every call (UI hiding is cosmetic). |
| Session hijack performs dangerous actions | Step-up re-authentication (recent MFA) for approvals, revocation, terminal, exec, mass jobs, user/network management, key export. |
| CSRF | SameSite=Strict + CSRF header token + Origin/Sec-Fetch-Site checks; the API accepts only `POST` with a JSON/proto content type. |
| **Compromised Central abuses every host** | Owner policy limits capabilities per host (`observe`/`operate` are strongly enforceable); escalation deny lists; local pause switch; local audit log; Phase 2: owner-signed high-risk commands. |
| Agent bug parsing network input gives root | Privilege separation: network parsing runs unprivileged under systemd sandboxing; the helper's input is signed bytes. |
| Mass destructive job | Target preview, typed confirmation above a threshold, batched rollout with failure threshold, cancel. |

## Residual risks (accepted for Phase 1)

- Under the `full` profile, a compromised Central (or admin) has root on those hosts. Mitigated
  by MFA/step-up/audit, not prevented. Owner-signed commands (Phase 2) address this.
- Appwrite is a dependency with its own attack surface; a compromised Appwrite project can
  alter non-secret state (not forge commands: signing keys are encrypted with the master key).
- Single-node deployments are a single point of failure (availability, not integrity).

## Security testing expectations

- Negative tests for every authorization rule (the request that must be rejected).
- An authorization matrix test across all RPCs and built-in roles.
- Fuzzing of parsers and verification code.
- `govulncheck`, `npm audit`, CodeQL, dependency license checks in CI.
- External penetration test before any public hosted offering
  ([SaaS launch gate](saas-launch-gate.md)).
