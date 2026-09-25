# Agent protocol overview

The normative definition is the Protobuf in [`proto/central/agent/v1/`](../proto/central/agent/v1/).
This page explains how the pieces fit together.

## Endpoints

| Listener | Default | TLS | Used by |
| -------- | ------- | --- | ------- |
| UI / API | `:8080` (behind a reverse proxy) or `:443` (built-in TLS) | WebPKI (ACME or provided) | Browsers, automation (`/api/…`, `/ws/…`, `/install-agent.sh`, `/.well-known/central-agent.json`) |
| Agent | `:9443` | Internal CA; TLS 1.3 only; client certificates | Agents (`EnrollmentService` without a client cert, `AgentService` with one) |

The agent listener must be reachable with **TCP passthrough**: a reverse proxy that terminates
TLS would hide the client certificate. See `docs/deployment/reverse-proxy.md`.

## Formats

### Enrollment key

```
cek1.<token_id>.<secret>.<ca_pin>
```

- `token_id`: 12 random bytes, base64url (16 chars) — identifies the token (not secret).
- `secret`: 32 random bytes, base64url (43 chars) — Central stores `SHA-256(secret)` only.
- `ca_pin`: base64url(SHA-256(DER SubjectPublicKeyInfo of the agent CA)) (43 chars).

The agent verifies the agent listener's certificate chains to a CA whose SPKI hash equals
`ca_pin` before sending anything. The `cek1.` prefix lets secret scanners recognise leaked keys.

### Pairing code

```
digest = SHA-256("central-pairing-v1" || 0x00 || agent_spki_der || enrollment_id || server_nonce)
code   = CrockfordBase32(digest)[0:8]  → "XXXX-XXXX"
```

Both sides compute it. The agent prints its own value; the approver types it into Central, which
compares it with its own value. 40 bits make brute-forcing a matching request infeasible within
the request's lifetime and rate limits.

### Command signatures

```
signature = Ed25519.Sign(command_key, "central-command-v1" || 0x00 || command_bytes)
keyset_sig = Ed25519.Sign(trusted_key, "central-keyset-v1" || 0x00 || key_set_bytes)
```

The signature covers the exact serialized bytes (`SignedCommand.command`), which the agent
verifies before decoding. Domain-separation prefixes prevent a signature for one purpose from
being valid for another.

### Agent identity

Client certificates are ECDSA P-256, valid 30 days, with the URI SAN
`spiffe://central/org/<org_id>/agent/<agent_id>`. Central checks the SAN, the certificate serial
(must be the agent's current one) and the agent's status on every handshake.

## Sequences

### Enrollment

```
Agent (root, CLI)                          Central (agent listener)                 Admin (UI)
  | TLS 1.3, verify CA pin                      |                                      |
  |-- Enroll(token_id, secret, CSR, facts) ---->| check token, IP range, hostname,     |
  |                                             | rate limits; create PENDING request  |
  |<-- id, poll_secret, nonce, pairing code ----|                                      |
  | print pairing code                          |                                      |
  |-- GetEnrollmentStatus(wait=60s) ----------->|          Approvals: facts, flags --->|
  |                                             |<-- Approve(request, typed code) -----|
  |<-- APPROVED + cert, CA, signing keys -------| issue cert, create agent             |
  | store credentials, start services           |                                      |
```

Rules Central enforces (see `server/internal/enrollment`):

- **Keys.** The secret is checked in constant time, and an unknown token and a wrong secret
  produce the same error. Only after the secret matches does Central report token state
  (expired, exhausted, revoked), source-CIDR mismatches and hostname-pattern mismatches.
- **Uses.** Each accepted request consumes one use of the token, whether it is later approved or
  not, so a leaked single-use key cannot create a queue of requests. A new request with the same
  agent key supersedes that key's older pending request.
- **Blocklist and quotas.** Denying with "block key" blocklists the agent's public key for the
  organization. There are at most 500 pending requests per organization, plus per-IP and
  per-token rate limits.
- **Pairing codes.** The approver types the code shown on the host (case, dashes and spaces are
  ignored, and Crockford aliases O→0 and I/L→1 apply). Ten wrong codes deny the request.
- **Auto-approval.** A token with auto-approval approves only requests without warning-level
  risk flags (duplicate machine-id, unsupported OS, outdated agent, many requests from one IP).
  Flagged requests wait for a human.
- **Re-enrollment.** Approving a request whose machine-id matches an active agent revokes that
  agent.

### Control stream

```
Agent                                         Central
  |== mTLS handshake (cert, serial, status checked) ==|
  |-- Hello(version, facts, policy, running ids) ---->|
  |<-- HelloAck(agent_id, config, signing keys) ------|
  |-- Metrics / Inventory / Heartbeat (periodic) ---->|  fleet index + ring buffers + chunks
  |<-- SignedCommand -------------------------------- |  user action or job batch
  |   helper verifies signature, target, time, replay, policy
  |-- CommandUpdate(ACCEPTED/RUNNING/…/SUCCEEDED) --->|  streamed to the UI
```

### Interactive session (terminal)

```
Browser            Central                                   Agent (helper spawns PTY)
  |-- OpenTerminal -->| permission + step-up + policy check     |
  |<-- ticket --------| SignedCommand{terminal_open, binding} -->|
  |== WS /ws/terminal ==|<== AttachSession(attach{id, token}) ===|
  |<========== PTY bytes (recorded) ===========================>|
```

## Limits (defaults)

| Limit | Value |
| ----- | ----- |
| Command TTL | ≤ 24 h (UI default 10 min; jobs 1 h) |
| Clock skew tolerated for `issued_at` | 5 min |
| Output per command | 4 MiB (then truncated) |
| Output chunk | 64 KiB |
| Session frame | 32 KiB, 1 MiB unacknowledged |
| Inline file read / write | 1 MiB / 4 MiB |
| Metrics interval | 5 s … 5 min (default 15 s) |
| Offline metrics buffer | 240 samples |
| Enrollment request lifetime | 24 h |
| Client certificate lifetime | 30 days, renew at ~20 days |
| Previous certificate after renewal | accepted for 24 h (only the current one may renew) |
| Control stream idle timeout | 120 s without any message |
| Queued commands per agent | 100 (memory only; lost on a Central restart and reported as expired) |
| Metrics report | 1000 samples; samples older than 2 h or > 5 min in the future are dropped |
| Inventory report | 8 MiB serialized |

## Versioning

`Hello.protocol_version` is `1`. Additive changes keep version 1 and are advertised via
`Hello.features`. A breaking change would introduce `central.agent.v2` served side by side.
`buf breaking` runs in CI against `main`.
