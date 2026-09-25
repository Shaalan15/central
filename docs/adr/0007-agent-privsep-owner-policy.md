# ADR 0007: Privilege-separated agent with an owner-controlled local policy

- Status: Accepted
- Date: 2026-09-25

## Context

Central administers servers (packages, services, users, files), which requires root. A single
root process that parses network input turns any parsing bug into root compromise. Machine
owners — especially on a future hosted Central — also need a way to limit what Central can do.

## Decision

- `central-agent` (unprivileged user) handles all network I/O, TLS and protobuf parsing, and
  reads telemetry from `/proc`.
- `central-agent-helper` (root) listens only on a local Unix socket (peer UID checked), executes
  **typed** operations with argv (never a shell), and independently verifies each command
  envelope's Ed25519 signature, target agent, expiry and replay cache.
- `/etc/central-agent/policy.toml` is root-owned and never writable by Central. It selects a
  profile (`observe`, `operate`, `administer` — the install default — or `full`) plus
  fine-grained overrides. Hardcoded protections stop Central from modifying or disabling the
  agent itself. The effective policy and its digest are reported to Central and shown read-only
  in the UI.

## Consequences

- A compromised network process cannot fabricate commands.
- Profiles below `full` are enforceable; `full` (root shell, arbitrary exec) is root-equivalent,
  so the policy is advisory there. The `administer` profile blocks known escalation paths
  (sudoers, cron, systemd units, apt sources, root's SSH keys) by default.
- Phase 2 adds owner-signed high-risk commands verified by the helper.
