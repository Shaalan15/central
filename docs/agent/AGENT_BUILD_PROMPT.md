# Prompt: build `central-agent`, the machine agent for Central

> **How to use this document.** Give it to a fresh Claude Code (or human) session working in
> this repository. It is self-contained: it explains what Central is, what the agent must do,
> the security requirements that are not negotiable, and how to verify the work. Read it fully
> before writing code, then read the files it points to.

---

## 1. Your role and mission

You are building **`central-agent`**, the software that runs on every Ubuntu/Debian server
managed by **Central**. Central is a fleet-management control plane (think Cockpit, but
distributed): admins use its web UI to watch server health and administer servers — packages,
services, logs, processes, terminal, files, users, networking — across a whole fleet.

The agent:

1. **enrolls** with a Central instance using a URL and an enrollment key,
2. keeps **one outbound, mutually authenticated gRPC stream** to Central,
3. streams **metrics and inventory**,
4. **executes signed, typed commands** from Central — but only those the machine owner's local
   policy allows — and streams results back,
5. hosts **interactive sessions** (terminal, log follow, file transfer) on request.

You own everything under `agent/`. The server (`server/`), the UI (`web/`) and the wire
contract (`proto/`) are owned by others: **do not modify them.** If you need a protocol change,
write a proposal in [`docs/agent/PROTOCOL_CHANGES.md`](PROTOCOL_CHANGES.md) (template inside)
and implement against the current contract in the meantime.

### Read these first

| File | Why |
| ---- | --- |
| `proto/central/agent/v1/*.proto` | **The contract.** Every message, field and rule you must implement. Comments are normative. |
| `docs/agent/local-policy.md` | The owner policy you must enforce (normative). |
| `docs/protocol.md` | Protocol overview, key formats, sequence diagrams. |
| `docs/adr/0005-*.md`, `0006-*.md`, `0007-*.md` | Why mTLS, why agent-initiated streams, why privilege separation. |
| `docs/security/threat-model.md` | Threats the agent must resist. |
| `CLAUDE.md` | Repository conventions. |

---

## 2. Non-negotiable security requirements

The agent runs as root on production servers and accepts instructions from the network.
Treat every byte from the network as hostile, including bytes from a legitimate Central (it
may be compromised). These rules are acceptance criteria: each needs tests.

1. **Privilege separation.** Two processes:
   - `central-agent` runs as the unprivileged system user `central-agent`. It does all network
     I/O, TLS, protobuf decoding of Central traffic, metrics collection from `/proc`/`/sys`,
     and relays commands. It has no sudo rights and no capabilities.
   - `central-agent-helper` runs as root, listens only on the Unix socket
     `/run/central-agent/helper.sock` (mode 0660, group `central-agent`), verifies the peer
     UID with `SO_PEERCRED` equals the `central-agent` user, and is the **only** component that
     executes operations.
2. **The helper trusts nothing from the unprivileged process except signed bytes.** For every
   command the helper itself re-verifies the `SignedCommand` exactly as specified in
   `command.proto` (signature over the exact bytes, key trust, agent/org targeting, time window,
   replay cache, capability, pause state). A compromised `central-agent` process must not be
   able to cause any operation Central did not sign.
3. **Trust anchors are root-owned.** The command-signing key set and the agent's identity
   (agent ID, org ID) live in `/etc/central-agent/trust.json` (root:root 0644), written only by
   `central-agent enroll` (run as root) and by the helper when it accepts a `SignedKeySet`
   signed by a currently trusted key with a higher version. The unprivileged process can never
   add or replace keys.
4. **No shells, no string commands.** Operations execute programs with explicit argv
   (`exec.Command(path, args...)`, absolute paths). Never `sh -c` with interpolated input.
   The only exception is `Exec` when Central explicitly sends `argv = ["/bin/sh", "-c", ...]`,
   which is gated by the `exec` capability.
5. **Validate every input** against the rules in the proto comments (name regexes, absolute
   clean paths, size limits, enum ranges). Reject unknown enum values. Fail closed.
6. **Filesystem safety.** Resolve paths with `openat2` (`golang.org/x/sys/unix.Openat2`,
   `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_BENEATH` from an `O_PATH` fd of `/`), check the
   *resolved* path against policy, operate on file descriptors (no path re-resolution between
   check and use: no TOCTOU), write atomically (temp file in the same dir, `fsync`, `rename`),
   and never follow symlinks for chmod/chown/delete. Kernels without `openat2` (< 5.6) are not
   supported (all supported distros ship newer kernels).
7. **Owner policy is authoritative** (see `local-policy.md`): enforced in the helper before
   execution, including the hardcoded protections and escalation deny lists.
8. **Secrets never leave memory unprotected.** Passwords from `UserCreate`/`UserSetPassword`
   go only to `chpasswd` via stdin; never log, persist or echo them. Never log enrollment
   secrets, poll secrets, private keys or file contents. Private key files are 0600.
9. **Resource limits.** Bound everything: concurrent commands (`AgentConfig`), output per
   command (truncate + flag), frame sizes, session buffers (1 MiB unacknowledged), replay cache
   size, offline metrics buffer. Use timeouts and contexts everywhere. A malicious Central must
   not be able to exhaust memory or disk on the host.
10. **Minimal, auditable dependencies.** Pure Go, `CGO_ENABLED=0`, AGPL-compatible licenses
    only (`scripts/check-licenses.sh`). Prefer the standard library and `golang.org/x/*`.
    Every new dependency needs a one-line justification in `agent/DEPENDENCIES.md`.
11. **Local audit log** for every command decision (see `local-policy.md`).
12. **No inbound ports.** The agent never listens on a network socket.

---

## 3. Technical constraints

- Go **1.27** (`go 1.27.1` in `agent/go.mod`), module `github.com/Shaalan15/central/agent`.
  Add `./agent` to the root `go.work`. Import generated code from
  `github.com/Shaalan15/central/gen/go/central/agent/v1` (Protobuf types) and
  `.../agentv1connect` (Connect/gRPC client stubs). Use `connectrpc.com/connect` with
  `connect.WithGRPC()` over an HTTP/2 client.
- Targets: **Ubuntu 22.04, 24.04, 26.04 LTS** and **Debian 12, 13**, on **amd64** and
  **arm64**. Refuse to enroll on anything else (check `/etc/os-release`), with a clear message.
- Build with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=…"`.
- Follow repository conventions: SPDX headers (`AGPL-3.0-only`), golangci-lint config at the
  repo root, tests with `-race`.

### Suggested layout

```
agent/
  go.mod
  cmd/central-agent/          # CLI + unprivileged daemon (`central-agent run`)
  cmd/central-agent-helper/   # privileged helper daemon
  internal/
    enroll/        # enrollment flow, key/CSR generation, pairing code
    identity/      # credential storage, trust store, cert renewal
    conn/          # control stream, backoff, keepalive, proxy
    telemetry/     # /proc & /sys metrics
    inventory/     # packages, updates, services, users, network, storage, firewall
    ipc/           # agent <-> helper protocol (length-prefixed protobuf over Unix socket)
    helper/        # command verification, policy enforcement, dispatch, audit log
    ops/           # one package per domain: apt, systemd, journal, proc, power, exec,
                   # terminal, files, users, network, firewall, storage
    policy/        # policy.toml parsing, profiles, glob matching, escalation lists
    session/       # AttachSession: PTY, journal follow, file transfer
  packaging/       # nfpm config, systemd units, postinst/prerm, example policy
  DEPENDENCIES.md
  README.md
```

The agent ↔ helper IPC protocol is internal to `agent/` (define it in
`agent/internal/ipc/ipc.proto` or as hand-written types). Suggested framing: 4-byte big-endian
length + protobuf message, max 16 MiB per frame, one request per connection or multiplexed
with request IDs. Messages: `Execute{signed_command bytes}` → stream of `CommandUpdate`;
`CollectInventory{kinds}` → `InventoryReport`s; `GetPolicy` → `EffectivePolicy`;
`AcceptKeySet{SignedKeySet}` → ok/error; `OpenSession{signed_command}` → the helper spawns the
PTY/stream and passes the file descriptor back with `SCM_RIGHTS`, so the unprivileged process
relays bytes without the helper doing network I/O.

---

## 4. Files on the host

| Path | Owner / mode | Contents |
| ---- | ------------ | -------- |
| `/usr/bin/central-agent`, `/usr/lib/central-agent/central-agent-helper` | root 0755 | Binaries |
| `/etc/central-agent/agent.toml` | root:central-agent 0640 | Central URL, proxy settings, log level |
| `/etc/central-agent/trust.json` | root 0644 | agent_id, org_id, command-signing key set + version |
| `/etc/central-agent/policy.toml` (+ `policy.d/`) | root 0644 | Owner policy |
| `/var/lib/central-agent/` | central-agent 0700 | `agent.key` (0600), `agent.crt`, `ca.pem`, offline buffer |
| `/var/lib/central-agent-helper/` | root 0700 | replay cache, paused flag, pending network rollback state |
| `/run/central-agent/helper.sock` | root:central-agent 0660 | Helper socket (created by systemd socket unit or the helper) |
| `/var/log/central-agent/audit.log` | root:adm 0640 | Local audit log (logrotate config shipped) |

---

## 5. Enrollment (`sudo central-agent enroll`)

Interactive by default, scriptable with flags:

```
sudo central-agent enroll                      # prompts for URL and key (key input hidden)
sudo central-agent enroll --url https://central.example.com:9443 --key-file /path/to/key
echo "$KEY" | sudo central-agent enroll --url … --key-file -
```

Never accept the key as a plain command-line argument (it would show up in `ps` and shell
history); `--key-file -` reads stdin.

**Enrollment key format:** `cek1.<token_id>.<secret>.<ca_pin>` — `token_id` is 16 base64url
chars, `secret` is 43 base64url chars (32 bytes), `ca_pin` is 43 base64url chars
(SHA-256 of the agent CA's DER SubjectPublicKeyInfo). Parse strictly; reject anything else.

Steps:

1. Verify OS support, root, and that the agent is not already enrolled (or `--force`, which
   first deletes old credentials).
2. **Discovery (optional):** if the URL has no port and does not answer gRPC, fetch
   `https://<host>/.well-known/central-agent.json` (`{"agent_url": "...", "ca_pin": "..."}`)
   and use `agent_url` if its `ca_pin` equals the key's pin.
3. Connect with TLS 1.3 using a custom `VerifyConnection` that accepts the server chain only if
   some certificate in the chain has an SPKI SHA-256 equal to `ca_pin` and the chain verifies
   from that CA to the leaf (with the correct server name). **Do this before sending any
   request.** Do not use system roots for this endpoint.
4. Generate an ECDSA P-256 key (`crypto/ecdsa`, `crypto/rand`), create a CSR, collect
   `HostFacts`, call `EnrollmentService.Enroll`.
5. Compute the pairing code yourself (algorithm in `enrollment.proto`); if it differs from the
   server's, abort. Print prominently:
   ```
   Enrollment request submitted to central.example.com.
   Pairing code:  K7QP-3MZX
   Approve this server in Central (Approvals) and enter the code above.
   Waiting for approval… (Ctrl+C to stop; `central-agent enroll --resume` continues later)
   ```
6. Long-poll `GetEnrollmentStatus`. On `APPROVED`: write the key, certificate and CA bundle to
   `/var/lib/central-agent/` (chown `central-agent`), write `trust.json` (root), write
   `agent.toml`, then `systemctl enable --now central-agent-helper central-agent`. On `DENIED`
   or `EXPIRED`: delete the key, print the reason, exit non-zero.
7. Persist in-progress enrollment state (enrollment ID, poll secret, key) under
   `/var/lib/central-agent/enroll/` (0600) so `--resume` works after a reboot.

---

## 6. Connection management (`central-agent run`, systemd)

- mTLS with the stored key/cert; trust only the stored CA bundle; TLS 1.3 only; HTTP/2 with
  PINGs every 30s (15s timeout).
- One `AgentService.Connect` stream. First message `Hello` (version, protocol_version 1,
  features, facts, effective policy from the helper, agent time, running command IDs). Wait for
  `HelloAck`; apply its `AgentConfig`; forward `signing_keys` (a `SignedKeySet`) to the helper.
- Reconnect with exponential backoff and full jitter (1s → 5m), reset after 5 healthy minutes.
  Obey `Disconnect.retry_after`. On `REASON_REVOKED`: stop, remove credentials, log clearly,
  exit 0 without restarting (systemd `RestartPreventExitStatus`).
- Honour `HTTPS_PROXY`/`NO_PROXY` and `proxy` in `agent.toml` (HTTP CONNECT).
- **Certificate renewal:** when the certificate is past 2/3 of its lifetime (or on
  `REASON_RENEW_CERTIFICATE`), generate a new key, call `RenewCertificate`, write the new
  key/cert atomically, reconnect. Retry hourly on failure. If the certificate expires, stop and
  instruct the owner to re-enroll.
- Report clock skew > 60s once per connection as a log warning (commands carry expiry times;
  a badly skewed clock causes `EXPIRED` rejections). Recommend `systemd-timesyncd`.
- While disconnected, buffer up to `offline_buffer_samples` metrics samples (ring buffer, in
  memory; optionally persisted) and flush them oldest-first after reconnecting.

---

## 7. Telemetry and inventory

**Metrics** (unprivileged process, every `metrics_interval`): compute from deltas of
`/proc/stat` (CPU total, per core, iowait, steal), `/proc/loadavg`, `/proc/meminfo`,
`/proc/swaps`, `statfs` on real filesystems from `/proc/self/mountinfo` (skip pseudo
filesystems, snap squashfs, overlay of containers), `/proc/diskstats` (whole disks),
`/proc/net/dev` (skip `lo`), `/proc/uptime`, process count, and the maximum of
`/sys/class/thermal/thermal_zone*/temp`. No external commands.

**Inventory** (collected by the helper on request/schedule, sent only when the content hash
changes; include only kinds whose `*.read` capability is allowed):

- `PACKAGES`: parse `/var/lib/dpkg/status` directly; holds via `apt-mark showhold`, auto via
  `/var/lib/apt/extended_states`.
- `UPDATES`: `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (simulation) parsed for `Inst`
  lines; mark `security` when the candidate's archive ends with `-security` (Ubuntu) or origin
  is `Debian-Security`/label contains `Security`; phased updates per Ubuntu's
  `Phased-Update-Percentage`; `requires_dist_upgrade` by comparing with `apt-get -s upgrade`;
  `reboot_required` from `/var/run/reboot-required(.pkgs)`; `lists_updated_at` from the newest
  mtime in `/var/lib/apt/lists/`. Watch `/var/lib/dpkg/status` and `/var/lib/apt/lists` with
  inotify to refresh after changes.
- `SERVICES`: systemd D-Bus (`org.freedesktop.systemd1`, `ListUnits` + properties).
- `USERS`: `/etc/passwd`, `/etc/group`, lock status from `/etc/shadow` (helper only; never
  send hashes), sudo membership, `lastlog`/`wtmpdb` where available.
- `NETWORK`: netlink or `/sys/class/net` + `ip -j addr/route` (JSON), resolv.conf /
  `resolvectl`, listening sockets from `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/*/fd` inode
  mapping, active backend detection, config files with secrets redacted.
- `STORAGE`: `lsblk -J -b -o …` and mount usage.
- `FIREWALL`: `ufw status numbered` / `ufw status verbose` parsed (helper).

Content hash: SHA-256 of `proto.MarshalOptions{Deterministic: true}` of the payload.

---

## 8. Command execution (helper)

Pipeline: `CentralMessage.command` → agent → IPC `Execute` → helper verification (§2 rule 2) →
policy check → `ACCEPTED` → execution → `RUNNING` updates with output chunks → exactly one
terminal update. The helper records each decision in the local audit log.

- **Concurrency:** up to `max_concurrent_commands`; package operations (anything using apt/dpkg)
  are serialized through a single queue and wait for the dpkg frontend lock
  (`/var/lib/dpkg/lock-frontend`) until the command deadline.
- **Cancellation:** `CancelCommand` → SIGTERM to the process group, SIGKILL after 10s →
  `CANCELLED`.
- **Replay cache:** persisted in `/var/lib/central-agent-helper/replay/` (command IDs with
  expiry), pruned after `expires_at`; bounded (evict expired first; if full, reject with
  `RESOURCE_EXHAUSTED`).
- **Idempotency across reconnects:** a command already running keeps running; its updates are
  re-sent on the new stream. Report running IDs in `Hello`.

### Per-domain notes

- **apt:** always `DEBIAN_FRONTEND=noninteractive`, `NEEDRESTART_MODE=a`,
  `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`, `-y`, `-q`, argv
  only. Package names must match `^[a-z0-9][a-z0-9+.-]+(:[a-z0-9]+)?(=[A-Za-z0-9.+~:-]+)?$`.
  Parse progress (`-o APT::Status-Fd=`) for `progress_percent`/`status`. Produce
  `PackagesChangeResult` by diffing dpkg status before/after.
- **systemd:** D-Bus (`github.com/coreos/go-systemd/v22/dbus` or `github.com/godbus/dbus/v5`)
  for list/status/start/stop/restart/reload/enable/disable/mask/unmask; honour protected units.
- **journal:** `journalctl -o json --no-pager` with argv-built filters (`-u`, `-p`, `--since`,
  `--until`, `--after-cursor`, `-b`, `-n`, `-r`, `--grep` with `--case-sensitive=false` and the
  pattern regex-escaped); follow mode uses `-f` inside a session.
- **processes:** `/proc`; `ProcessSignal` checks `expected_started_at` against
  `/proc/<pid>/stat` starttime before signalling (PID reuse protection); use `pidfd_open` +
  `pidfd_send_signal` where available.
- **power:** `shutdown -r +N "msg"` / `shutdown -P +N` / `shutdown -c`; always report success
  first.
- **exec / terminal:** run as the requested user (validated against `run_as` policy) via
  `SysProcAttr.Credential` with supplementary groups from `getgrouplist`, a clean environment
  (PATH, HOME, USER, LOGNAME, SHELL, LANG, TERM), new session/process group, working dir
  checked. Terminal uses a PTY (`github.com/creack/pty`) running the user's login shell
  (`-l`), idle timeout, and passes the PTY master fd to the agent via `SCM_RIGHTS`.
- **files (Phase 1b):** see §2 rule 6 and `files.proto`. `FileRead` ≤ 1 MiB inline;
  `FileDownload`/`FileUpload` via sessions with SHA-256 verification.
- **users (Phase 1b):** `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel`/`gpasswd -M`/
  `chpasswd` (stdin)/`chage`; validate names; privileged-group rules from the policy;
  authorized_keys written atomically with correct ownership (0700 dir, 0600 file) using the
  target user's credentials (no following of attacker-planted symlinks in `~/.ssh`).
- **network (Phase 1b):** commit-confirm exactly as documented on `NetworkApply`: back up,
  validate (`netplan generate`; for ifupdown reject hook directives), apply
  (`netplan apply` / `ifreload -a` or `systemctl restart networking`), start a rollback timer
  **in the helper** persisted to disk (so a crash or reboot still rolls back), cancel it on
  `NetworkConfirm`. Send `TYPE_NETWORK_ROLLED_BACK` after a rollback.
- **firewall (Phase 1b):** `ufw` with argv; same commit-confirm semantics.
- **agent upgrade/uninstall:** `apt-get install --only-upgrade central-agent[=version]`
  from the configured Central agent repository; uninstall only if
  `allow_remote_uninstall` — report success first, then run `apt-get purge` from a transient
  systemd unit (`systemd-run`) so it survives the agent stopping.

---

## 9. Sessions (`AttachSession`)

When a signed command carries a `SessionBinding` (`terminal_open`, `journal_follow`,
`file_download`, `file_upload`), open a new `AttachSession` stream, send `SessionAttach` first,
then:

- terminal: relay PTY bytes both ways (`data`), apply `resize`, send `close` with the exit code;
- journal follow: batches of `JournalEntries` (≤ 100 entries or 250 ms);
- file download/upload: `data` chunks ≤ 32 KiB, `close` with SHA-256 and total bytes; uploads
  are staged in a temp file and renamed only if size and hash match.

Flow control: never keep more than 1 MiB unacknowledged; send `ack_bytes` as you consume.

Ending a session: send `close`, then **half-close** the request stream (end of stream, not a
reset) and keep reading until Central ends the response. Resetting the HTTP/2 stream (RST_STREAM)
right after sending `close` can discard the frame in transit, and Central would then report the
session as ended without an exit status. The same applies to the control stream: send final
`CommandUpdate`s before closing, and close gracefully.

---

## 10. Packaging and installation

- Build `.deb` packages with **nfpm** for amd64 and arm64: `central-agent_<version>_<arch>.deb`.
- `postinst`: create the `central-agent` system user/group (`adduser --system --group
  --no-create-home --home /var/lib/central-agent`), directories with the permissions in §4,
  install (but do not start) the units, and install the example policy. `prerm`/`postrm`:
  stop units; `purge` removes state and config.
- **systemd units** (ship both, hardened):
  - `central-agent.service`: `User=central-agent`, `NoNewPrivileges=yes`,
    `ProtectSystem=strict`, `ReadWritePaths=/var/lib/central-agent`, `ProtectHome=yes`,
    `PrivateTmp=yes`, `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_UNIX AF_INET
    AF_INET6 AF_NETLINK`, `SystemCallFilter=@system-service`, `MemoryMax=256M`,
    `Restart=always`, `RestartPreventExitStatus=` for the revoked exit code.
  - `central-agent-helper.service` (+ `.socket` if you use socket activation): root, as much
    hardening as its duties allow (`ProtectKernelModules`, `ProtectClock`, `RestrictRealtime`,
    `LockPersonality`, `MemoryDenyWriteExecute`), `Restart=always`.
- **Releases:** publish `.deb`s plus `SHA256SUMS` and a detached GPG signature
  `SHA256SUMS.gpg`. Central's install script (served at `/install-agent.sh`, owned by the server
  team) downloads the right `.deb`, verifies the checksum with `gpgv` against the embedded
  release key, installs it with apt, and runs `central-agent enroll --url … --key-file -`.
  Phase 1b adds a signed APT repository, which replaces this for installs and upgrades.
- Generate an SBOM (SPDX JSON) per release.

---

## 11. CLI reference

```
central-agent enroll [--url URL] [--key-file FILE|-] [--resume] [--force]   (root)
central-agent run                                  (systemd; unprivileged daemon)
central-agent status                               (connection, identity, policy, last error)
central-agent pause [--reason TEXT] | resume       (root)
central-agent policy show | check [FILE] | reload  (check/reload: root)
central-agent audit [--since DURATION] [--json]    (root)
central-agent unenroll                             (root; deletes credentials, stops units)
central-agent version
```

`status` output must be useful to a stressed admin: connected or not (and why), Central URL,
agent ID, certificate expiry, profile + digest, paused state, last N errors.

---

## 12. Testing and verification

- **Unit tests** for every package; table-driven tests for parsers (dpkg status, apt
  simulation output, ufw status, os-release, mountinfo, /proc files) using fixtures captured
  from each supported distro.
- **Negative security tests** (required): forged signature, wrong key ID, untrusted key, key
  set rotation signed by an untrusted key or with a lower version, wrong agent/org, expired,
  issued in the future, TTL > 24h, replay, policy-denied capability for every profile, paused,
  path traversal (`..`, symlink escapes, magic links, bind mounts), escalation deny list,
  protected users/units/packages, oversized inputs, malformed protobuf, IPC peer UID mismatch.
- **Fuzzing** (`go test -fuzz`) for: command verification, policy glob matching and path
  resolution, apt/ufw/dpkg parsers, the IPC framing.
- **Integration tests** against a real Central in dev mode: `make dev-server` from the repo
  root (in-memory store, prints a setup token), complete setup, create an enrollment token,
  enroll the agent in a container or VM, run operations from the UI/API.
- **Distro matrix:** run the integration suite on Ubuntu 22.04/24.04/26.04 and Debian 12/13
  (e.g. with Incus/LXD system containers or VMs); document how in `agent/README.md`.
- `go test -race ./agent/...`, `golangci-lint run ./agent/...`, `govulncheck ./agent/...` and
  `scripts/check-licenses.sh` must pass. Add the agent to the CI workflow (a separate job) when
  you add the module.

---

## 13. Suggested milestones

| # | Deliverable | Phase |
| - | ----------- | ----- |
| A1 | Module skeleton, CLI, config, packaging skeleton, CI job | 1a |
| A2 | Enrollment (pinning, CSR, pairing code, long-poll, credential storage, trust store) | 1a |
| A3 | Control stream, Hello/HelloAck, backoff, proxy, heartbeat, renewal, revocation handling | 1a |
| A4 | Metrics + inventory (packages, updates, services, network, storage) | 1a |
| A5 | Helper: IPC, verification, policy engine, audit log, pause/resume | 1a |
| A6 | Operations: packages, services, journal (query + follow), processes, power, storage, agent upgrade | 1a |
| A7 | Sessions: terminal (full / opt-in), exec | 1a |
| A8 | Files, users/groups/authorized_keys, network + firewall with rollback, uninstall | 1b |
| A9 | Signed APT repository and self-upgrade path | 1b |

Deliver each milestone as focused commits with tests; keep `agent/README.md` current.

---

## 14. Definition of done (Phase 1a)

- A fresh Ubuntu 24.04 VM can be enrolled with the Central-generated install command; the
  pairing code matches; after approval the host appears online with live metrics and inventory.
- From Central: refresh/upgrade packages (including security-only), install/remove packages,
  manage services, query and follow logs, list/signal processes, reboot, open a terminal (when
  the policy allows), run a fleet-wide apt upgrade job — all respecting the owner policy, with
  every decision in the local audit log.
- Revoking the agent in Central disconnects it within seconds and it stops reconnecting.
- Changing `policy.toml` is reflected in Central within seconds.
- All tests in §12 pass; no `golangci-lint`/`govulncheck` findings; packages build for both
  architectures.

## 15. Do not

- Do not modify `proto/`, `server/`, `web/` or `gen/` (propose changes instead).
- Do not add a listening network socket, an HTTP server, or a debug endpoint.
- Do not execute anything through a shell with interpolated input.
- Do not weaken a security check to make something work; if the contract makes something
  impossible, write it up in `PROTOCOL_CHANGES.md`.
- Do not store or log secrets.
- Do not use CGO or dependencies with non-AGPL-compatible licenses.
