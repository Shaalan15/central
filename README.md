# Central

**Central** is a self-hostable control plane for managing fleets of Ubuntu and Debian servers —
think Cockpit, but distributed, fast with large fleets, and built security-first.

A lightweight agent on each server connects **outbound** to Central. Admins approve new agents,
watch live health (CPU, memory, disks, pending updates), and administer servers from a modern web
UI: packages and updates, services, logs, processes, terminal, fleet-wide jobs — with users,
files and networking following in Phase 1b.

> **Status:** early development (Phase 1a). Not ready for production use.

## Highlights

- **Single binary.** A Go server with the Angular 22 UI embedded. Ships as a distroless container
  image or a `.deb` for bare metal, VMs and LXC.
- **Agent-initiated connections.** No inbound ports on managed servers: agents hold one outbound
  gRPC stream over TLS 1.3 with mutual certificate authentication; commands are pushed down it
  instantly.
- **Zero-trust enrollment.** Enrollment keys pin Central's CA; admins approve agents by matching
  a pairing code shown on the server, with provenance and risk flags.
- **Owner-controlled limits.** A root-owned policy on each server restricts what Central may do
  there — and Central can never change it.
- **Defense in depth.** Signed, short-lived, replay-protected commands; privilege-separated
  agent; mandatory MFA (passkeys/TOTP); step-up re-auth; hash-chained audit log.
- **Multi-tenant ready.** Every record is scoped to an organization from day one.
- **Pluggable storage.** Appwrite 2.x (Cloud or self-hosted) today, behind a store interface.

## Repository layout

```
proto/     Protobuf contracts (agent protocol, UI/public API)
gen/go/    Generated Go code (shared by server and agent)
server/    Go server: cmd/central, cmd/central-sim, internal/...
web/       Angular 22 UI (embedded into the server binary)
agent/     Reserved for the machine agent (built from docs/agent/AGENT_BUILD_PROMPT.md)
deploy/    Docker, compose, systemd, .deb packaging, LXC
docs/      Architecture, ADRs, security, deployment
```

## Development

Requirements: Go 1.27+, Node.js 24 LTS, GNU make.

```bash
make tools        # install pinned code generators and linters into ./bin
make gen          # generate Go/TypeScript code from proto/
make dev-server   # terminal 1: central in dev mode (in-memory store) on :8080
make dev-web      # terminal 2: Angular dev server on :4200
make check        # lint + tests + vulnerability scan
```

### Simulated agents

`central-sim` runs agents that speak the real protocol. They have realistic metrics, inventory,
pending updates, an owner-policy profile, a fake shell for the terminal, and a live journal. Use
it for UI work and load tests before the real agent exists.

1. Create an enrollment token in the UI (Enrollment → Tokens). An auto-approval token with
   enough uses avoids approving each host by hand.
2. Save the key to a file, then run `make sim KEY_FILE=key.txt AGENTS=50`.

Credentials are kept in `.central-sim/`, so later runs reconnect the same hosts without a key.
In dev mode the gateway relaxes its per-IP enrollment limits so one machine can enroll a large
simulated fleet.

`CENTRAL_SIM_AGENTS=1000 go test -run TestSimulatedFleet ./server/internal/app/` runs a
self-contained load test. It starts Central, enrolls 1,000 simulated hosts and runs a
fleet-wide upgrade job. Reference run: 1,000 agents online in 3.4 s, the job finished in 10 s,
dispatch p99 was 22 ms, and heap was 280 MiB for Central and all simulated agents together.

See [`CLAUDE.md`](CLAUDE.md) for conventions and [`docs/`](docs/) for architecture and security
design.

## Security

Please report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

## License

Copyright (C) 2026 The Central Authors.

Central is free software: you can redistribute it and/or modify it under the terms of the
[GNU Affero General Public License v3.0](LICENSE) only.
