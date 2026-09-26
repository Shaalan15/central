# CLAUDE.md — working in the Central repository

Guidance for AI coding agents (and humans) contributing to this repo. Read this first.

## What this is

Central is a fleet-management control plane for Ubuntu/Debian servers (think Cockpit, but
distributed). A Go server (`server/`) embeds an Angular 22 UI (`web/`). Agents on managed
servers connect **outbound** to Central over gRPC + mTLS. The agent itself lives in `agent/`
and is built separately from `docs/agent/AGENT_BUILD_PROMPT.md`.

Architecture: `docs/architecture.md`. Decisions: `docs/adr/`. Security: `docs/security/`.

## Layout

| Path                     | What                                                            |
| ------------------------ | --------------------------------------------------------------- |
| `proto/central/agent/v1` | Agent ↔ Central wire contract (source of truth)                 |
| `proto/central/api/v1`   | UI / public API (ConnectRPC)                                    |
| `gen/go`                 | Generated Go (own module; never edit by hand)                   |
| `web/src/gen`            | Generated TypeScript (never edit by hand)                       |
| `server/`                | Go module: `cmd/central`, `cmd/central-sim`, `internal/...`     |
| `web/`                   | Angular 22 app                                                  |
| `agent/`                 | Reserved for the agent (separate contributor)                   |
| `deploy/`                | Dockerfile, compose, systemd, nfpm (.deb), LXC                  |
| `docs/`                  | Architecture, ADRs, security, deployment, agent-builder prompt  |

## Commands

```bash
make tools        # pinned buf/protoc plugins/golangci-lint/govulncheck into ./bin
make gen          # regenerate gen/go and web/src/gen from proto/
make test         # go test -race + vitest
make lint         # buf lint, golangci-lint, eslint, prettier
make vuln         # govulncheck
make build        # UI + central binary with the UI embedded -> ./bin/central
make dev-server   # central serve --dev (in-memory store) on :8080
make dev-web      # ng serve on :4200 with proxy to :8080
```

Toolchains: Go 1.27 (`GOTOOLCHAIN=go1.27.1` is set by the Makefile), Node 24 LTS (`.nvmrc`).

## Rules

1. **Security is the product.** Before writing code that touches auth, sessions, enrollment,
   PKI, command dispatch, file paths or shell execution, re-read `docs/security/threat-model.md`.
   Never weaken a check to make a test pass.
2. **Tenant isolation**: every store method takes a `store.TenantScope`. Never query across
   orgs except in explicitly named system-level code paths.
3. **No shell strings.** Anything executed on a managed host is a typed operation with argv —
   never string concatenation.
4. **Contracts first.** Change `proto/` → `make gen` → implement. `buf breaking` must pass
   against `main` unless a new API version is introduced.
5. **Secrets** never go in logs, errors returned to clients, URLs, or the repo. Secrets at rest
   are encrypted with the master key (`server/internal/crypto`).
6. **Frontend**: standalone components, signals, zoneless, OnPush (v22 default), no inline
   scripts, no CDNs (strict CSP), Angular Material 3 components.
7. **Tests**: new behavior needs tests; security-relevant behavior needs negative tests
   (the request that must be rejected).
8. **License**: AGPL-3.0-only. New source files start with the SPDX header used elsewhere.
   Only add dependencies with AGPL-compatible licenses (`scripts/check-licenses.sh`).

## Commits

Conventional Commits (`feat(server): …`, `fix(web): …`, `docs: …`, `chore: …`). Keep commits
focused; one milestone may span several commits.
