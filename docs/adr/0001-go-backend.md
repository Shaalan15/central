# ADR 0001: Go for the backend

- Status: Accepted
- Date: 2026-09-25

## Context

Central holds thousands of long-lived agent connections, fans live telemetry out to browsers,
and must be trivially packageable as a container or LXC guest. The workload is dominated by
network I/O and concurrency rather than CPU-bound computation. Rust and Go were the candidates.

## Decision

Write the server (and the agent) in Go (1.27+).

## Consequences

- Goroutines and `net/http`'s HTTP/2 support make tens of thousands of concurrent streams cheap.
- `CGO_ENABLED=0` produces a single static binary with the UI embedded, which fits distroless
  containers, `.deb` packages and LXC guests.
- Official Appwrite Go SDK (v7 targets Appwrite 2.0), and first-class libraries for gRPC /
  ConnectRPC, `x/crypto/ssh`, WebAuthn, ACME and WireGuard (Phase 2).
- Garbage collection is acceptable for this workload; hot paths avoid allocation-heavy designs.
- Server and agent share generated protocol code through the Go workspace.
