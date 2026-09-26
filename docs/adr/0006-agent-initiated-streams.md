# ADR 0006: Agent-initiated persistent streams

- Status: Accepted
- Date: 2026-09-25

## Context

Should Central poll agents, or should agents push to Central? Managed servers are often behind
NAT or firewalls, and exposing an inbound management port on every server is a large attack
surface. Commands must still reach agents immediately.

## Decision

Agents open one persistent outbound gRPC bidirectional stream to Central. Telemetry flows up at
a configurable interval (default 15s); Central pushes typed, signed commands down the same stream
the moment they are issued. Interactive sessions (terminal, file transfer) use additional streams
the agent opens on request (reverse tunnel), multiplexed over the same HTTP/2 connection.
Agents reconnect with jittered exponential backoff; queued commands have a TTL.

## Consequences

- No inbound ports on managed servers; works through NAT and outbound HTTPS proxies.
- Central must track presence (which replica holds which stream) — an in-memory bus in Phase 1,
  NATS for multi-replica HA later.
- Offline agents are detected immediately when the stream drops.
