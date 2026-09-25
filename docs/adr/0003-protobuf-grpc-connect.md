# ADR 0003: Protobuf contracts — gRPC for agents, ConnectRPC for the UI

- Status: Accepted
- Date: 2026-09-25

## Context

Two interfaces need schemas: the agent protocol (long-lived, bidirectional, versioned across
independently deployed agents) and the UI/public API (browser, curl, automation).

## Decision

- Define both in Protobuf under `proto/`, linted and breaking-change-checked with Buf.
- Agents speak the **gRPC** protocol over HTTP/2 + mTLS (implemented with `connectrpc.com/connect`,
  which serves gRPC natively), using one bidirectional control stream plus on-demand session
  streams.
- The UI and public API use **ConnectRPC** (JSON or binary over HTTP/1.1 or HTTP/2) with
  generated TypeScript clients (`@bufbuild/protobuf` v2 + `@connectrpc/connect-web`). Terminals
  use a WebSocket because browsers cannot do full-duplex fetch streams.

## Consequences

- One schema language, typed end to end, compact on the wire for large fleets.
- The public API remains curl-friendly (`POST` + JSON).
- `buf breaking` protects deployed agents from accidental wire changes.
