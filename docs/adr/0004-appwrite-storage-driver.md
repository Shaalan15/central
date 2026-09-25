# ADR 0004: Appwrite as the first storage driver, behind a store interface

- Status: Accepted
- Date: 2026-09-25

## Context

The product owner chose Appwrite (Cloud or self-hosted, 2.x) as the initial database. Appwrite
is a BaaS: it adds a network hop, has limited query capabilities, and is not a time-series DB.
Future drivers (SQLite, Postgres) are expected.

## Decision

- All persistence goes through `server/internal/store` interfaces. Appwrite (TablesDB API,
  Go SDK v7) is the first driver; an in-memory driver backs tests and `--dev` mode. A shared
  contract test suite runs against every driver.
- Only the Central server talks to Appwrite, with a least-privilege server API key. The browser
  never talks to Appwrite directly, and no client-side row permissions are granted.
- Tenant isolation is enforced in the store layer: every method requires a `TenantScope`.
- Hot data (fleet index, live metrics) lives in memory; Appwrite is the durable record. Metrics
  are persisted as hourly chunk rows (60 packed one-minute points) to keep row counts low.

## Consequences

- Appwrite latency and quotas stay off the hot path.
- Swapping or adding a database later is a driver implementation, not a rewrite.
- Central-native auth (not Appwrite Auth) keeps identity portable across drivers.
