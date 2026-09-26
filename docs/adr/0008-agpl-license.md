# ADR 0008: AGPL-3.0 license

- Status: Accepted
- Date: 2026-09-25

## Context

Central will be open to the public and may be offered as a hosted service. The license must
keep improvements open when others host modified versions.

## Decision

License the project under **AGPL-3.0-only**. Every source file carries an SPDX header. CI
verifies that shipped dependencies use AGPL-compatible licenses (`scripts/check-licenses.sh`).

## Consequences

- Anyone offering a modified Central as a network service must publish their changes.
- Some organizations avoid AGPL software; a commercial license can be considered later.
- Dependencies with incompatible licenses (e.g. SSPL, BUSL, proprietary) cannot be used.
