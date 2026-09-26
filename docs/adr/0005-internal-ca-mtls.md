# ADR 0005: Internal CA and mutual TLS for agent identity

- Status: Accepted
- Date: 2026-09-25

## Context

Agents need a strong, revocable identity, and must authenticate Central before sending any
secret — including on self-hosted installs without public certificates.

## Decision

- Central runs an internal CA (ECDSA P-256). Its private key is encrypted at rest with the
  master key.
- The agent listener (default `:9443`) uses a server certificate issued by that CA. Enrollment
  keys embed the CA's SPKI SHA-256 fingerprint, so agents pin Central without trust-on-first-use.
- Agents generate their own P-256 key; the private key never leaves the host. On approval,
  Central issues a 30-day client certificate with a SPIFFE-style URI SAN
  (`spiffe://central/org/<org>/agent/<id>`); agents renew at ~2/3 of lifetime.
- Revocation is enforced by Central (the only relying party) on every handshake and by closing
  live streams immediately, so no CRL/OCSP is needed.

## Consequences

- The agent port requires TCP (L4) passthrough on load balancers and reverse proxies.
- CA and master-key backups are critical: losing them forces re-enrollment of the fleet.
- P-256 keeps TPM-backed agent keys possible later.
