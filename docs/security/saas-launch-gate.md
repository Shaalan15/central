# SaaS launch gate

Central is designed to run multi-tenant, but a public hosted offering — where strangers connect
their servers to an instance someone else operates — raises the stakes: a single compromise of
the hosted Central would reach every customer's fleet. **Do not open a hosted instance to the
public until every item below is done.**

## Required before launch

- [ ] **External penetration test** of the server, UI, agent protocol and agent, by an
      independent firm, with all high/critical findings fixed and retested.
- [ ] **Owner-signed high-risk commands**: machine owners can require that terminal, exec,
      file writes, user management and network changes carry a signature from a key they hold
      (WebAuthn/hardware key), verified by the agent's helper. A compromised hosted Central must
      not be able to run these on hosts that opted in.
- [ ] **Signup abuse controls**: email verification, CAPTCHA or proof-of-work on signup,
      disposable-domain blocking, per-IP signup limits.
- [ ] **Per-tenant quotas and alerting**: agents, tokens, API keys, jobs, commands per minute,
      storage; alerts on anomalies (mass jobs, many revocations, login failures).
- [ ] **Tenant isolation review**: code review of every store query and cache for `org_id`
      scoping; cross-tenant fuzzing of IDs across all RPCs.
- [ ] **Secrets management**: master key and signing keys in a KMS/HSM (not a file on disk),
      key rotation runbook tested.
- [ ] **Operational security**: least-privilege access for operators, audited break-glass,
      separate production accounts, backups encrypted and restore-tested.
- [ ] **Bug bounty or coordinated disclosure program** announced (`SECURITY.md`).
- [ ] **Incident response runbook**: fleet-wide revocation, signing-key rotation, customer
      notification.
- [ ] **Legal**: terms of service, privacy policy, data processing agreement, AGPL
      source-offer compliance for the hosted version.
