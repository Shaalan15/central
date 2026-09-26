# ADR 0002: Angular 22 and Angular Material 3 for the UI

- Status: Accepted
- Date: 2026-09-25

## Context

The repository started as an Angular 19 scaffold. The UI must stay fast with large fleets
(thousands of rows updating live) and must run under a strict Content-Security-Policy.

## Decision

Keep Angular, upgraded to v22: standalone components, signals, zoneless change detection and
OnPush (the v22 default). Use Angular Material 3 with a custom dense theme (light and dark),
CDK virtual scrolling for large tables, canvas charts (uPlot) and xterm.js for terminals.

## Consequences

- Fine-grained reactivity without zone.js keeps change detection cost proportional to what
  actually changed; live updates are coalesced (≤ 1 Hz per view).
- Material is maintained in lockstep with Angular and is accessible out of the box.
- No inline scripts and no CDNs: the server injects a per-request CSP nonce that Angular applies
  to its generated `<style>` elements; fonts are self-hosted.
