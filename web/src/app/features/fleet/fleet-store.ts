// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';

import {
  FleetService,
  type AgentSummary,
  type FleetSummary,
} from '../../../gen/central/api/v1/fleet_pb';
import { Api } from '../../core/api';

/**
 * FleetStore mirrors the caller's fleet from the WatchFleet stream: a snapshot, then coalesced
 * upserts (applied in batches so a busy fleet re-renders a few times per second at most). It
 * reconnects with backoff and lives as long as the app shell.
 */
@Injectable()
export class FleetStore {
  private readonly fleet = inject(Api).client(FleetService);
  private readonly abort = new AbortController();

  readonly agents = signal<ReadonlyMap<string, AgentSummary>>(new Map());
  readonly summary = signal<FleetSummary | null>(null);
  readonly connected = signal(false);
  readonly list = computed(() => [...this.agents().values()]);

  private pending = new Map<string, AgentSummary | null>();
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.abort.abort());
    void this.run();
  }

  get(id: string): AgentSummary | undefined {
    return this.agents().get(id);
  }

  private async run(): Promise<void> {
    let backoff = 1000;
    const signal = this.abort.signal;
    while (!signal.aborted) {
      try {
        for await (const res of this.fleet.watchFleet({}, { signal })) {
          backoff = 1000;
          this.connected.set(true);
          const ev = res.event;
          switch (ev.case) {
            case 'snapshot':
              this.pending.clear();
              this.agents.set(new Map(ev.value.agents.map((a) => [a.id, a])));
              if (ev.value.summary) this.summary.set(ev.value.summary);
              break;
            case 'upsert':
              this.queue(ev.value.id, ev.value);
              break;
            case 'removed':
              this.queue(ev.value, null);
              break;
            case 'summary':
              this.summary.set(ev.value);
              break;
          }
        }
      } catch {
        if (signal.aborted) return;
      }
      this.connected.set(false);
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  private queue(id: string, a: AgentSummary | null): void {
    this.pending.set(id, a);
    this.flushTimer ??= setTimeout(() => this.flush(), 250);
  }

  private flush(): void {
    this.flushTimer = null;
    if (!this.pending.size) return;
    const next = new Map(this.agents());
    for (const [id, a] of this.pending) {
      if (a) next.set(id, a);
      else next.delete(id);
    }
    this.pending.clear();
    this.agents.set(next);
  }
}
