// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ScrollingModule } from '@angular/cdk/scrolling';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { MatButton } from '@angular/material/button';
import { MatMenu, MatMenuItem, MatMenuTrigger } from '@angular/material/menu';
import { RouterLink } from '@angular/router';

import type { AgentSummary } from '../../../gen/central/api/v1/fleet_pb';
import { ago, duration } from '../../core/format';
import { Session } from '../../core/session';
import { Icon } from '../../shared/icon';
import type { IconName } from '../../shared/icons.generated';
import { Meter } from '../../shared/meter';
import { FleetStore } from './fleet-store';
import {
  FILTER_LABELS,
  PROFILE_LABELS,
  countByFilter,
  isOnline,
  selectHosts,
  type HostFilter,
  type HostSort,
} from './fleet-util';

// Re-exported for older imports.
export { PROFILE_LABELS, underPressure } from './fleet-util';

interface Stat {
  id: HostFilter;
  label: string;
  value: number;
  sub?: string;
  tone?: 'ok' | 'warn' | 'crit';
}

/** Fleet overview: status counters that double as filters, and a dense table of every host. */
@Component({
  selector: 'app-dashboard',
  imports: [
    ScrollingModule,
    RouterLink,
    MatButton,
    MatMenu,
    MatMenuItem,
    MatMenuTrigger,
    Icon,
    Meter,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard {
  readonly store = inject(FleetStore);
  readonly session = inject(Session);

  readonly query = signal('');
  readonly filter = signal<HostFilter>('all');
  readonly sort = signal<HostSort>('name');
  readonly desc = signal(false);
  readonly profiles = PROFILE_LABELS;
  readonly filterLabels = FILTER_LABELS;
  readonly filters = Object.keys(FILTER_LABELS) as HostFilter[];
  readonly online = isOnline;

  readonly summary = this.store.summary;
  readonly counts = computed(() => countByFilter(this.store.list()));

  readonly stats = computed<Stat[]>(() => {
    const s = this.summary();
    const c = this.counts();
    return [
      {
        id: 'online',
        label: 'Online',
        value: c.online,
        sub: `of ${c.all} hosts`,
      },
      { id: 'offline', label: 'Offline', value: c.offline, tone: c.offline ? 'crit' : undefined },
      {
        id: 'updates',
        label: 'Updates available',
        value: c.updates,
        sub: `${s?.totalUpdates ?? 0} packages`,
      },
      {
        id: 'security',
        label: 'Security updates',
        value: c.security,
        sub: `${s?.totalSecurityUpdates ?? 0} packages`,
        tone: c.security ? 'crit' : undefined,
      },
      {
        id: 'reboot',
        label: 'Reboot required',
        value: c.reboot,
        tone: c.reboot ? 'warn' : undefined,
      },
      {
        id: 'pressure',
        label: 'Under pressure',
        value: c.pressure,
        sub: 'CPU, memory or disk over 90%',
        tone: c.pressure ? 'warn' : undefined,
      },
    ];
  });

  readonly rows = computed(() =>
    selectHosts(this.store.list(), {
      query: this.query(),
      filter: this.filter(),
      sort: this.sort(),
      desc: this.desc(),
    }),
  );

  toggleFilter(f: HostFilter): void {
    this.filter.set(this.filter() === f ? 'all' : f);
  }

  sortBy(k: HostSort): void {
    if (this.sort() === k) this.desc.set(!this.desc());
    else {
      this.sort.set(k);
      this.desc.set(k !== 'name');
    }
  }

  sortIcon(k: HostSort): IconName | null {
    return this.sort() !== k ? null : this.desc() ? 'south' : 'north';
  }

  trackId = (_: number, a: AgentSummary) => a.id;
  uptime = (a: AgentSummary) =>
    isOnline(a) ? duration(a.uptimeSeconds) : `seen ${ago(a.lastSeenAt)}`;
}
