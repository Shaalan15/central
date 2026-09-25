// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ScrollingModule } from '@angular/cdk/scrolling';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButton } from '@angular/material/button';
import { MatTooltip } from '@angular/material/tooltip';
import { Router, RouterLink } from '@angular/router';

import { PolicyProfile } from '../../../gen/central/agent/v1/policy_pb';
import { ConnectionState, type AgentSummary } from '../../../gen/central/api/v1/fleet_pb';
import { ago, duration } from '../../core/format';
import { Session } from '../../core/session';
import { Icon } from '../../shared/icon';
import type { IconName } from '../../shared/icons.generated';
import { Meter } from '../../shared/meter';
import { FleetStore } from './fleet-store';

type Quick = 'all' | 'online' | 'offline' | 'updates' | 'security' | 'reboot' | 'pressure';
type SortKey = 'name' | 'cpu' | 'memory' | 'disk' | 'updates' | 'seen';

export const PROFILE_LABELS: Record<number, string> = {
  [PolicyProfile.OBSERVE]: 'Observe',
  [PolicyProfile.OPERATE]: 'Operate',
  [PolicyProfile.ADMINISTER]: 'Administer',
  [PolicyProfile.FULL]: 'Full',
};

export function underPressure(a: AgentSummary): boolean {
  return (
    a.connection === ConnectionState.ONLINE &&
    (a.cpuPercent > 90 || a.memoryUsedPercent > 90 || a.diskUsedPercentMax > 90)
  );
}

@Component({
  selector: 'app-dashboard',
  imports: [ScrollingModule, FormsModule, RouterLink, MatButton, MatTooltip, Icon, Meter],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard {
  readonly store = inject(FleetStore);
  readonly session = inject(Session);
  private readonly router = inject(Router);

  readonly query = signal('');
  readonly quick = signal<Quick>('all');
  readonly sort = signal<SortKey>('name');
  readonly desc = signal(false);
  readonly online = ConnectionState.ONLINE;
  readonly profiles = PROFILE_LABELS;

  readonly summary = this.store.summary;

  readonly tiles = computed(() => {
    const s = this.summary();
    const t: {
      id: Quick;
      label: string;
      value: number;
      icon: IconName;
      tone?: string;
      sub?: string;
    }[] = [
      {
        id: 'online',
        label: 'Online',
        value: s?.online ?? 0,
        icon: 'check_circle',
        tone: 'ok',
        sub: `of ${s?.total ?? 0} hosts`,
      },
      {
        id: 'offline',
        label: 'Offline',
        value: s?.offline ?? 0,
        icon: 'cancel',
        tone: (s?.offline ?? 0) > 0 ? 'muted' : undefined,
      },
      {
        id: 'updates',
        label: 'Need updates',
        value: s?.agentsWithUpdates ?? 0,
        icon: 'update',
        sub: `${s?.totalUpdates ?? 0} packages`,
      },
      {
        id: 'security',
        label: 'Security updates',
        value: s?.agentsWithSecurityUpdates ?? 0,
        icon: 'security',
        tone: (s?.agentsWithSecurityUpdates ?? 0) > 0 ? 'danger' : undefined,
        sub: `${s?.totalSecurityUpdates ?? 0} packages`,
      },
      {
        id: 'reboot',
        label: 'Reboot required',
        value: s?.agentsRebootRequired ?? 0,
        icon: 'restart_alt',
        tone: (s?.agentsRebootRequired ?? 0) > 0 ? 'warn' : undefined,
      },
      {
        id: 'pressure',
        label: 'Under pressure',
        value: s?.agentsUnderPressure ?? 0,
        icon: 'speed',
        tone: (s?.agentsUnderPressure ?? 0) > 0 ? 'warn' : undefined,
        sub: 'CPU, memory or disk > 90%',
      },
    ];
    return t;
  });

  readonly rows = computed(() => {
    const q = this.query().trim().toLowerCase();
    const quick = this.quick();
    let list = this.store.list().filter((a) => {
      switch (quick) {
        case 'online':
          if (a.connection !== ConnectionState.ONLINE) return false;
          break;
        case 'offline':
          if (a.connection === ConnectionState.ONLINE) return false;
          break;
        case 'updates':
          if (!a.updatesAvailable) return false;
          break;
        case 'security':
          if (!a.securityUpdates) return false;
          break;
        case 'reboot':
          if (!a.rebootRequired) return false;
          break;
        case 'pressure':
          if (!underPressure(a)) return false;
          break;
        case 'all':
      }
      if (!q) return true;
      return (
        a.name.toLowerCase().includes(q) ||
        a.hostname.toLowerCase().includes(q) ||
        a.primaryIp.startsWith(q) ||
        a.osPrettyName.toLowerCase().includes(q) ||
        a.tags.some((t) => t.includes(q))
      );
    });
    const dir = this.desc() ? -1 : 1;
    const key = this.sort();
    const val = (a: AgentSummary): number | string => {
      switch (key) {
        case 'cpu':
          return a.cpuPercent;
        case 'memory':
          return a.memoryUsedPercent;
        case 'disk':
          return a.diskUsedPercentMax;
        case 'updates':
          return a.securityUpdates * 10_000 + a.updatesAvailable;
        case 'seen':
          return Number(a.lastSeenAt?.seconds ?? 0);
        default:
          return a.name.toLowerCase();
      }
    };
    list = [...list].sort((x, y) => {
      const a = val(x);
      const b = val(y);
      return (a < b ? -1 : a > b ? 1 : x.name.localeCompare(y.name)) * dir;
    });
    return list;
  });

  setQuick(q: Quick): void {
    this.quick.set(this.quick() === q ? 'all' : q);
  }

  sortBy(k: SortKey): void {
    if (this.sort() === k) this.desc.set(!this.desc());
    else {
      this.sort.set(k);
      this.desc.set(k !== 'name');
    }
  }

  open(a: AgentSummary): void {
    void this.router.navigate(['/hosts', a.id]);
  }

  trackId = (_: number, a: AgentSummary) => a.id;
  uptime = (a: AgentSummary) =>
    a.connection === ConnectionState.ONLINE ? duration(a.uptimeSeconds) : ago(a.lastSeenAt);
}
