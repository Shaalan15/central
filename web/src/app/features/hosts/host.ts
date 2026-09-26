// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
} from '@angular/core';
import { MatButton } from '@angular/material/button';
import { MatTabLink, MatTabNav, MatTabNavPanel } from '@angular/material/tabs';
import { MatTooltip } from '@angular/material/tooltip';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { FleetService, ConnectionState, type Agent } from '../../../gen/central/api/v1/fleet_pb';
import { Api, errorMessage } from '../../core/api';
import { ago, duration } from '../../core/format';
import { Session } from '../../core/session';
import { Icon } from '../../shared/icon';
import { PROFILE_LABELS } from '../fleet/dashboard';
import { FleetStore } from '../fleet/fleet-store';
import { HostContext } from './host-context';

@Component({
  selector: 'app-host',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatTabNav,
    MatTabLink,
    MatTabNavPanel,
    MatButton,
    MatTooltip,
    Icon,
  ],
  providers: [HostContext],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './host.html',
  styleUrl: './host.scss',
})
export class Host {
  readonly id = input.required<string>();
  private readonly fleet = inject(Api).client(FleetService);
  private readonly store = inject(FleetStore);
  readonly session = inject(Session);
  readonly ctx = inject(HostContext);

  readonly error = signal('');
  readonly profiles = PROFILE_LABELS;
  /** Live summary from the fleet stream (falls back to the loaded detail). */
  readonly summary = computed(() => this.store.get(this.id()) ?? this.ctx.agent()?.summary);
  readonly online = computed(() => this.summary()?.connection === ConnectionState.ONLINE);
  readonly uptime = computed(() => {
    const s = this.summary();
    return !s
      ? ''
      : this.online()
        ? `Up ${duration(s.uptimeSeconds)}`
        : `Last seen ${ago(s.lastSeenAt)}`;
  });

  readonly tabs = [
    { path: 'overview', label: 'Overview' },
    { path: 'updates', label: 'Updates' },
    { path: 'packages', label: 'Packages' },
    { path: 'services', label: 'Services' },
    { path: 'logs', label: 'Logs' },
    { path: 'processes', label: 'Processes' },
    { path: 'terminal', label: 'Terminal' },
    { path: 'network', label: 'Network' },
    { path: 'storage', label: 'Storage' },
    { path: 'policy', label: 'Owner policy' },
  ];

  constructor() {
    effect(() => {
      const id = this.id();
      this.ctx.id.set(id);
      void this.load(id);
    });
  }

  private async load(id: string): Promise<void> {
    this.error.set('');
    try {
      const res = await this.fleet.getAgent({ agentId: id });
      this.ctx.agent.set(res.agent ?? null);
    } catch (err) {
      this.ctx.agent.set(null);
      this.error.set(errorMessage(err));
    }
  }

  osLine(a: Agent | null): string {
    const f = a?.facts;
    return f ? [f.os?.prettyName, f.kernelRelease, f.arch].filter(Boolean).join(' · ') : '';
  }
}
