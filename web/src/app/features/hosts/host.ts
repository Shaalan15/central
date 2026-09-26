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
  untracked,
} from '@angular/core';
import { MatButton } from '@angular/material/button';
import { MatTabLink, MatTabNav, MatTabNavPanel } from '@angular/material/tabs';
import { MatTooltip } from '@angular/material/tooltip';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { Capability } from '../../../gen/central/agent/v1/policy_pb';
import { FleetService, ConnectionState, type Agent } from '../../../gen/central/api/v1/fleet_pb';
import { Api, errorMessage } from '../../core/api';
import { ago, duration } from '../../core/format';
import { Session } from '../../core/session';
import { Icon } from '../../shared/icon';
import { FleetStore } from '../fleet/fleet-store';
import { PROFILE_LABELS } from '../fleet/fleet-util';
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
  readonly state = computed(() => {
    const s = this.summary();
    return !s
      ? ''
      : this.online()
        ? `Online, up ${duration(s.uptimeSeconds)}`
        : `Offline, last seen ${ago(s.lastSeenAt)}`;
  });
  /** Whether the owner policy on the host allows a browser terminal. */
  readonly terminalAllowed = computed(() => {
    const p = this.ctx.agent()?.policy;
    return !p || (!p.paused && p.allowed.includes(Capability.TERMINAL));
  });

  readonly tabs = computed(() => [
    { path: 'overview', label: 'Summary' },
    { path: 'updates', label: 'Updates', count: this.summary()?.updatesAvailable ?? 0 },
    { path: 'packages', label: 'Packages' },
    { path: 'services', label: 'Services' },
    { path: 'logs', label: 'Logs' },
    { path: 'processes', label: 'Processes' },
    { path: 'terminal', label: 'Shell' },
    { path: 'network', label: 'Network' },
    { path: 'storage', label: 'Storage' },
    { path: 'policy', label: 'Owner policy' },
  ]);

  constructor() {
    effect(() => {
      const id = this.id();
      if (id !== untracked(() => this.ctx.id())) this.ctx.agent.set(null);
      this.ctx.id.set(id);
      void this.load(id);
    });
  }

  private async load(id: string): Promise<void> {
    this.error.set('');
    try {
      const res = await this.fleet.getAgent({ agentId: id });
      if (id === this.ctx.id()) this.ctx.agent.set(res.agent ?? null);
    } catch (err) {
      if (id !== this.ctx.id()) return;
      this.ctx.agent.set(null);
      this.error.set(errorMessage(err));
    }
  }

  /** Address, OS, kernel, architecture and agent version on one line. */
  metaLine(a: Agent | null): string {
    const s = this.summary();
    const f = a?.facts;
    return [
      s?.primaryIp,
      s?.hostname !== s?.name ? s?.hostname : '',
      f?.os?.prettyName ?? s?.osPrettyName,
      f?.kernelRelease,
      f?.arch ?? s?.arch,
      s?.agentVersion ? `agent ${s.agentVersion}` : '',
    ]
      .filter(Boolean)
      .join(' · ');
  }
}
