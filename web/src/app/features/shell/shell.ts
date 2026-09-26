// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { BreakpointObserver } from '@angular/cdk/layout';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconButton } from '@angular/material/button';
import { MatDivider } from '@angular/material/divider';
import { MatMenu, MatMenuItem, MatMenuTrigger } from '@angular/material/menu';
import { MatSidenav, MatSidenavContainer, MatSidenavContent } from '@angular/material/sidenav';
import { MatTooltip } from '@angular/material/tooltip';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { map } from 'rxjs';

import { Session } from '../../core/session';
import { Theme } from '../../core/theme';
import { Icon } from '../../shared/icon';
import type { IconName } from '../../shared/icons.generated';
import { FleetStore } from '../fleet/fleet-store';

interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  permission?: string;
  badge?: () => number;
}

@Component({
  selector: 'app-shell',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatSidenavContainer,
    MatSidenav,
    MatSidenavContent,
    MatIconButton,
    MatMenu,
    MatMenuItem,
    MatMenuTrigger,
    MatDivider,
    MatTooltip,
    Icon,
  ],
  providers: [FleetStore],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell {
  readonly session = inject(Session);
  readonly theme = inject(Theme);
  readonly fleet = inject(FleetStore);
  private readonly router = inject(Router);

  readonly narrow = toSignal(
    inject(BreakpointObserver)
      .observe('(max-width: 900px)')
      .pipe(map((r) => r.matches)),
    { initialValue: false },
  );
  readonly pending = computed(() => this.fleet.summary()?.pendingEnrollments ?? 0);

  readonly nav: NavItem[] = [
    { path: '/', label: 'Fleet', icon: 'dns' },
    {
      path: '/approvals',
      label: 'Approvals',
      icon: 'how_to_reg',
      permission: 'agents.approve',
      badge: () => this.pending(),
    },
    { path: '/enrollment', label: 'Enrollment', icon: 'key', permission: 'tokens.manage' },
    { path: '/jobs', label: 'Jobs', icon: 'work', permission: 'jobs.view' },
    { path: '/audit', label: 'Audit log', icon: 'receipt_long', permission: 'audit.view' },
    { path: '/settings', label: 'Settings', icon: 'settings' },
  ];
  readonly visibleNav = computed(() =>
    this.nav.filter((n) => !n.permission || this.session.can(n.permission)),
  );
  readonly themeIcon = computed<IconName>(() =>
    this.theme.mode() === 'dark'
      ? 'dark_mode'
      : this.theme.mode() === 'light'
        ? 'light_mode'
        : 'computer',
  );
  readonly themeLabel = computed(() => `Theme: ${this.theme.mode()}`);
  readonly initials = computed(() =>
    (this.session.user()?.displayName || this.session.user()?.email || '?')
      .split(/\s+/)
      .map((p) => p[0])
      .slice(0, 2)
      .join('')
      .toUpperCase(),
  );

  async logout(): Promise<void> {
    await this.session.logout();
    await this.router.navigate(['/login']);
  }
}
