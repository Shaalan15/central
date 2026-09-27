// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { BreakpointObserver } from '@angular/cdk/layout';
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatDivider } from '@angular/material/divider';
import { MatMenu, MatMenuItem, MatMenuTrigger } from '@angular/material/menu';
import { MatTooltip } from '@angular/material/tooltip';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';

import { Layout, clampWidth } from '../../core/layout';
import { Session } from '../../core/session';
import { Theme } from '../../core/theme';
import { Icon } from '../../shared/icon';
import type { IconName } from '../../shared/icons.generated';
import { FleetStore } from '../fleet/fleet-store';
import { HostNav } from './host-nav';
import { Palette, type PalettePage } from './palette';

interface NavItem extends PalettePage {
  permission?: string;
  badge?: () => number;
}

const RAIL_WIDTH = 44;
const DRAWER_WIDTH = 288;

@Component({
  selector: 'app-shell',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatMenu,
    MatMenuItem,
    MatMenuTrigger,
    MatDivider,
    MatTooltip,
    Icon,
    HostNav,
    Palette,
  ],
  providers: [FleetStore],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '(document:keydown)': 'onKey($event)' },
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell {
  readonly session = inject(Session);
  readonly theme = inject(Theme);
  readonly fleet = inject(FleetStore);
  readonly layout = inject(Layout);
  private readonly router = inject(Router);
  private readonly hostNav = viewChild(HostNav);

  readonly narrow = toSignal(
    inject(BreakpointObserver)
      .observe('(max-width: 900px)')
      .pipe(map((r) => r.matches)),
    { initialValue: false },
  );
  /** Desktop sidebar collapsed to icons. */
  readonly rail = computed(() => !this.narrow() && this.layout.collapsed());
  readonly sidebarWidth = computed(() =>
    this.narrow() ? DRAWER_WIDTH : this.rail() ? RAIL_WIDTH : this.layout.width(),
  );
  readonly pending = computed(() => this.fleet.summary()?.pendingEnrollments ?? 0);

  readonly nav: NavItem[] = [
    { path: '/', label: 'Overview', icon: 'dashboard' },
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
  readonly pages = computed<PalettePage[]>(() => [
    ...this.visibleNav().map(({ path, label, icon }) => ({ path, label, icon })),
    { path: '/settings/account', label: 'Account and security', icon: 'person' },
  ]);

  readonly themeIcon = computed<IconName>(() =>
    this.theme.mode() === 'dark'
      ? 'dark_mode'
      : this.theme.mode() === 'light'
        ? 'light_mode'
        : 'computer',
  );
  readonly themeLabel = computed(
    () =>
      `Theme: ${this.theme.mode() === 'system' ? 'follow system' : this.theme.mode()} (click to change)`,
  );
  readonly initials = computed(() =>
    (this.session.user()?.displayName || this.session.user()?.email || '?')
      .split(/\s+/)
      .map((p) => p[0])
      .slice(0, 2)
      .join('')
      .toUpperCase(),
  );
  readonly isMac = /Mac|iPhone|iPad/.test(navigator.platform);

  constructor() {
    const sub = this.router.events
      .pipe(filter((e) => e instanceof NavigationEnd))
      .subscribe(() => this.layout.drawerOpen.set(false));
    inject(DestroyRef).onDestroy(() => sub.unsubscribe());
  }

  toggleNav(): void {
    if (this.narrow()) this.layout.drawerOpen.update((o) => !o);
    else this.layout.toggleCollapsed();
  }

  closeDrawer(): void {
    this.layout.drawerOpen.set(false);
  }

  openPalette(): void {
    this.layout.drawerOpen.set(false);
    this.layout.paletteOpen.set(true);
  }

  onKey(e: KeyboardEvent): void {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      this.layout.paletteOpen.update((o) => !o);
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || this.layout.paletteOpen() || typing(e)) return;
    if (e.key === '[' && !this.narrow()) {
      e.preventDefault();
      this.layout.toggleCollapsed();
    } else if (e.key === '/') {
      e.preventDefault();
      const nav = this.hostNav();
      if (nav && !this.narrow()) nav.focusFilter();
      else this.openPalette();
    }
  }

  startResize(e: PointerEvent): void {
    if (e.button !== 0) return;
    e.preventDefault();
    const startX = e.clientX;
    const startW = this.layout.width();
    const body = document.body;
    const move = (ev: PointerEvent) =>
      this.layout.width.set(clampWidth(startW + ev.clientX - startX));
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      body.classList.remove('resizing');
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    body.classList.add('resizing');
  }

  resizeKey(e: KeyboardEvent): void {
    const step = e.key === 'ArrowLeft' ? -16 : e.key === 'ArrowRight' ? 16 : 0;
    if (!step) return;
    e.preventDefault();
    this.layout.width.update((w) => clampWidth(w + step));
  }

  async logout(): Promise<void> {
    await this.session.logout();
    await this.router.navigate(['/login']);
  }
}

/** True while the user types into a field or a terminal (shortcuts stay out of the way). */
function typing(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null;
  if (!t) return false;
  return (
    t.isContentEditable ||
    t.tagName === 'INPUT' ||
    t.tagName === 'TEXTAREA' ||
    t.tagName === 'SELECT' ||
    !!t.closest('.xterm')
  );
}
