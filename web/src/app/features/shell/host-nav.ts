// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { CdkVirtualScrollViewport, ScrollingModule } from '@angular/cdk/scrolling';
import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatMenu, MatMenuItem, MatMenuTrigger } from '@angular/material/menu';
import { MatTooltip } from '@angular/material/tooltip';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { filter, map } from 'rxjs';

import type { AgentSummary } from '../../../gen/central/api/v1/fleet_pb';
import { readPref, writePref } from '../../core/layout';
import { Icon } from '../../shared/icon';
import { FleetStore } from '../fleet/fleet-store';
import {
  FILTER_LABELS,
  SORT_LABELS,
  countByFilter,
  isOnline,
  level,
  selectHosts,
  type HostFilter,
  type HostSort,
} from '../fleet/fleet-util';

const ROW = 26;
const FILTER_KEY = 'central.hosts.filter';
const SORT_KEY = 'central.hosts.sort';

/** A saved preference if it is one of the allowed values, otherwise the default. */
function pref<T extends string>(key: string, allowed: Record<T, unknown>, def: T): T {
  const v = readPref(key);
  return v !== null && v in allowed ? (v as T) : def;
}

/** Parses /hosts/:id/:tab from a router URL. */
export function hostRoute(url: string): { id: string; tab: string } | null {
  const m = /^\/hosts\/([^/?#]+)(?:\/([^/?#]+))?/.exec(url);
  return m ? { id: decodeURIComponent(m[1]!), tab: m[2] ?? 'overview' } : null;
}

/**
 * The sidebar host list: every host with its live status, filterable and sortable, with
 * keyboard navigation. Selecting a host keeps the current host tab (Summary, Updates, ...).
 */
@Component({
  selector: 'app-host-nav',
  imports: [ScrollingModule, RouterLink, MatMenu, MatMenuItem, MatMenuTrigger, MatTooltip, Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'host-nav' },
  template: `
    <div class="head">
      <span class="title">Hosts</span>
      <span class="count tabular-nums">{{ countLabel() }}</span>
      <span class="spacer"></span>
      <button
        type="button"
        class="tool"
        [matMenuTriggerFor]="sortMenu"
        [matTooltip]="'Sort: ' + sortLabels[sort()]"
        aria-label="Sort hosts"
      >
        <app-icon name="sort" [size]="16" />
      </button>
    </div>
    <div class="tools">
      <input
        #filterInput
        class="input filter"
        type="search"
        placeholder="Filter hosts"
        aria-label="Filter hosts by name, IP, OS or tag"
        [value]="query()"
        (input)="query.set(filterInput.value)"
        (keydown.arrowdown)="focusList($event)"
        (keydown.enter)="openFirst()"
        (keydown.escape)="clearQuery()"
      />
      <button
        type="button"
        class="show"
        [class.active]="filter() !== 'all'"
        [matMenuTriggerFor]="filterMenu"
        aria-label="Show hosts"
      >
        {{ filter() === 'all' ? 'All' : filterLabels[filter()] }}
        <app-icon name="keyboard_arrow_down" [size]="14" />
      </button>
    </div>

    @if (store.list().length === 0) {
      <p class="empty faint">No hosts enrolled yet.</p>
    } @else if (rows().length === 0) {
      <p class="empty faint">No hosts match.</p>
    }
    <cdk-virtual-scroll-viewport
      [itemSize]="row"
      class="list"
      role="listbox"
      aria-label="Hosts"
      tabindex="0"
      [attr.aria-activedescendant]="activeId()"
      (keydown)="onKey($event)"
    >
      <a
        *cdkVirtualFor="let a of rows(); trackBy: trackId"
        class="host"
        role="option"
        tabindex="-1"
        [id]="'host-opt-' + a.id"
        [attr.aria-selected]="a.id === selectedId()"
        [class.selected]="a.id === selectedId()"
        [class.offline]="!online(a)"
        [routerLink]="['/hosts', a.id, tab()]"
        [title]="tooltip(a)"
      >
        <span class="dot" [class.ok]="online(a)"></span>
        <span class="name">{{ a.name }}</span>
        @if (a.securityUpdates) {
          <span class="sec tabular-nums">{{ a.securityUpdates }}</span>
        }
        @if (a.rebootRequired) {
          <app-icon class="reboot" name="restart_alt" [size]="13" />
        }
        @if (online(a)) {
          <span class="bars" aria-hidden="true">
            <span class="bar"
              ><i [style.width.%]="a.cpuPercent" [class]="level(a.cpuPercent)"></i
            ></span>
            <span class="bar"
              ><i [style.width.%]="a.memoryUsedPercent" [class]="level(a.memoryUsedPercent)"></i
            ></span>
          </span>
        }
      </a>
    </cdk-virtual-scroll-viewport>

    <mat-menu #filterMenu="matMenu">
      @for (f of filters; track f) {
        <button mat-menu-item (click)="setFilter(f)" [class.current]="filter() === f">
          <span class="menu-row"
            ><span>{{ filterLabels[f] }}</span
            ><span class="faint tabular-nums">{{ counts()[f] }}</span></span
          >
        </button>
      }
    </mat-menu>
    <mat-menu #sortMenu="matMenu">
      @for (s of sorts; track s) {
        <button mat-menu-item (click)="setSort(s)" [class.current]="sort() === s">
          {{ sortLabels[s] }}
        </button>
      }
    </mat-menu>
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      min-height: 0;
    }
    .head {
      display: flex;
      align-items: center;
      gap: 6px;
      height: 28px;
      padding: 0 6px 0 12px;
      color: var(--text-2);
      font-size: var(--fs-xs);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .count {
      font-weight: 400;
      letter-spacing: 0;
      color: var(--text-3);
    }
    .spacer {
      flex: 1;
    }
    .tool {
      display: inline-grid;
      place-items: center;
      width: 24px;
      height: 24px;
      padding: 0;
      border: 0;
      border-radius: var(--radius);
      background: transparent;
      color: var(--text-2);
      cursor: pointer;
      &:hover {
        background: var(--hover);
        color: var(--text);
      }
    }
    .tools {
      display: flex;
      gap: 4px;
      padding: 0 8px 6px;
    }
    .filter {
      flex: 1;
      min-width: 0;
      height: 26px;
      font-size: var(--fs-sm);
    }
    .show {
      display: inline-flex;
      align-items: center;
      gap: 2px;
      max-width: 45%;
      height: 26px;
      padding: 0 4px 0 8px;
      border: 1px solid var(--border-strong);
      border-radius: var(--radius);
      background: var(--panel);
      color: var(--text-2);
      font: inherit;
      font-size: var(--fs-sm);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      cursor: pointer;
      &.active {
        border-color: var(--accent);
        color: var(--accent);
      }
    }
    .empty {
      margin: 4px 12px;
      font-size: var(--fs-sm);
    }
    .list {
      flex: 1;
      min-height: 0;
      outline: none;
      &:focus-visible .selected {
        box-shadow: inset 0 0 0 1px var(--accent);
      }
    }
    .host {
      display: flex;
      align-items: center;
      gap: 7px;
      height: 26px;
      padding: 0 10px 0 12px;
      border-left: 2px solid transparent;
      color: var(--text);
      text-decoration: none;
      font-size: var(--fs);
      &:hover {
        background: var(--hover);
      }
      &.selected {
        background: var(--accent-bg);
        border-left-color: var(--accent);
      }
      &.offline .name {
        color: var(--text-3);
      }
    }
    .name {
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .sec {
      color: var(--crit);
      font-size: var(--fs-xs);
    }
    .reboot {
      color: var(--warn);
    }
    .bars {
      display: flex;
      flex-direction: column;
      gap: 2px;
      width: 30px;
      flex: none;
    }
    .bar {
      height: 3px;
      background: var(--track);
      i {
        display: block;
        height: 100%;
        max-width: 100%;
        background: var(--text-3);
        &.warn {
          background: var(--warn);
        }
        &.crit {
          background: var(--crit);
        }
      }
    }
    .menu-row {
      display: flex;
      justify-content: space-between;
      gap: 24px;
      min-width: 160px;
    }
    .current {
      color: var(--accent);
    }
  `,
})
export class HostNav {
  readonly store = inject(FleetStore);
  private readonly router = inject(Router);

  /** Emitted after the user picks a host (the mobile drawer closes on it). */
  readonly picked = output<void>();

  private readonly viewport = viewChild.required(CdkVirtualScrollViewport);
  private readonly filterInput = viewChild.required<ElementRef<HTMLInputElement>>('filterInput');

  readonly row = ROW;
  readonly filterLabels = FILTER_LABELS;
  readonly sortLabels = SORT_LABELS;
  readonly filters = Object.keys(FILTER_LABELS) as HostFilter[];
  readonly sorts: HostSort[] = ['name', 'cpu', 'memory', 'disk', 'updates'];
  readonly level = level;
  readonly online = isOnline;

  readonly query = signal('');
  readonly filter = signal<HostFilter>(pref(FILTER_KEY, FILTER_LABELS, 'all'));
  readonly sort = signal<HostSort>(pref(SORT_KEY, SORT_LABELS, 'name'));

  private readonly url = toSignal(
    this.router.events.pipe(
      filter((e): e is NavigationEnd => e instanceof NavigationEnd),
      map((e) => e.urlAfterRedirects),
    ),
    { initialValue: this.router.url },
  );
  private readonly route = computed(() => hostRoute(this.url()));
  /** Row moved to with the keyboard but not opened yet. */
  private readonly cursor = signal<string | null>(null);
  readonly selectedId = computed(() => this.cursor() ?? this.route()?.id ?? '');
  readonly tab = computed(() => this.route()?.tab ?? 'overview');
  readonly activeId = computed(() => (this.selectedId() ? 'host-opt-' + this.selectedId() : null));

  readonly counts = computed(() => countByFilter(this.store.list()));
  readonly rows = computed(() =>
    selectHosts(this.store.list(), {
      query: this.query(),
      filter: this.filter(),
      sort: this.sort(),
      desc: this.sort() !== 'name',
    }),
  );
  readonly countLabel = computed(() => {
    const total = this.store.list().length;
    const shown = this.rows().length;
    return shown === total ? `${total}` : `${shown} / ${total}`;
  });

  private navTimer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    effect(() => writePref(FILTER_KEY, this.filter()));
    effect(() => writePref(SORT_KEY, this.sort()));
  }

  trackId = (_: number, a: AgentSummary) => a.id;

  tooltip(a: AgentSummary): string {
    if (!isOnline(a)) return `${a.name}: offline`;
    const parts = [
      `CPU ${a.cpuPercent.toFixed(0)}%`,
      `memory ${a.memoryUsedPercent.toFixed(0)}%`,
      `disk ${a.diskUsedPercentMax.toFixed(0)}%`,
    ];
    if (a.securityUpdates) parts.push(`${a.securityUpdates} security updates`);
    if (a.rebootRequired) parts.push('reboot required');
    return `${a.name}: ${parts.join(', ')}`;
  }

  setFilter(f: HostFilter): void {
    this.filter.set(f);
  }

  setSort(s: HostSort): void {
    this.sort.set(s);
  }

  focusFilter(): void {
    const el = this.filterInput().nativeElement;
    el.focus();
    el.select();
  }

  clearQuery(): void {
    this.query.set('');
    this.filterInput().nativeElement.value = '';
  }

  focusList(e: Event): void {
    e.preventDefault();
    const el = this.viewport().elementRef.nativeElement;
    el.focus();
    if (!this.rows().some((r) => r.id === this.selectedId())) this.move(0);
  }

  openFirst(): void {
    const first = this.rows()[0];
    if (first) this.open(first.id, 0);
  }

  onKey(e: KeyboardEvent): void {
    const rows = this.rows();
    if (!rows.length) return;
    const cur = rows.findIndex((r) => r.id === this.selectedId());
    let next: number;
    switch (e.key) {
      case 'ArrowDown':
      case 'j':
        next = cur < 0 ? 0 : Math.min(rows.length - 1, cur + 1);
        break;
      case 'ArrowUp':
      case 'k':
        next = cur < 0 ? 0 : Math.max(0, cur - 1);
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = rows.length - 1;
        break;
      default:
        return;
    }
    e.preventDefault();
    this.move(next);
  }

  /** Selects the row at index i: scrolls it into view and opens it after a short pause. */
  private move(i: number): void {
    const a = this.rows()[i];
    if (!a) return;
    const vp = this.viewport();
    const top = vp.measureScrollOffset();
    const height = vp.getViewportSize();
    const y = i * ROW;
    if (y < top) vp.scrollToOffset(y);
    else if (y + ROW > top + height) vp.scrollToOffset(y + ROW - height);
    this.open(a.id, 120);
  }

  private open(id: string, delay: number): void {
    this.cursor.set(id);
    clearTimeout(this.navTimer);
    this.navTimer = setTimeout(() => {
      void this.router.navigate(['/hosts', id, this.tab()]).finally(() => {
        if (this.cursor() === id) this.cursor.set(null);
      });
      this.picked.emit();
    }, delay);
  }
}
