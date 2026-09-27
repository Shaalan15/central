// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  afterNextRender,
  computed,
  inject,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';

import { Icon } from '../../shared/icon';
import type { IconName } from '../../shared/icons.generated';
import { FleetStore } from '../fleet/fleet-store';
import { isOnline, matchesQuery } from '../fleet/fleet-util';

export interface PalettePage {
  path: string;
  label: string;
  icon: IconName;
}

interface Item {
  kind: 'host' | 'page';
  id: string;
  label: string;
  detail: string;
  icon?: IconName;
  online?: boolean;
  path: unknown[];
}

const MAX_HOSTS = 50;

/** Ctrl+K switcher: jump to any host or page by typing part of its name. */
@Component({
  selector: 'app-palette',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '(document:keydown.escape)': 'closed.emit()' },
  template: `
    <div class="backdrop" aria-hidden="true" (pointerdown)="closed.emit()"></div>
    <div class="palette" role="dialog" aria-modal="true" aria-label="Go to host or page">
      <div class="field">
        <app-icon name="search" [size]="16" />
        <input
          #input
          type="text"
          placeholder="Go to host or page…"
          aria-label="Search hosts and pages"
          aria-controls="palette-results"
          [attr.aria-activedescendant]="items()[index()] ? 'pal-' + index() : null"
          [value]="query()"
          (input)="onInput(input.value)"
          (keydown)="onKey($event)"
        />
        <kbd>Esc</kbd>
      </div>
      <ul id="palette-results" class="results" role="listbox">
        @for (it of items(); track it.kind + it.id; let i = $index) {
          <li
            [id]="'pal-' + i"
            role="option"
            [attr.aria-selected]="i === index()"
            [class.active]="i === index()"
            tabindex="-1"
            (mousemove)="index.set(i)"
            (click)="go(it)"
            (keydown.enter)="go(it)"
          >
            @if (it.kind === 'host') {
              <span class="dot" [class.ok]="it.online"></span>
            } @else {
              <app-icon [name]="it.icon!" [size]="16" />
            }
            <span class="label">{{ it.label }}</span>
            <span class="detail faint">{{ it.detail }}</span>
          </li>
        } @empty {
          <li class="none faint">No matches</li>
        }
      </ul>
      <div class="foot faint">
        <span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span>
        @if (hostMatches() > maxHosts) {
          <span class="more">{{ hostMatches() - maxHosts }} more hosts: keep typing</span>
        }
      </div>
    </div>
  `,
  styles: `
    :host {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 12vh 16px 16px;
    }
    .backdrop {
      position: absolute;
      inset: 0;
      background: rgb(0 0 0 / 0.35);
    }
    .palette {
      position: relative;
      width: min(560px, 100%);
      max-height: 70vh;
      display: flex;
      flex-direction: column;
      background: var(--panel);
      border: 1px solid var(--border-strong);
      border-radius: 4px;
      box-shadow: 0 12px 32px rgb(0 0 0 / 0.3);
      overflow: hidden;
    }
    .field {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 0 12px;
      height: 40px;
      border-bottom: 1px solid var(--border);
      color: var(--text-2);
      input {
        flex: 1;
        min-width: 0;
        border: 0;
        outline: none;
        background: transparent;
        color: var(--text);
        font: inherit;
        font-size: 14px;
      }
    }
    .results {
      list-style: none;
      margin: 0;
      padding: 4px 0;
      overflow: auto;
    }
    li {
      display: flex;
      align-items: center;
      gap: 8px;
      height: 28px;
      padding: 0 12px;
      cursor: pointer;
      color: var(--text);
      app-icon {
        color: var(--text-2);
      }
      &.active {
        background: var(--accent-bg);
      }
      &.none {
        cursor: default;
      }
    }
    .dot {
      margin: 0 4px;
    }
    .label {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .detail {
      margin-left: auto;
      font-size: var(--fs-sm);
      white-space: nowrap;
    }
    .foot {
      display: flex;
      gap: 14px;
      padding: 6px 12px;
      border-top: 1px solid var(--border);
      font-size: var(--fs-xs);
      kbd {
        margin-right: 2px;
      }
    }
    .more {
      margin-left: auto;
    }
  `,
})
export class Palette {
  private readonly store = inject(FleetStore);
  private readonly router = inject(Router);
  private readonly inputEl = viewChild.required<ElementRef<HTMLInputElement>>('input');

  readonly pages = input<PalettePage[]>([]);
  readonly closed = output<void>();

  readonly maxHosts = MAX_HOSTS;
  readonly query = signal('');
  readonly index = signal(0);

  private readonly hostHits = computed(() => {
    const q = this.query();
    return this.store
      .list()
      .filter((a) => matchesQuery(a, q))
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  });
  readonly hostMatches = computed(() => this.hostHits().length);

  readonly items = computed<Item[]>(() => {
    const q = this.query().trim().toLowerCase();
    const pages: Item[] = this.pages()
      .filter((p) => !q || p.label.toLowerCase().includes(q))
      .map((p) => ({
        kind: 'page',
        id: p.path,
        label: p.label,
        detail: 'Page',
        icon: p.icon,
        path: [p.path],
      }));
    const hosts: Item[] = this.hostHits()
      .slice(0, MAX_HOSTS)
      .map((a) => ({
        kind: 'host',
        id: a.id,
        label: a.name,
        detail: [a.primaryIp, a.osPrettyName].filter(Boolean).join(' · '),
        online: isOnline(a),
        path: ['/hosts', a.id],
      }));
    // Typing usually means a host; with no query the pages come first.
    return q ? [...hosts, ...pages] : [...pages, ...hosts];
  });

  constructor() {
    afterNextRender(() => this.inputEl().nativeElement.focus());
  }

  onInput(v: string): void {
    this.query.set(v);
    this.index.set(0);
  }

  onKey(e: KeyboardEvent): void {
    const n = this.items().length;
    if (e.key === 'ArrowDown' && n) {
      this.index.set((this.index() + 1) % n);
    } else if (e.key === 'ArrowUp' && n) {
      this.index.set((this.index() - 1 + n) % n);
    } else if (e.key === 'Enter') {
      const it = this.items()[this.index()];
      if (it) this.go(it);
    } else {
      return;
    }
    e.preventDefault();
    this.scrollActive();
  }

  go(it: Item): void {
    void this.router.navigate(it.path);
    this.closed.emit();
  }

  private scrollActive(): void {
    queueMicrotask(() =>
      document.getElementById('pal-' + this.index())?.scrollIntoView({ block: 'nearest' }),
    );
  }
}
