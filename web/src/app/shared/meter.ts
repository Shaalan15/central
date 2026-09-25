// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

/** Compact usage bar with a value label; turns amber at 75% and red at 90%. */
@Component({
  selector: 'app-meter',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    '[class.warn]': 'level() === "warn"',
    '[class.crit]': 'level() === "crit"',
    '[attr.title]': 'title()',
  },
  template: `
    <span class="track"><span class="fill" [style.width.%]="clamped()"></span></span>
    <span class="value tabular-nums">{{ label() }}</span>
  `,
  styles: `
    :host {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      min-width: 0;
    }
    .track {
      flex: 1;
      height: 6px;
      border-radius: 3px;
      background: var(--mat-sys-surface-container-highest);
      overflow: hidden;
    }
    .fill {
      display: block;
      height: 100%;
      border-radius: 3px;
      background: var(--mat-sys-primary);
      transition: width 400ms ease;
    }
    :host(.warn) .fill {
      background: var(--app-warn, #e3a008);
    }
    :host(.crit) .fill {
      background: var(--mat-sys-error);
    }
    .value {
      width: 3.2em;
      text-align: right;
      font: var(--mat-sys-label-medium);
      color: var(--mat-sys-on-surface-variant);
    }
  `,
})
export class Meter {
  readonly value = input(0);
  readonly unknown = input(false);
  readonly title = input('');
  readonly clamped = computed(() =>
    this.unknown() ? 0 : Math.max(0, Math.min(100, this.value())),
  );
  readonly level = computed(() =>
    this.unknown() ? 'ok' : this.value() >= 90 ? 'crit' : this.value() >= 75 ? 'warn' : 'ok',
  );
  readonly label = computed(() => {
    if (this.unknown()) return '—';
    const v = this.value();
    return `${v < 10 ? v.toFixed(1) : v.toFixed(0)}%`;
  });
}
