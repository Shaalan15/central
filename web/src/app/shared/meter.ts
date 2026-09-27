// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

/** Thin usage bar with a value label; turns amber at 75% and red at 90%. */
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
      gap: 6px;
      width: 100%;
      min-width: 0;
    }
    .track {
      flex: 1;
      height: 4px;
      background: var(--track);
      overflow: hidden;
    }
    .fill {
      display: block;
      height: 100%;
      background: color-mix(in srgb, var(--accent) 80%, transparent);
      transition: width 300ms ease;
    }
    :host(.warn) .fill {
      background: var(--warn);
    }
    :host(.crit) .fill {
      background: var(--crit);
    }
    :host(.warn) .value {
      color: var(--warn);
    }
    :host(.crit) .value {
      color: var(--crit);
    }
    .value {
      width: 3em;
      text-align: right;
      font-size: var(--fs-sm);
      color: var(--text-2);
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
