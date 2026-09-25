// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import { ICONS, type IconName } from './icons.generated';

/** Inline Material Symbols icon (no font, no innerHTML). */
@Component({
  selector: 'app-icon',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'app-icon',
    '[attr.aria-hidden]': '!label()',
    '[attr.role]': 'label() ? "img" : null',
    '[attr.aria-label]': 'label() || null',
  },
  template: `<svg
    viewBox="0 -960 960 960"
    [attr.width]="size()"
    [attr.height]="size()"
    focusable="false"
  >
    <path [attr.d]="path()" />
  </svg>`,
  styles: `
    :host {
      display: inline-flex;
      line-height: 0;
      vertical-align: middle;
    }
    svg {
      fill: currentColor;
    }
  `,
})
export class Icon {
  readonly name = input.required<IconName>();
  readonly size = input(20);
  readonly label = input('');
  readonly path = computed(() => ICONS[this.name()]);
}
