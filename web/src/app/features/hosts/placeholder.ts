// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { Icon } from '../../shared/icon';

/** Temporary page for screens that follow the UI checkpoint. */
@Component({
  selector: 'app-placeholder',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="page">
      <div class="card empty">
        <app-icon name="schedule" [size]="36" />
        <h2>{{ title }}</h2>
        <p class="muted">This screen is part of the next UI milestone.</p>
      </div>
    </div>
  `,
  styles: `
    .empty {
      display: grid;
      justify-items: center;
      gap: 6px;
      padding: 48px 16px;
      text-align: center;
      color: var(--mat-sys-on-surface-variant);
    }
    h2 {
      margin: 0;
      color: var(--mat-sys-on-surface);
      font: var(--mat-sys-title-medium);
    }
  `,
})
export class Placeholder {
  readonly title =
    (inject(ActivatedRoute).snapshot.data['title'] as string | undefined) ?? 'Coming soon';
}
