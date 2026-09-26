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
      <div class="panel">
        <div class="panel-head">
          <h2>{{ title }}</h2>
        </div>
        <p class="panel-body faint">
          <app-icon name="schedule" [size]="16" /> This screen is part of the next UI milestone.
        </p>
      </div>
    </div>
  `,
  styles: `
    .panel-body {
      display: flex;
      align-items: center;
      gap: 6px;
      margin: 0;
      padding: 16px 10px;
    }
  `,
})
export class Placeholder {
  readonly title =
    (inject(ActivatedRoute).snapshot.data['title'] as string | undefined) ?? 'Coming soon';
}
