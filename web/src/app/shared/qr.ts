// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { encode } from 'uqr';

/** QR code rendered as SVG rectangles (for otpauth:// enrollment URIs). */
@Component({
  selector: 'app-qr',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <svg
      [attr.viewBox]="viewBox()"
      [attr.width]="size()"
      [attr.height]="size()"
      shape-rendering="crispEdges"
      role="img"
      aria-label="QR code"
    >
      <rect [attr.width]="dim() + 8" [attr.height]="dim() + 8" x="-4" y="-4" fill="#fff" />
      <path [attr.d]="path()" fill="#000" />
    </svg>
  `,
})
export class Qr {
  readonly value = input.required<string>();
  readonly size = input(200);
  private readonly data = computed(() => encode(this.value(), { ecc: 'M', border: 0 }).data);
  readonly dim = computed(() => this.data().length);
  readonly viewBox = computed(() => `-4 -4 ${this.dim() + 8} ${this.dim() + 8}`);
  readonly path = computed(() => {
    let d = '';
    this.data().forEach((row, y) =>
      row.forEach((on, x) => {
        if (on) d += `M${x} ${y}h1v1h-1z`;
      }),
    );
    return d;
  });
}
