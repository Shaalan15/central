// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Injectable, effect, signal } from '@angular/core';

const COLLAPSED = 'central.sidebar.collapsed';
const WIDTH = 'central.sidebar.width';

export const SIDEBAR_MIN = 220;
export const SIDEBAR_MAX = 480;
const SIDEBAR_DEFAULT = 264;

/** Reads a per-browser preference (null when unset or storage is unavailable). */
export function readPref(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** Stores a per-browser preference; silently skipped when storage is unavailable. */
export function writePref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: the preference lasts for this page only */
  }
}

export const clampWidth = (w: number) =>
  Math.round(Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, w)));

/** Shell layout preferences (remembered per browser) and the command palette state. */
@Injectable({ providedIn: 'root' })
export class Layout {
  /** Desktop sidebar collapsed to an icon rail. */
  readonly collapsed = signal(readPref(COLLAPSED) === '1');
  /** Desktop sidebar width in pixels. */
  readonly width = signal(clampWidth(Number(readPref(WIDTH)) || SIDEBAR_DEFAULT));
  /** Mobile navigation drawer. */
  readonly drawerOpen = signal(false);
  readonly paletteOpen = signal(false);

  constructor() {
    effect(() => writePref(COLLAPSED, this.collapsed() ? '1' : '0'));
    effect(() => writePref(WIDTH, String(this.width())));
  }

  toggleCollapsed(): void {
    this.collapsed.update((c) => !c);
  }
}
