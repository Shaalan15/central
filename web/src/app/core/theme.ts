// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { DOCUMENT, Injectable, effect, inject, signal } from '@angular/core';

export type ThemeMode = 'system' | 'light' | 'dark';
const KEY = 'central.theme';

/** Theme switches between the OS preference and forced light or dark (remembered locally). */
@Injectable({ providedIn: 'root' })
export class Theme {
  private readonly doc = inject(DOCUMENT);
  readonly mode = signal<ThemeMode>(this.load());

  constructor() {
    effect(() => {
      const m = this.mode();
      const cl = this.doc.documentElement.classList;
      cl.toggle('theme-light', m === 'light');
      cl.toggle('theme-dark', m === 'dark');
      try {
        localStorage.setItem(KEY, m);
      } catch {
        /* storage unavailable */
      }
    });
  }

  /** Cycles system → dark → light. */
  toggle(): void {
    this.mode.update((m) => (m === 'system' ? 'dark' : m === 'dark' ? 'light' : 'system'));
  }

  private load(): ThemeMode {
    try {
      const v = localStorage.getItem(KEY);
      if (v === 'light' || v === 'dark' || v === 'system') return v;
    } catch {
      /* storage unavailable */
    }
    return 'system';
  }
}
