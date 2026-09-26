// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ago, bytes, duration, percent, rate } from './format';

describe('format', () => {
  it('formats bytes in binary units', () => {
    expect(bytes(0)).toBe('0 B');
    expect(bytes(1023)).toBe('1023 B');
    expect(bytes(1536)).toBe('1.5 KiB');
    expect(bytes(150n * 1024n * 1024n)).toBe('150 MiB');
    expect(bytes(undefined)).toBe('0 B');
    expect(rate(2048)).toBe('2.0 KiB/s');
  });

  it('formats percentages', () => {
    expect(percent(5.25)).toBe('5.3%');
    expect(percent(42.4)).toBe('42%');
  });

  it('formats relative times and durations', () => {
    const now = Date.UTC(2026, 0, 1);
    expect(ago(new Date(now - 5_000), now)).toBe('just now');
    expect(ago(new Date(now - 90_000), now)).toBe('1 min ago');
    expect(ago(new Date(now - 3 * 86400e3), now)).toBe('3 d ago');
    expect(ago(undefined, now)).toBe('never');
    expect(duration(45)).toBe('45 s');
    expect(duration(3 * 3600 + 20 * 60)).toBe('3 h 20 min');
    expect(duration(12n * 86400n + 4n * 3600n)).toBe('12 d 4 h');
  });
});
