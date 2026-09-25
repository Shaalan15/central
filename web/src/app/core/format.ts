// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { timestampDate } from '@bufbuild/protobuf/wkt';

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

/** Formats a byte count ("1.5 GiB"). */
export function bytes(n: number | bigint | undefined): string {
  let v = Number(n ?? 0);
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${UNITS[i]}`;
}

/** Formats a rate in bytes per second. */
export function rate(n: number | undefined): string {
  return `${bytes(n ?? 0)}/s`;
}

/** Formats a percentage (0–100) without decimals below 10%. */
export function percent(v: number | undefined): string {
  const n = v ?? 0;
  return `${n < 10 ? n.toFixed(1) : n.toFixed(0)}%`;
}

export function toDate(ts: Timestamp | undefined): Date | undefined {
  return ts ? timestampDate(ts) : undefined;
}

/** "3 min ago", "2 h ago", "just now". */
export function ago(ts: Timestamp | Date | undefined, now = Date.now()): string {
  const d = ts instanceof Date ? ts : toDate(ts);
  if (!d || d.getTime() <= 0) return 'never';
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < 10) return 'just now';
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** "12 d 4 h", "3 h 20 min", "45 s". */
export function duration(seconds: number | bigint | undefined): string {
  const s = Number(seconds ?? 0);
  if (s >= 86400) return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
  if (s >= 3600) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  if (s >= 60) return `${Math.floor(s / 60)} min`;
  return `${Math.floor(s)} s`;
}

/** Formats a date for tables. */
export function dateTime(ts: Timestamp | undefined): string {
  const d = toDate(ts);
  return d && d.getTime() > 0
    ? d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : '—';
}
