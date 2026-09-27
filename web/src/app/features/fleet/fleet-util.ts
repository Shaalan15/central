// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { PolicyProfile } from '../../../gen/central/agent/v1/policy_pb';
import { ConnectionState, type AgentSummary } from '../../../gen/central/api/v1/fleet_pb';

/** Quick filters shared by the sidebar host list and the fleet overview. */
export type HostFilter =
  'all' | 'online' | 'offline' | 'updates' | 'security' | 'reboot' | 'pressure';

export type HostSort = 'name' | 'cpu' | 'memory' | 'disk' | 'updates' | 'seen';

export const FILTER_LABELS: Record<HostFilter, string> = {
  all: 'All hosts',
  online: 'Online',
  offline: 'Offline',
  updates: 'Updates available',
  security: 'Security updates',
  reboot: 'Reboot required',
  pressure: 'Under pressure',
};

export const SORT_LABELS: Record<HostSort, string> = {
  name: 'Name',
  cpu: 'CPU',
  memory: 'Memory',
  disk: 'Disk',
  updates: 'Updates',
  seen: 'Uptime',
};

export const PROFILE_LABELS: Record<number, string> = {
  [PolicyProfile.OBSERVE]: 'Observe',
  [PolicyProfile.OPERATE]: 'Operate',
  [PolicyProfile.ADMINISTER]: 'Administer',
  [PolicyProfile.FULL]: 'Full',
};

export const isOnline = (a: AgentSummary) => a.connection === ConnectionState.ONLINE;

/** Usage threshold level used for bars and values: warn at 75%, critical at 90%. */
export function level(v: number): '' | 'warn' | 'crit' {
  return v >= 90 ? 'crit' : v >= 75 ? 'warn' : '';
}

export function underPressure(a: AgentSummary): boolean {
  return (
    isOnline(a) && (a.cpuPercent > 90 || a.memoryUsedPercent > 90 || a.diskUsedPercentMax > 90)
  );
}

export function matchesFilter(a: AgentSummary, f: HostFilter): boolean {
  switch (f) {
    case 'online':
      return isOnline(a);
    case 'offline':
      return !isOnline(a);
    case 'updates':
      return a.updatesAvailable > 0;
    case 'security':
      return a.securityUpdates > 0;
    case 'reboot':
      return a.rebootRequired;
    case 'pressure':
      return underPressure(a);
    case 'all':
      return true;
  }
}

/** Case-insensitive match on name, hostname, IP prefix, OS and tags. */
export function matchesQuery(a: AgentSummary, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    a.name.toLowerCase().includes(q) ||
    a.hostname.toLowerCase().includes(q) ||
    a.primaryIp.startsWith(q) ||
    a.osPrettyName.toLowerCase().includes(q) ||
    a.tags.some((t) => t.toLowerCase().includes(q))
  );
}

export function countByFilter(list: readonly AgentSummary[]): Record<HostFilter, number> {
  const c: Record<HostFilter, number> = {
    all: list.length,
    online: 0,
    offline: 0,
    updates: 0,
    security: 0,
    reboot: 0,
    pressure: 0,
  };
  for (const a of list) {
    if (isOnline(a)) c.online++;
    else c.offline++;
    if (a.updatesAvailable) c.updates++;
    if (a.securityUpdates) c.security++;
    if (a.rebootRequired) c.reboot++;
    if (underPressure(a)) c.pressure++;
  }
  return c;
}

const byName = (x: AgentSummary, y: AgentSummary) =>
  x.name.localeCompare(y.name, undefined, { numeric: true, sensitivity: 'base' });

/** Sorts in place: names naturally ("web-2" before "web-10"), metrics numerically. */
export function sortHosts(list: AgentSummary[], key: HostSort, desc: boolean): AgentSummary[] {
  const dir = desc ? -1 : 1;
  if (key === 'name') return list.sort((x, y) => byName(x, y) * dir);
  const val = (a: AgentSummary): number => {
    switch (key) {
      case 'cpu':
        return isOnline(a) ? a.cpuPercent : -1;
      case 'memory':
        return isOnline(a) ? a.memoryUsedPercent : -1;
      case 'disk':
        return a.diskUsedPercentMax;
      case 'updates':
        return a.securityUpdates * 10_000 + a.updatesAvailable;
      case 'seen':
        return isOnline(a) ? Number(a.uptimeSeconds) : -1;
    }
  };
  return list.sort((x, y) => (val(x) - val(y)) * dir || byName(x, y));
}

/** Filters and sorts a copy of the fleet list. */
export function selectHosts(
  list: readonly AgentSummary[],
  opts: { query: string; filter: HostFilter; sort: HostSort; desc: boolean },
): AgentSummary[] {
  return sortHosts(
    list.filter((a) => matchesFilter(a, opts.filter) && matchesQuery(a, opts.query)),
    opts.sort,
    opts.desc,
  );
}
