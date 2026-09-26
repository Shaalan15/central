// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { create, type MessageInitShape } from '@bufbuild/protobuf';

import {
  AgentSummarySchema,
  ConnectionState,
  type AgentSummary,
} from '../../../gen/central/api/v1/fleet_pb';
import { countByFilter, level, matchesQuery, selectHosts, underPressure } from './fleet-util';

const host = (over: MessageInitShape<typeof AgentSummarySchema>): AgentSummary =>
  create(AgentSummarySchema, { connection: ConnectionState.ONLINE, ...over });

const fleet = [
  host({ id: 'a', name: 'web-10', primaryIp: '10.0.0.10', cpuPercent: 20, tags: ['web'] }),
  host({
    id: 'b',
    name: 'web-2',
    primaryIp: '10.0.0.2',
    cpuPercent: 95,
    securityUpdates: 3,
    updatesAvailable: 5,
  }),
  host({
    id: 'c',
    name: 'db-1',
    osPrettyName: 'Debian GNU/Linux 13',
    connection: ConnectionState.OFFLINE,
  }),
  host({ id: 'd', name: 'edge', rebootRequired: true, updatesAvailable: 1 }),
];

describe('fleet-util', () => {
  it('filters by query on name, IP prefix, OS and tags', () => {
    expect(matchesQuery(fleet[0]!, 'WEB')).toBe(true);
    expect(matchesQuery(fleet[0]!, '10.0.0.1')).toBe(true);
    expect(matchesQuery(fleet[1]!, '0.0.2')).toBe(false);
    expect(matchesQuery(fleet[2]!, 'debian')).toBe(true);
    expect(matchesQuery(fleet[0]!, '')).toBe(true);
  });

  it('counts quick filters', () => {
    expect(countByFilter(fleet)).toEqual({
      all: 4,
      online: 3,
      offline: 1,
      updates: 2,
      security: 1,
      reboot: 1,
      pressure: 1,
    });
    expect(underPressure(fleet[1]!)).toBe(true);
  });

  it('sorts names naturally and puts offline hosts last by CPU', () => {
    const byName = selectHosts(fleet, { query: 'web', filter: 'all', sort: 'name', desc: false });
    expect(byName.map((a) => a.name)).toEqual(['web-2', 'web-10']);
    const byCpu = selectHosts(fleet, { query: '', filter: 'all', sort: 'cpu', desc: true });
    expect(byCpu.map((a) => a.id)).toEqual(['b', 'a', 'd', 'c']);
    const security = selectHosts(fleet, {
      query: '',
      filter: 'security',
      sort: 'name',
      desc: false,
    });
    expect(security.map((a) => a.id)).toEqual(['b']);
  });

  it('maps usage to warning levels', () => {
    expect(level(10)).toBe('');
    expect(level(75)).toBe('warn');
    expect(level(90)).toBe('crit');
  });
});
