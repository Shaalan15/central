// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { hostRoute } from './host-nav';

describe('hostRoute', () => {
  it('parses the host and tab from the URL', () => {
    expect(hostRoute('/hosts/abc/updates')).toEqual({ id: 'abc', tab: 'updates' });
    expect(hostRoute('/hosts/abc?x=1')).toEqual({ id: 'abc', tab: 'overview' });
    expect(hostRoute('/hosts/a%2Fb/logs#top')).toEqual({ id: 'a/b', tab: 'logs' });
    expect(hostRoute('/jobs')).toBeNull();
  });
});
