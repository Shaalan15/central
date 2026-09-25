// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { safeRedirect } from './redirect';

const ORIGIN = 'https://central.example';

describe('safeRedirect', () => {
  it('keeps in-app paths with query and fragment', () => {
    expect(safeRedirect('/hosts/a1/overview', ORIGIN)).toBe('/hosts/a1/overview');
    expect(safeRedirect('/audit?actor=u1#top', ORIGIN)).toBe('/audit?actor=u1#top');
  });

  it('rejects anything that could leave the origin', () => {
    for (const bad of [
      'https://evil.example/',
      '//evil.example',
      '/\\evil.example',
      '\\\\evil.example',
      '/\t/evil.example',
      '/%0a/evil',
      'javascript:alert(1)',
      'evil.example',
      ' /hosts',
      '',
      null,
      undefined,
    ]) {
      const got = safeRedirect(bad, ORIGIN);
      expect(new URL(got, ORIGIN).origin, String(bad)).toBe(ORIGIN);
      if (bad !== '/%0a/evil') expect(got, String(bad)).toBe('/');
    }
  });

  it('never redirects back to the sign-in pages', () => {
    for (const p of ['/login', '/login?next=/x', '/mfa', '/setup', '/setup/step']) {
      expect(safeRedirect(p, ORIGIN)).toBe('/');
    }
    expect(safeRedirect('/loginhistory', ORIGIN)).toBe('/loginhistory');
  });
});
