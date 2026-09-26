// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

/** Pages that must never be the target of a post-sign-in redirect (they would loop). */
const AUTH_PAGES = ['/login', '/mfa', '/setup'];

/**
 * Returns `next` when it is an in-app path on this origin, otherwise "/". Used for the `next`
 * query parameter after sign-in so it can never become an open redirect: absolute and
 * protocol-relative URLs, backslashes (browsers treat "/\" like "//") and control characters
 * are all rejected.
 */
export function safeRedirect(next: string | null | undefined, origin = location.origin): string {
  const n = next ?? '';
  if (!n.startsWith('/') || n.startsWith('//')) return '/';
  for (const c of n) {
    const code = c.charCodeAt(0);
    if (c === '\\' || code < 0x20 || code === 0x7f) return '/';
  }
  let url: URL;
  try {
    url = new URL(n, origin);
  } catch {
    return '/';
  }
  if (url.origin !== origin) return '/';
  if (AUTH_PAGES.some((p) => url.pathname === p || url.pathname.startsWith(p + '/'))) return '/';
  return url.pathname + url.search + url.hash;
}
