// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { inject } from '@angular/core';
import { Router, type CanActivateFn, type CanMatchFn } from '@angular/router';

import { SessionStage } from '../../gen/central/api/v1/auth_pb';
import { Session } from './session';

/** The setup wizard is only reachable before setup has completed. */
export const setupGuard: CanMatchFn = () => {
  const s = inject(Session);
  return s.setup()?.complete === false ? true : inject(Router).parseUrl('/login');
};

/** Sign-in pages redirect to setup (fresh install) or into the app (already signed in). */
export const anonymousGuard: CanActivateFn = () => {
  const s = inject(Session);
  const router = inject(Router);
  if (s.setup()?.complete === false) return router.parseUrl('/setup');
  if (s.signedIn()) return router.parseUrl('/');
  return true;
};

export const mfaEnrollmentGuard: CanActivateFn = () => {
  const s = inject(Session);
  return s.stage() === SessionStage.MFA_ENROLLMENT
    ? true
    : inject(Router).parseUrl(s.signedIn() ? '/' : '/login');
};

/** The app requires a fully authenticated session. */
export const authGuard: CanActivateFn = (_route, state) => {
  const s = inject(Session);
  const router = inject(Router);
  if (s.setup()?.complete === false) return router.parseUrl('/setup');
  if (s.signedIn()) return true;
  if (s.stage() === SessionStage.MFA_ENROLLMENT) return router.parseUrl('/mfa');
  return router.createUrlTree(['/login'], {
    queryParams: state.url && state.url !== '/' ? { next: state.url } : {},
  });
};
