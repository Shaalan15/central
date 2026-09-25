// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Routes } from '@angular/router';

import { anonymousGuard, authGuard, mfaEnrollmentGuard, setupGuard } from './core/guards';

const placeholder = (title: string) => ({
  loadComponent: () => import('./features/hosts/placeholder').then((m) => m.Placeholder),
  data: { title },
});

export const routes: Routes = [
  {
    path: 'setup',
    canMatch: [setupGuard],
    title: 'Set up Central',
    loadComponent: () => import('./features/setup/setup').then((m) => m.Setup),
  },
  {
    path: 'login',
    canActivate: [anonymousGuard],
    title: 'Sign in · Central',
    loadComponent: () => import('./features/auth/login').then((m) => m.Login),
  },
  {
    path: 'mfa',
    canActivate: [mfaEnrollmentGuard],
    title: 'Two-factor authentication · Central',
    loadComponent: () => import('./features/auth/enroll-mfa').then((m) => m.EnrollMfa),
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./features/shell/shell').then((m) => m.Shell),
    children: [
      {
        path: '',
        title: 'Fleet · Central',
        loadComponent: () => import('./features/fleet/dashboard').then((m) => m.Dashboard),
      },
      {
        path: 'hosts/:id',
        title: 'Host · Central',
        loadComponent: () => import('./features/hosts/host').then((m) => m.Host),
        children: [
          { path: '', pathMatch: 'full', redirectTo: 'overview' },
          {
            path: 'overview',
            loadComponent: () => import('./features/hosts/overview').then((m) => m.Overview),
          },
          { path: 'updates', ...placeholder('Updates') },
          { path: 'packages', ...placeholder('Packages') },
          { path: 'services', ...placeholder('Services') },
          { path: 'logs', ...placeholder('Logs') },
          { path: 'processes', ...placeholder('Processes') },
          { path: 'terminal', ...placeholder('Terminal') },
          { path: 'network', ...placeholder('Network') },
          { path: 'storage', ...placeholder('Storage') },
          { path: 'policy', ...placeholder('Owner policy') },
        ],
      },
      { path: 'approvals', title: 'Approvals · Central', ...placeholder('Approvals') },
      { path: 'enrollment', title: 'Enrollment · Central', ...placeholder('Enrollment tokens') },
      { path: 'jobs', title: 'Jobs · Central', ...placeholder('Jobs') },
      { path: 'audit', title: 'Audit log · Central', ...placeholder('Audit log') },
      { path: 'settings', title: 'Settings · Central', ...placeholder('Settings') },
      {
        path: 'settings/account',
        title: 'Account · Central',
        ...placeholder('Account and security'),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
