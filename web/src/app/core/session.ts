// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Injectable, computed, inject, signal } from '@angular/core';
import { Code } from '@connectrpc/connect';

import {
  AuthService,
  SessionStage,
  type GetSessionResponse,
} from '../../gen/central/api/v1/auth_pb';
import { SetupService, type GetSetupStatusResponse } from '../../gen/central/api/v1/setup_pb';
import { Api, isCode } from './api';

/** Session holds who is signed in, their organization and effective permissions. */
@Injectable({ providedIn: 'root' })
export class Session {
  private readonly api = inject(Api);
  private readonly auth = this.api.client(AuthService);

  readonly state = signal<GetSessionResponse | null>(null);
  readonly setup = signal<GetSetupStatusResponse | null>(null);

  readonly stage = computed(() => this.state()?.stage ?? SessionStage.UNSPECIFIED);
  readonly signedIn = computed(() => this.stage() === SessionStage.FULL);
  readonly user = computed(() => this.state()?.user);
  readonly org = computed(() => this.state()?.activeOrganization);
  readonly permissions = computed(() => new Set(this.state()?.permissions ?? []));

  /** Reports whether the user holds a permission (somewhere; the server checks scopes). */
  can(permission: string): boolean {
    return this.permissions().has(permission);
  }

  /** Loads setup status and the current session (at startup and after sign-in changes). */
  async refresh(): Promise<void> {
    try {
      this.setup.set(await this.api.client(SetupService).getSetupStatus({}));
    } catch {
      this.setup.set(null);
    }
    try {
      const s = await this.auth.getSession({});
      this.state.set(s);
      this.api.setCsrf(s.csrfToken);
    } catch (err) {
      if (!isCode(err, Code.Unauthenticated)) console.warn('session refresh failed', err);
      this.state.set(null);
      this.api.setCsrf('');
    }
  }

  async logout(): Promise<void> {
    try {
      await this.auth.logout({});
    } finally {
      this.state.set(null);
      this.api.setCsrf('');
    }
  }
}
