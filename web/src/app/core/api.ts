// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import type { DescService } from '@bufbuild/protobuf';
import {
  Code,
  ConnectError,
  createClient,
  type Client,
  type Interceptor,
  type Transport,
} from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';

import { StepUp } from './step-up';

/** Machine-readable reasons sent by Central in the `Central-Reason` error header. */
export const REASON_STEP_UP = 'step_up_required';
export const REASON_CONFIRM_COUNT = 'confirm_target_count';
export const REASON_POLICY_DENIED = 'policy_denied';
export const REASON_PAUSED = 'paused';

/** Returns the Central reason of an RPC error ('' if none). */
export function errorReason(err: unknown): string {
  return err instanceof ConnectError ? (err.metadata.get('Central-Reason') ?? '') : '';
}

/** Returns a human-readable message for an RPC error. */
export function errorMessage(err: unknown): string {
  if (err instanceof ConnectError) {
    if (err.code === Code.Unavailable) return 'Central is not reachable. Check your connection.';
    return err.rawMessage || err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export function isCode(err: unknown, code: Code): boolean {
  return err instanceof ConnectError && err.code === code;
}

/**
 * Api owns the Connect transport for the Central API. It adds the CSRF header, sends users to
 * sign-in when their session ends, and runs the step-up dialog (then retries once) when an
 * action needs a recent re-authentication.
 */
@Injectable({ providedIn: 'root' })
export class Api {
  private readonly router = inject(Router);
  private readonly stepUp = inject(StepUp);
  private csrf = '';
  private readonly clients = new Map<DescService, unknown>();

  /** Called by the session store whenever the CSRF token changes. */
  setCsrf(token: string): void {
    this.csrf = token;
  }

  private readonly csrfInterceptor: Interceptor = (next) => async (req) => {
    if (this.csrf) req.header.set('X-CSRF-Token', this.csrf);
    return next(req);
  };

  private readonly errorInterceptor: Interceptor = (next) => async (req) => {
    try {
      return await next(req);
    } catch (err) {
      if (!req.stream && errorReason(err) === REASON_STEP_UP) {
        if (await this.stepUp.prompt()) {
          if (this.csrf) req.header.set('X-CSRF-Token', this.csrf);
          return await next(req);
        }
      }
      if (
        isCode(err, Code.Unauthenticated) &&
        !req.url.includes('AuthService/') &&
        !req.url.includes('SetupService/')
      ) {
        void this.router.navigate(['/login'], {
          queryParams: { next: this.router.url === '/login' ? undefined : this.router.url },
        });
      }
      throw err;
    }
  };

  readonly transport: Transport = createConnectTransport({
    baseUrl: '/api',
    useBinaryFormat: true,
    interceptors: [this.errorInterceptor, this.csrfInterceptor],
  });

  /** Returns a (cached) typed client for a service. */
  client<T extends DescService>(service: T): Client<T> {
    let c = this.clients.get(service) as Client<T> | undefined;
    if (!c) {
      c = createClient(service, this.transport);
      this.clients.set(service, c);
    }
    return c;
  }
}
