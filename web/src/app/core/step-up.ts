// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Injectable, Injector, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { AuthService } from '../../gen/central/api/v1/auth_pb';
import { Api } from './api';

/** StepUp asks the user to re-verify their second factor for sensitive actions. */
@Injectable({ providedIn: 'root' })
export class StepUp {
  private readonly injector = inject(Injector);
  private pending: Promise<boolean> | null = null;

  /** Opens the step-up dialog (once, even if several requests need it) and reports success. */
  prompt(): Promise<boolean> {
    this.pending ??= this.open().finally(() => (this.pending = null));
    return this.pending;
  }

  private async open(): Promise<boolean> {
    // Resolved lazily: Api depends on StepUp.
    const auth = this.injector.get(Api).client(AuthService);
    const begin = await auth.beginStepUp({});
    // Loaded on demand: keeps Material Dialog out of the initial bundle.
    const [{ MatDialog }, { StepUpDialog }] = await Promise.all([
      import('@angular/material/dialog'),
      import('./step-up-dialog'),
    ]);
    const ref = this.injector.get(MatDialog).open(StepUpDialog, {
      width: '420px',
      data: {
        methods: begin.methods,
        passkeyOptions: begin.passkeyOptionsJson,
        totp: async (code: string) => {
          await auth.finishStepUp({ proof: { case: 'totpCode', value: code } });
        },
        passkey: async (credential: string) => {
          await auth.finishStepUp({ proof: { case: 'passkeyCredentialJson', value: credential } });
        },
      },
    });
    return (await firstValueFrom(ref.afterClosed())) ?? false;
  }
}
