// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButton } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormField, MatInput, MatLabel } from '@angular/material/input';

import { MfaMethodType } from '../../gen/central/api/v1/auth_pb';
import { errorMessage } from './api';
import { getAssertion, passkeysSupported } from './webauthn';

export interface StepUpData {
  methods: MfaMethodType[];
  passkeyOptions: string;
  totp: (code: string) => Promise<void>;
  passkey: (credential: string) => Promise<void>;
}

@Component({
  selector: 'app-step-up-dialog',
  imports: [MatDialogModule, MatButton, MatFormField, MatLabel, MatInput, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h2 mat-dialog-title>Confirm it's you</h2>
    <mat-dialog-content>
      <p class="hint">This action needs a recent verification of your second factor.</p>
      @if (hasTotp) {
        <form id="step-up-form" (ngSubmit)="submitTotp()">
          <mat-form-field appearance="outline" class="code">
            <mat-label>Authenticator code</mat-label>
            <input
              matInput
              name="code"
              [(ngModel)]="code"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              pattern="[0-9]{6}"
              required
              cdkFocusInitial
            />
          </mat-form-field>
        </form>
      }
      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button type="button" (click)="ref.close(false)">Cancel</button>
      @if (hasPasskey) {
        <button mat-button type="button" [disabled]="busy()" (click)="usePasskey()">
          Use a passkey
        </button>
      }
      @if (hasTotp) {
        <button
          mat-flat-button
          type="submit"
          form="step-up-form"
          [disabled]="busy() || code.length !== 6"
        >
          Verify
        </button>
      }
    </mat-dialog-actions>
  `,
  styles: `
    .hint {
      color: var(--mat-sys-on-surface-variant);
      margin-top: 0;
    }
    .code {
      width: 100%;
    }
    .error {
      color: var(--mat-sys-error);
    }
  `,
})
export class StepUpDialog {
  readonly ref = inject(MatDialogRef<StepUpDialog, boolean>);
  private readonly data = inject<StepUpData>(MAT_DIALOG_DATA);
  readonly hasTotp = this.data.methods.includes(MfaMethodType.TOTP);
  readonly hasPasskey = passkeysSupported() && !!this.data.passkeyOptions;
  code = '';
  readonly busy = signal(false);
  readonly error = signal('');

  async submitTotp(): Promise<void> {
    await this.run(() => this.data.totp(this.code));
  }

  async usePasskey(): Promise<void> {
    await this.run(async () => this.data.passkey(await getAssertion(this.data.passkeyOptions)));
  }

  private async run(fn: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    try {
      await fn();
      this.ref.close(true);
    } catch (err) {
      this.error.set(errorMessage(err));
      this.code = '';
    } finally {
      this.busy.set(false);
    }
  }
}
