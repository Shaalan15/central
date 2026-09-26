// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButton } from '@angular/material/button';
import { MatFormField, MatHint, MatInput, MatLabel } from '@angular/material/input';
import { MatProgressBar } from '@angular/material/progress-bar';
import { Router } from '@angular/router';

import { AuthService } from '../../../gen/central/api/v1/auth_pb';
import { Api, errorMessage } from '../../core/api';
import { safeRedirect } from '../../core/redirect';
import { Session } from '../../core/session';
import { createCredential, passkeysSupported } from '../../core/webauthn';
import { Icon } from '../../shared/icon';
import { Qr } from '../../shared/qr';

@Component({
  selector: 'app-enroll-mfa',
  imports: [
    FormsModule,
    MatButton,
    MatFormField,
    MatHint,
    MatInput,
    MatLabel,
    MatProgressBar,
    Icon,
    Qr,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="auth-page">
      <section class="auth-card" aria-labelledby="mfa-title">
        <header class="brand">
          <app-icon name="shield" [size]="28" />
          <div>
            <h1 id="mfa-title">Protect your account</h1>
            <p class="muted">Two-factor authentication is required for everyone.</p>
          </div>
        </header>
        @if (busy()) {
          <mat-progress-bar mode="indeterminate" />
        }
        @if (codes().length) {
          <div class="form">
            <p>
              <strong>Save these recovery codes.</strong> Each works once if you lose your
              authenticator. They are shown only now.
            </p>
            <ol class="codes tabular-nums">
              @for (c of codes(); track c) {
                <li>{{ c }}</li>
              }
            </ol>
            <div class="actions stretch">
              <button mat-stroked-button type="button" (click)="copyCodes()">
                <app-icon name="content_copy" /> Copy
              </button>
              <button mat-flat-button type="button" (click)="finish()">
                I saved them, continue
              </button>
            </div>
          </div>
        } @else if (secret()) {
          <form class="form" (ngSubmit)="confirmTotp()">
            <p>
              Scan the code with your authenticator app (for example Aegis, 1Password, Google
              Authenticator), then enter the 6-digit code it shows.
            </p>
            <div class="qr"><app-qr [value]="uri()" [size]="184" /></div>
            <p class="secret muted">
              Or enter the key manually:
              <code>{{ groupedSecret() }}</code>
            </p>
            <mat-form-field appearance="outline">
              <mat-label>6-digit code</mat-label>
              <input
                matInput
                name="code"
                [(ngModel)]="code"
                required
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
              />
            </mat-form-field>
            <div class="actions stretch">
              <button mat-flat-button [disabled]="busy() || code.length !== 6">Confirm</button>
            </div>
          </form>
        } @else {
          <div class="form options">
            <button
              mat-stroked-button
              type="button"
              class="option"
              [disabled]="busy()"
              (click)="startTotp()"
            >
              <app-icon name="schedule" [size]="24" />
              <span
                ><strong>Authenticator app</strong><br /><span class="muted"
                  >Time-based 6-digit codes</span
                ></span
              >
            </button>
            @if (passkeys) {
              <div class="passkey">
                <mat-form-field appearance="outline">
                  <mat-label>Passkey name</mat-label>
                  <input matInput name="pkname" [(ngModel)]="passkeyName" />
                  <mat-hint>For example "YubiKey 5C" or "MacBook Touch ID"</mat-hint>
                </mat-form-field>
                <button
                  mat-stroked-button
                  type="button"
                  class="option"
                  [disabled]="busy()"
                  (click)="registerPasskey()"
                >
                  <app-icon name="key" [size]="24" />
                  <span
                    ><strong>Passkey or security key</strong><br /><span class="muted"
                      >Phishing-resistant, recommended</span
                    ></span
                  >
                </button>
              </div>
            }
          </div>
        }
        @if (error()) {
          <p class="error" role="alert">{{ error() }}</p>
        }
      </section>
    </main>
  `,
  styles: `
    .qr {
      display: grid;
      place-items: center;
      padding: 8px;
    }
    .secret code {
      display: block;
      margin-top: 4px;
      font-family: ui-monospace, monospace;
      max-width: 20ch; /* two rows of four groups */
      font-size: 15px;
      color: var(--mat-sys-on-surface);
    }
    .codes {
      columns: 2;
      font-family: ui-monospace, monospace;
      padding-left: 1.5em;
    }
    .options {
      gap: 16px;
    }
    .option {
      height: auto;
      padding: 12px 16px;
      justify-content: flex-start;
      text-align: left;
      width: 100%;
      gap: 12px;
    }
    .passkey {
      display: grid;
      gap: 4px;
    }
  `,
})
export class EnrollMfa {
  private readonly api = inject(Api);
  private readonly auth = this.api.client(AuthService);
  private readonly session = inject(Session);
  private readonly router = inject(Router);
  /** Router-bound query parameter (undefined when absent). */
  readonly next = input<string | undefined>();

  readonly busy = signal(false);
  readonly error = signal('');
  readonly secret = signal('');
  readonly uri = signal('');
  readonly codes = signal<string[]>([]);
  readonly groupedSecret = computed(() =>
    this.secret()
      .replace(/(.{4})/g, '$1 ')
      .trim(),
  );
  readonly passkeys = passkeysSupported();
  private enrollmentId = '';
  code = '';
  passkeyName = 'Passkey';

  private async run(fn: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    try {
      await fn();
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  startTotp(): Promise<void> {
    return this.run(async () => {
      const res = await this.auth.beginTotpEnrollment({});
      this.enrollmentId = res.enrollmentId;
      this.secret.set(res.secret);
      this.uri.set(res.otpauthUri);
    });
  }

  confirmTotp(): Promise<void> {
    return this.run(async () => {
      const res = await this.auth.confirmTotpEnrollment({
        enrollmentId: this.enrollmentId,
        code: this.code.trim(),
        name: 'Authenticator app',
      });
      this.code = '';
      this.secret.set('');
      await this.session.refresh();
      if (res.recoveryCodes.length) this.codes.set(res.recoveryCodes);
      else await this.finish();
    });
  }

  registerPasskey(): Promise<void> {
    return this.run(async () => {
      const begin = await this.auth.beginPasskeyRegistration({});
      const res = await this.auth.finishPasskeyRegistration({
        name: this.passkeyName.trim() || 'Passkey',
        credentialJson: await createCredential(begin.optionsJson),
      });
      await this.session.refresh();
      if (res.recoveryCodes.length) this.codes.set(res.recoveryCodes);
      else await this.finish();
    });
  }

  async copyCodes(): Promise<void> {
    await navigator.clipboard.writeText(this.codes().join('\n'));
  }

  async finish(): Promise<void> {
    this.codes.set([]);
    await this.router.navigateByUrl(safeRedirect(this.next()));
  }
}
