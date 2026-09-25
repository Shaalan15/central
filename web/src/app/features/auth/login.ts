// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButton } from '@angular/material/button';
import { MatFormField, MatInput, MatLabel } from '@angular/material/input';
import { MatProgressBar } from '@angular/material/progress-bar';
import { Router } from '@angular/router';

import { AuthService, MfaMethodType, SessionStage } from '../../../gen/central/api/v1/auth_pb';
import { Api, errorMessage } from '../../core/api';
import { safeRedirect } from '../../core/redirect';
import { Session } from '../../core/session';
import { getAssertion, passkeysSupported } from '../../core/webauthn';
import { Icon } from '../../shared/icon';

@Component({
  selector: 'app-login',
  imports: [FormsModule, MatButton, MatFormField, MatInput, MatLabel, MatProgressBar, Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="auth-page">
      <section class="auth-card" aria-labelledby="login-title">
        <header class="brand">
          <app-icon name="hub" [size]="28" />
          <div>
            <h1 id="login-title">Central</h1>
            <p class="muted">
              {{ stage() === 'password' ? 'Sign in to your fleet' : 'Two-factor authentication' }}
            </p>
          </div>
        </header>
        @if (busy()) {
          <mat-progress-bar mode="indeterminate" />
        }
        @if (stage() === 'password') {
          <form (ngSubmit)="login()" class="form">
            <mat-form-field appearance="outline">
              <mat-label>Email</mat-label>
              <input
                matInput
                name="email"
                type="email"
                [(ngModel)]="emailValue"
                required
                autocomplete="username webauthn"
              />
            </mat-form-field>
            <mat-form-field appearance="outline">
              <mat-label>Password</mat-label>
              <input
                matInput
                name="password"
                type="password"
                [(ngModel)]="password"
                required
                autocomplete="current-password"
              />
            </mat-form-field>
            <div class="actions stretch">
              <button mat-flat-button [disabled]="busy() || !emailValue || !password">
                Sign in
              </button>
            </div>
            @if (passkeys) {
              <div class="divider"><span>or</span></div>
              <div class="actions stretch">
                <button
                  mat-stroked-button
                  type="button"
                  [disabled]="busy()"
                  (click)="passkeyLogin()"
                >
                  <app-icon name="key" /> Sign in with a passkey
                </button>
              </div>
            }
          </form>
        } @else {
          <form (ngSubmit)="verify()" class="form">
            @if (useRecovery()) {
              <p>
                Enter one of the recovery codes you saved when you set up two-factor authentication.
              </p>
              <mat-form-field appearance="outline">
                <mat-label>Recovery code</mat-label>
                <input
                  matInput
                  name="recovery"
                  [(ngModel)]="code"
                  required
                  autocomplete="off"
                  spellcheck="false"
                />
              </mat-form-field>
            } @else if (methods().includes(totp)) {
              <p>Enter the 6-digit code from your authenticator app.</p>
              <mat-form-field appearance="outline">
                <mat-label>Authentication code</mat-label>
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
            }
            <div class="actions stretch">
              @if (useRecovery() || methods().includes(totp)) {
                <button mat-flat-button [disabled]="busy() || !code">Verify</button>
              }
              @if (!useRecovery() && passkeys && methods().includes(passkey)) {
                <button
                  mat-stroked-button
                  type="button"
                  [disabled]="busy()"
                  (click)="passkeySecondFactor()"
                >
                  <app-icon name="key" /> Use a passkey
                </button>
              }
            </div>
            <button
              mat-button
              type="button"
              class="link"
              (click)="useRecovery.set(!useRecovery()); code = ''"
            >
              {{ useRecovery() ? 'Use your authenticator instead' : 'Use a recovery code' }}
            </button>
          </form>
        }
        @if (error()) {
          <p class="error" role="alert">{{ error() }}</p>
        }
      </section>
    </main>
  `,
})
export class Login implements OnInit {
  private readonly api = inject(Api);
  private readonly auth = this.api.client(AuthService);
  private readonly session = inject(Session);
  private readonly router = inject(Router);

  // Router-bound query parameters (undefined when absent).
  readonly email = input<string | undefined>();
  readonly next = input<string | undefined>();

  readonly stage = signal<'password' | 'mfa'>('password');
  readonly methods = signal<MfaMethodType[]>([]);
  readonly useRecovery = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly passkeys = passkeysSupported();
  readonly totp = MfaMethodType.TOTP;
  readonly passkey = MfaMethodType.PASSKEY;

  emailValue = '';
  password = '';
  code = '';

  ngOnInit(): void {
    this.emailValue = this.email() ?? '';
    if (this.session.stage() === SessionStage.MFA_ENROLLMENT) void this.router.navigate(['/mfa']);
  }

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

  login(): Promise<void> {
    return this.run(async () => {
      const res = await this.auth.login({ email: this.emailValue.trim(), password: this.password });
      this.password = '';
      await this.session.refresh();
      await this.after(res.stage, res.mfaMethods);
    });
  }

  verify(): Promise<void> {
    return this.run(async () => {
      const code = this.code.trim();
      this.code = '';
      const res = this.useRecovery()
        ? await this.auth.useRecoveryCode({ code })
        : await this.auth.verifyTotp({ code });
      await this.session.refresh();
      await this.after(res.stage, []);
    });
  }

  passkeyLogin(): Promise<void> {
    return this.run(async () => {
      const begin = await this.auth.beginPasskeyLogin({});
      const res = await this.auth.finishPasskeyLogin({
        credentialJson: await getAssertion(begin.optionsJson),
      });
      await this.session.refresh();
      await this.after(res.stage, []);
    });
  }

  passkeySecondFactor(): Promise<void> {
    return this.run(async () => {
      const begin = await this.auth.beginStepUp({});
      await this.auth.finishStepUp({
        proof: {
          case: 'passkeyCredentialJson',
          value: await getAssertion(begin.passkeyOptionsJson),
        },
      });
      await this.session.refresh();
      await this.after(this.session.stage(), []);
    });
  }

  private async after(stage: SessionStage, methods: MfaMethodType[]): Promise<void> {
    switch (stage) {
      case SessionStage.MFA_REQUIRED:
        this.methods.set(methods.length ? methods : [MfaMethodType.TOTP]);
        this.stage.set('mfa');
        return;
      case SessionStage.MFA_ENROLLMENT:
        await this.router.navigate(['/mfa'], { queryParams: { next: this.next() || undefined } });
        return;
      case SessionStage.FULL:
        await this.router.navigateByUrl(this.safeNext());
        return;
      default:
        this.error.set('Sign-in failed.');
    }
  }

  private safeNext(): string {
    return safeRedirect(this.next());
  }
}
