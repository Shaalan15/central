// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButton } from '@angular/material/button';
import { MatCheckbox } from '@angular/material/checkbox';
import { MatFormField, MatHint, MatInput, MatLabel } from '@angular/material/input';
import { MatProgressBar } from '@angular/material/progress-bar';
import { MatRadioButton, MatRadioGroup } from '@angular/material/radio';
import { Router } from '@angular/router';

import {
  AppwriteDeployment,
  SetupService,
  SetupStep,
  type TestDatabaseResponse,
} from '../../../gen/central/api/v1/setup_pb';
import { Api, errorMessage } from '../../core/api';
import { Session } from '../../core/session';
import { Icon } from '../../shared/icon';

type Step = 'token' | 'database' | 'endpoints' | 'owner' | 'done';

const STEPS: { id: Step; label: string }[] = [
  { id: 'token', label: 'Verify' },
  { id: 'database', label: 'Database' },
  { id: 'endpoints', label: 'Addresses' },
  { id: 'owner', label: 'Owner' },
];

function stepOf(s: SetupStep): Step {
  switch (s) {
    case SetupStep.DATABASE:
      return 'database';
    case SetupStep.ENDPOINTS:
      return 'endpoints';
    case SetupStep.OWNER:
      return 'owner';
    case SetupStep.COMPLETE:
      return 'done';
    default:
      return 'token';
  }
}

@Component({
  selector: 'app-setup',
  imports: [
    FormsModule,
    MatButton,
    MatCheckbox,
    MatFormField,
    MatHint,
    MatInput,
    MatLabel,
    MatProgressBar,
    MatRadioGroup,
    MatRadioButton,
    Icon,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './setup.html',
  styleUrl: './setup.scss',
})
export class Setup {
  private readonly api = inject(Api);
  private readonly setup = this.api.client(SetupService);
  private readonly session = inject(Session);
  private readonly router = inject(Router);

  readonly steps = STEPS;
  readonly step = signal<Step>('token');
  readonly stepIndex = computed(() => STEPS.findIndex((s) => s.id === this.step()));
  readonly busy = signal(false);
  readonly error = signal('');
  readonly version = computed(() => this.session.setup()?.version ?? '');

  token = '';

  // Database
  deployment: 'cloud' | 'self' = 'cloud';
  region = 'fra';
  endpoint = '';
  projectId = '';
  apiKey = '';
  databaseId = 'central';
  createDatabase = true;
  caBundle = '';
  readonly test = signal<TestDatabaseResponse | null>(null);

  // Endpoints
  publicUrl = location.origin;
  agentUrl = `https://${location.hostname}:9443`;

  // Owner
  displayName = '';
  email = '';
  organization = '';
  password = '';
  confirm = '';

  readonly regions = [
    { id: 'fra', name: 'Frankfurt' },
    { id: 'nyc', name: 'New York' },
    { id: 'syd', name: 'Sydney' },
    { id: 'sfo', name: 'San Francisco' },
    { id: 'sgp', name: 'Singapore' },
    { id: 'tor', name: 'Toronto' },
  ];

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

  begin(): Promise<void> {
    return this.run(async () => {
      const res = await this.setup.beginSetup({ setupToken: this.token.trim() });
      this.step.set(stepOf(res.nextStep));
    });
  }

  private dbConfig() {
    const endpoint =
      this.deployment === 'cloud'
        ? `https://${this.region}.cloud.appwrite.io/v1`
        : this.endpoint.trim();
    return {
      driver: {
        case: 'appwrite' as const,
        value: {
          deployment:
            this.deployment === 'cloud' ? AppwriteDeployment.CLOUD : AppwriteDeployment.SELF_HOSTED,
          endpoint,
          projectId: this.projectId.trim(),
          apiKey: this.apiKey.trim(),
          databaseId: this.databaseId.trim(),
          createDatabase: this.createDatabase,
          caBundlePem: this.deployment === 'self' ? this.caBundle : '',
        },
      },
    };
  }

  testDatabase(): Promise<void> {
    return this.run(async () => {
      this.test.set(await this.setup.testDatabase({ config: this.dbConfig() }));
    });
  }

  saveDatabase(): Promise<void> {
    return this.run(async () => {
      const res = await this.setup.saveDatabase({ config: this.dbConfig() });
      this.apiKey = '';
      this.step.set(stepOf(res.nextStep));
    });
  }

  saveEndpoints(): Promise<void> {
    return this.run(async () => {
      const res = await this.setup.saveEndpoints({
        publicUrl: this.publicUrl.trim(),
        agentUrl: this.agentUrl.trim(),
      });
      this.step.set(stepOf(res.nextStep));
    });
  }

  createOwner(): Promise<void> {
    if (this.password !== this.confirm) {
      this.error.set('The passwords do not match.');
      return Promise.resolve();
    }
    return this.run(async () => {
      await this.setup.createOwner({
        email: this.email.trim(),
        displayName: this.displayName.trim(),
        organizationName: this.organization.trim(),
        password: this.password,
      });
      this.password = this.confirm = '';
      this.step.set('done');
      await this.session.refresh();
    });
  }

  signIn(): void {
    void this.router.navigate(['/login'], { queryParams: { email: this.email.trim() } });
  }
}
