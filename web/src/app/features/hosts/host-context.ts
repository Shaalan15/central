// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import { Injectable, signal } from '@angular/core';

import type { Agent } from '../../../gen/central/api/v1/fleet_pb';

/** Shared state of the host page and its tabs. */
@Injectable()
export class HostContext {
  readonly id = signal('');
  readonly agent = signal<Agent | null>(null);
}
