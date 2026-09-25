// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
  untracked,
} from '@angular/core';
import { MatButtonToggle, MatButtonToggleGroup } from '@angular/material/button-toggle';
import { RouterLink } from '@angular/router';
import { timestampFromDate } from '@bufbuild/protobuf/wkt';

import type { MetricsSample } from '../../../gen/central/agent/v1/telemetry_pb';
import { MetricsResolution, MetricsService } from '../../../gen/central/api/v1/metrics_pb';
import { Api } from '../../core/api';
import { bytes, dateTime, rate, toDate } from '../../core/format';
import { Chart, type ChartSeries } from '../../shared/chart';
import { Icon } from '../../shared/icon';
import { Meter } from '../../shared/meter';
import { PROFILE_LABELS } from '../fleet/dashboard';
import { HostContext } from './host-context';

type Range = '1h' | '6h' | '24h' | '7d';
const RANGES: Record<Range, number> = {
  '1h': 3600e3,
  '6h': 6 * 3600e3,
  '24h': 24 * 3600e3,
  '7d': 7 * 24 * 3600e3,
};

interface Series {
  t: number[];
  cpu: number[];
  mem: number[];
  swap: number[];
  load: number[];
  rx: number[];
  tx: number[];
  read: number[];
  write: number[];
}

function empty(): Series {
  return { t: [], cpu: [], mem: [], swap: [], load: [], rx: [], tx: [], read: [], write: [] };
}

function pct(used: bigint, total: bigint): number {
  return total > 0n ? (Number(used) / Number(total)) * 100 : 0;
}

@Component({
  selector: 'app-host-overview',
  imports: [MatButtonToggleGroup, MatButtonToggle, RouterLink, Chart, Icon, Meter],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './overview.html',
  styleUrl: './overview.scss',
})
export class Overview {
  readonly ctx = inject(HostContext);
  private readonly metrics = inject(Api).client(MetricsService);
  private readonly destroyRef = inject(DestroyRef);

  readonly range = signal<Range>('1h');
  readonly ranges = Object.keys(RANGES) as Range[];
  readonly data = signal<Series>(empty());
  /** Visible time range in Unix ms, shared by every chart. */
  readonly window = signal<readonly [number, number] | null>(null);
  readonly latest = signal<MetricsSample | null>(null);
  readonly profiles = PROFILE_LABELS;
  private live: AbortController | null = null;
  private refresh: ReturnType<typeof setTimeout> | undefined;
  private generation = 0;

  readonly fmt = {
    percent: (v: number) => `${v.toFixed(0)}%`,
    rate: (v: number) => rate(v),
    load: (v: number) => v.toFixed(1),
  };

  readonly cpuSeries = computed<ChartSeries[]>(() => [
    { label: 'CPU', color: 'var(--mat-sys-primary)', values: this.data().cpu, fill: true },
  ]);
  readonly memSeries = computed<ChartSeries[]>(() => [
    { label: 'Memory', color: 'var(--mat-sys-tertiary)', values: this.data().mem, fill: true },
    { label: 'Swap', color: 'var(--app-warn)', values: this.data().swap },
  ]);
  readonly netSeries = computed<ChartSeries[]>(() => [
    { label: 'Received', color: 'var(--mat-sys-primary)', values: this.data().rx, fill: true },
    { label: 'Sent', color: 'var(--mat-sys-tertiary)', values: this.data().tx },
  ]);
  readonly diskSeries = computed<ChartSeries[]>(() => [
    { label: 'Read', color: 'var(--mat-sys-primary)', values: this.data().read, fill: true },
    { label: 'Write', color: 'var(--mat-sys-tertiary)', values: this.data().write },
  ]);
  readonly loadSeries = computed<ChartSeries[]>(() => [
    {
      label: 'Load (1 min)',
      color: 'var(--mat-sys-secondary)',
      values: this.data().load,
      fill: true,
    },
  ]);

  readonly sample = computed(() => this.latest() ?? this.ctx.agent()?.latestMetrics ?? null);
  readonly facts = computed(() => this.ctx.agent()?.facts);
  readonly policy = computed(() => this.ctx.agent()?.policy);

  readonly bytes = bytes;
  readonly dateTime = dateTime;

  constructor() {
    effect(() => {
      const id = this.ctx.id();
      const r = this.range();
      if (id) untracked(() => void this.load(id, r));
    });
    this.destroyRef.onDestroy(() => {
      this.live?.abort();
      clearTimeout(this.refresh);
    });
  }

  private async load(id: string, r: Range): Promise<void> {
    const gen = ++this.generation;
    this.live?.abort();
    this.live = null;
    clearTimeout(this.refresh);
    const end = new Date();
    const start = new Date(end.getTime() - RANGES[r]);
    let next = empty();
    try {
      const s = (
        await this.metrics.getAgentMetrics({
          agentId: id,
          start: timestampFromDate(start),
          end: timestampFromDate(end),
          resolution: r === '1h' ? MetricsResolution.RAW : MetricsResolution.UNSPECIFIED,
        })
      ).series;
      if (s) {
        next = {
          t: s.timestampsMs.map(Number),
          cpu: s.cpuPercent,
          mem: s.memoryUsedPercent,
          swap: s.swapUsedPercent,
          load: s.load1,
          rx: s.netRxBytesPerSecond,
          tx: s.netTxBytesPerSecond,
          read: s.diskReadBytesPerSecond,
          write: s.diskWriteBytesPerSecond,
        };
      }
    } catch {
      /* keep the charts empty; the next refresh retries */
    }
    if (gen !== this.generation) return; // superseded by a newer range or host
    this.window.set([start.getTime(), end.getTime()]);
    this.data.set(next);
    if (r === '1h') void this.follow(id);
    else this.refresh = setTimeout(() => void this.load(id, r), 60_000);
  }

  /** Appends live samples while the 1-hour range is shown. */
  private async follow(id: string): Promise<void> {
    const ctrl = new AbortController();
    this.live = ctrl;
    try {
      for await (const res of this.metrics.watchAgentMetrics(
        { agentId: id },
        { signal: ctrl.signal },
      )) {
        const s = res.sample;
        if (!s?.time) continue;
        this.latest.set(s);
        const t = toDate(s.time)!.getTime();
        this.window.set([Math.max(t, Date.now()) - RANGES['1h'], Math.max(t, Date.now())]);
        this.data.update((d) => {
          if (d.t.length && t <= (d.t.at(-1) ?? 0)) return d;
          const cut = t - RANGES['1h'];
          const keep = d.t.findIndex((x) => x >= cut);
          const from = keep < 0 ? d.t.length : keep;
          const push = (arr: number[], v: number) => [...arr.slice(from), v];
          return {
            t: push(d.t, t),
            cpu: push(d.cpu, s.cpuPercent),
            mem: push(d.mem, pct(s.memoryUsedBytes, s.memoryTotalBytes)),
            swap: push(d.swap, pct(s.swapUsedBytes, s.swapTotalBytes)),
            load: push(d.load, s.load1),
            rx: push(
              d.rx,
              s.network.reduce((a, n) => a + n.rxBytesPerSecond, 0),
            ),
            tx: push(
              d.tx,
              s.network.reduce((a, n) => a + n.txBytesPerSecond, 0),
            ),
            read: push(
              d.read,
              s.disks.reduce((a, n) => a + n.readBytesPerSecond, 0),
            ),
            write: push(
              d.write,
              s.disks.reduce((a, n) => a + n.writeBytesPerSecond, 0),
            ),
          };
        });
      }
    } catch {
      /* stream ended (navigation, network): the next load restarts it */
    }
  }

  fsPercent(used: bigint, total: bigint): number {
    return pct(used, total);
  }
}
