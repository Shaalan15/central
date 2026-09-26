// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  afterNextRender,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import uPlot from 'uplot';

import { Theme } from '../core/theme';

export interface ChartSeries {
  label: string;
  /** CSS color or var(--token); resolved by the browser (supports light-dark()). */
  color: string;
  values: (number | null)[];
  fill?: boolean;
}

/** Resolves any CSS color expression to rgb() using the browser's own cascade. */
function resolveColor(probe: HTMLElement, value: string): [number, number, number] {
  probe.style.color = value;
  const m = getComputedStyle(probe).color.match(/[\d.]+/g) ?? ['128', '128', '128'];
  return [Number(m[0]), Number(m[1]), Number(m[2])];
}

const rgba = (c: [number, number, number], a = 1) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

const DAY = 86400;

/** Axis label for a split (Unix seconds), given the split increment and the visible span. */
function timeLabel(sec: number, incr: number, span: number): string {
  const d = new Date(sec * 1000);
  const midnight = d.getHours() === 0 && d.getMinutes() === 0;
  if (incr >= DAY || (span > 1.5 * DAY && midnight)) {
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  return d.toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
    second: incr < 60 ? '2-digit' : undefined,
  });
}

let measureCtx: CanvasRenderingContext2D | null = null;

/** Width in CSS pixels of the widest label, for sizing the value axis to fit. */
function labelWidth(labels: string[] | null, font: string): number {
  measureCtx ??= document.createElement('canvas').getContext('2d');
  if (!measureCtx || !labels) return 0;
  measureCtx.font = font;
  return Math.max(0, ...labels.map((l) => measureCtx!.measureText(l).width));
}

/**
 * Time-series chart on canvas (uPlot). Timestamps are Unix milliseconds; `format` renders axis
 * and legend values. The legend shows values under the cursor (or the latest values).
 */
@Component({
  selector: 'app-chart',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="legend" aria-hidden="true">
      @for (s of series(); track s.label; let i = $index) {
        <span class="item">
          <span class="swatch" [style.background]="s.color"></span>
          {{ s.label }}
          <strong class="tabular-nums">{{ legendValue(i) }}</strong>
        </span>
      }
      <span class="when muted tabular-nums">{{ cursorTime() }}</span>
    </div>
    <div class="plot" #plot></div>
    <span class="probe" #probe></span>
  `,
  styles: `
    :host {
      display: block;
      width: 100%;
    }
    .legend {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 4px 14px;
      min-height: 20px;
      margin-bottom: 4px;
      font: var(--mat-sys-label-medium);
      color: var(--mat-sys-on-surface-variant);
    }
    .item {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .item strong {
      color: var(--mat-sys-on-surface);
      font-weight: 500;
    }
    .swatch {
      width: 10px;
      height: 3px;
      border-radius: 2px;
    }
    .when {
      margin-left: auto;
    }
    .plot {
      width: 100%;
    }
    .probe {
      position: absolute;
      visibility: hidden;
      pointer-events: none;
    }
  `,
})
export class Chart {
  readonly times = input<number[]>([]);
  readonly series = input<ChartSeries[]>([]);
  readonly max = input<number | null>(null);
  readonly height = input(150);
  readonly format = input<(v: number) => string>((v) => v.toFixed(0));
  /** Visible time range [start, end] in Unix ms; defaults to the extent of the data. */
  readonly window = input<readonly [number, number] | null>(null);

  private readonly plotEl = viewChild.required<ElementRef<HTMLElement>>('plot');
  private readonly probe = viewChild.required<ElementRef<HTMLElement>>('probe');
  private readonly theme = inject(Theme);
  private readonly destroyRef = inject(DestroyRef);
  private plot: uPlot | null = null;
  private key = '';

  /** Data index under the cursor (null: show the latest values). */
  private readonly cursor = signal<number | null>(null);
  private readonly schemeTick = signal(0);

  readonly cursorTime = computed(() => {
    const i = this.cursor();
    const t = this.times();
    const ms = i === null ? undefined : t[i];
    if (ms === undefined) return '';
    const w = this.window();
    const span = w ? w[1] - w[0] : (t.at(-1) ?? 0) - (t[0] ?? 0);
    const d = new Date(ms);
    return span > DAY * 1000
      ? d.toLocaleString(undefined, {
          month: 'short',
          day: 'numeric',
          hour: 'numeric',
          minute: '2-digit',
        })
      : d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' });
  });

  legendValue(seriesIndex: number): string {
    const s = this.series()[seriesIndex];
    if (!s || s.values.length === 0) return '—';
    const i = this.cursor() ?? s.values.length - 1;
    const v = s.values[Math.min(i, s.values.length - 1)];
    return v === null || v === undefined ? '—' : this.format()(v);
  }

  constructor() {
    afterNextRender(() => {
      const el = this.plotEl().nativeElement;
      const ro = new ResizeObserver(() => {
        if (this.plot) this.plot.setSize({ width: this.width(), height: this.height() });
        else this.render(true);
      });
      ro.observe(el);
      const media = matchMedia('(prefers-color-scheme: dark)');
      const onScheme = () => this.schemeTick.update((n) => n + 1);
      media.addEventListener('change', onScheme);
      this.destroyRef.onDestroy(() => {
        ro.disconnect();
        media.removeEventListener('change', onScheme);
        this.plot?.destroy();
        this.plot = null;
      });
      this.render(true);
    });
    // Data changes update in place; theme changes rebuild (colors are baked into the canvas).
    effect(() => {
      this.times();
      this.series();
      this.window();
      untracked(() => this.render(false));
    });
    effect(() => {
      this.theme.mode();
      this.schemeTick();
      untracked(() => requestAnimationFrame(() => this.render(true)));
    });
  }

  private width(): number {
    return Math.max(this.plotEl().nativeElement.clientWidth, 100);
  }

  private render(rebuild: boolean): void {
    const host = this.plotEl?.()?.nativeElement;
    if (!host || !host.isConnected || host.clientWidth === 0) return;
    const series = this.series();
    const times = this.times();
    const data: uPlot.AlignedData = [times.map((t) => t / 1000), ...series.map((s) => s.values)];
    const key = series.map((s) => s.label).join('|');
    if (this.plot && !rebuild && key === this.key) {
      this.plot.setData(data);
      return;
    }
    this.plot?.destroy();
    this.key = key;
    const probe = this.probe().nativeElement;
    const grid = rgba(resolveColor(probe, 'var(--mat-sys-outline-variant)'), 0.6);
    const text = rgba(resolveColor(probe, 'var(--mat-sys-on-surface-variant)'));
    const fmt = this.format();
    const max = this.max();
    const font = '11px "Inter Variable", system-ui, sans-serif';
    this.plot = new uPlot(
      {
        width: this.width(),
        height: this.height(),
        legend: { show: false },
        cursor: { drag: { x: false, y: false }, points: { size: 6 } },
        padding: [8, 28, 0, 0], // the last time label is centred on the right edge
        scales: {
          x: {
            time: true,
            range: (_u, dmin, dmax) => {
              const w = this.window();
              return w ? [w[0] / 1000, w[1] / 1000] : [dmin, dmax];
            },
          },
          y:
            max === null
              ? { range: (_u, _min, dmax) => [0, Math.max(dmax * 1.15, 1)] }
              : { range: [0, max] },
        },
        axes: [
          {
            stroke: text,
            font,
            grid: { stroke: grid, width: 1 },
            ticks: { show: false },
            size: 28,
            values: (u, splits, _axis, _space, incr) => {
              const x = u.scales['x'];
              const span = (x?.max ?? 0) - (x?.min ?? 0);
              return splits.map((s) => timeLabel(s, incr, span));
            },
          },
          {
            stroke: text,
            font,
            grid: { stroke: grid, width: 1 },
            ticks: { show: false },
            size: (_u, labels) => Math.ceil(labelWidth(labels, font)) + 12,
            values: (_u, vals) => vals.map((v) => fmt(v)),
          },
        ],
        series: [
          {},
          ...series.map((s) => {
            const c = resolveColor(probe, s.color);
            return {
              label: s.label,
              stroke: rgba(c),
              width: 1.5,
              fill: s.fill ? rgba(c, 0.14) : undefined,
              points: { show: false },
            };
          }),
        ],
        hooks: {
          setCursor: [(u) => this.cursor.set(u.cursor.idx ?? null)],
        },
      },
      data,
      host,
    );
  }
}
