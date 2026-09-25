// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"io"
	"log/slog"
	"math"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T, h *store.Holder, c *clock) *Store {
	t.Helper()
	s := NewStore(h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = c.now
	return s
}

func holder(t *testing.T) *store.Holder {
	t.Helper()
	st := store.Open(memory.New())
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(st)
	return h
}

func sample(at time.Time, cpu float32) *agentv1.MetricsSample {
	return &agentv1.MetricsSample{
		Time: timestamppb.New(at), CpuPercent: cpu, MemoryTotalBytes: 1000, MemoryUsedBytes: 250,
		Filesystems: []*agentv1.FilesystemUsage{{TotalBytes: 100, UsedBytes: 40}, {TotalBytes: 100, UsedBytes: 91}},
		Network:     []*agentv1.NetIO{{RxBytesPerSecond: 10, TxBytesPerSecond: 5}, {RxBytesPerSecond: 1}},
	}
}

func TestFromSampleSanitizes(t *testing.T) {
	p := FromSample(&agentv1.MetricsSample{
		CpuPercent: float32(math.NaN()), Load1: -3, MemoryTotalBytes: 10, MemoryUsedBytes: 50,
		Disks: []*agentv1.DiskIO{{ReadBytesPerSecond: math.Inf(1), WriteBytesPerSecond: -1}},
	})
	if p.CPU != 0 || p.Load1 != 0 || p.Mem != 100 || p.DiskRead != 0 || p.DiskWrite != 0 {
		t.Fatalf("unsanitized point: %+v", p)
	}
	q := FromSample(sample(time.Now(), 150))
	if q.CPU != 100 || q.DiskMax != 91 || q.NetRx != 11 || q.Mem != 25 {
		t.Fatalf("point: %+v", q)
	}
}

func TestIngestRollupAndPersistence(t *testing.T) {
	ctx := context.Background()
	h := holder(t)
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	c := &clock{t: t0}
	s := newStore(t, h, c)

	// 2.5 hours of samples every 15s: CPU alternates 20/40, so minute averages are 30.
	for i := range 600 {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		c.t = at
		cpu := float32(20)
		if i%2 == 1 {
			cpu = 40
		}
		if got := s.Ingest("org", "a1", []*agentv1.MetricsSample{sample(at, cpu)}); len(got) != 1 {
			t.Fatalf("sample %d rejected", i)
		}
	}
	// Duplicate, out-of-order, future and ancient samples are dropped.
	for _, at := range []time.Time{c.t, c.t.Add(-time.Minute), c.t.Add(time.Hour), c.t.Add(-3 * time.Hour)} {
		if got := s.Ingest("org", "a1", []*agentv1.MetricsSample{sample(at, 1)}); len(got) != 0 {
			t.Fatalf("accepted sample at %s", at)
		}
	}
	if p, ok := s.Latest("a1"); !ok || p.T != c.t.UnixMilli() {
		t.Fatal("latest point")
	}

	res, raw, err := s.Series(ctx, "org", "a1", c.t.Add(-30*time.Minute), c.t, Auto)
	if err != nil || res != Raw || len(raw) != 121 {
		t.Fatalf("raw series: res=%v len=%d err=%v", res, len(raw), err)
	}
	if err := s.Flush(ctx, true); err != nil {
		t.Fatal(err)
	}

	// A fresh process sees the persisted rollups.
	s2 := newStore(t, h, c)
	res, mins, err := s2.Series(ctx, "org", "a1", t0, t0.Add(2*time.Hour-time.Second), Minute)
	if err != nil || res != Minute {
		t.Fatal(err)
	}
	if len(mins) != 120 {
		t.Fatalf("minute points: %d", len(mins))
	}
	for _, p := range mins {
		if p.CPU != 30 || p.CPUMax != 40 || p.N != 4 || p.DiskMax != 91 {
			t.Fatalf("minute rollup: %+v", p)
		}
	}
	_, hours, err := s2.Series(ctx, "org", "a1", t0, c.t, Hour)
	if err != nil || len(hours) < 2 || hours[0].N != 240 || hours[0].CPU != 30 {
		t.Fatalf("hour rollups: %+v %v", hours, err)
	}
	// Another organization cannot read the series.
	if _, other, _ := s2.Series(ctx, "other", "a1", t0, c.t, Minute); len(other) != 0 {
		t.Fatal("series visible to another organization")
	}

	// A restart in the middle of an hour merges with the stored partial chunk.
	s3 := newStore(t, h, c)
	next := c.t.Add(15 * time.Second)
	for i := range 40 {
		at := next.Add(time.Duration(i) * 15 * time.Second)
		c.t = at
		s3.Ingest("org", "a1", []*agentv1.MetricsSample{sample(at, 50)})
	}
	if err := s3.Flush(ctx, true); err != nil {
		t.Fatal(err)
	}
	_, merged, _ := newStore(t, h, c).Series(ctx, "org", "a1", t0.Add(2*time.Hour), c.t, Minute)
	if len(merged) < 35 {
		t.Fatalf("merged partial hour has %d points", len(merged))
	}

	// Retention removes old chunks.
	c.t = c.t.Add(40 * 24 * time.Hour)
	if err := s3.Prune(ctx, "org", 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.Get().MetricsChunks.Count(ctx, store.Tenant("org"), store.Query{}); n != 0 {
		t.Fatalf("%d chunks survived retention", n)
	}
}

func TestEncodeDecode(t *testing.T) {
	in := []Point{{T: 1, CPU: 1.5, CPUMax: 2, Mem: 3, Swap: 4, Load1: 5, DiskMax: 6, DiskRead: 7, DiskWrite: 8, NetRx: 9, NetTx: 10, N: 11}}
	data, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil || len(out) != 1 || out[0] != in[0] {
		t.Fatalf("roundtrip: %+v %v", out, err)
	}
	for _, bad := range [][]byte{nil, []byte("not gzip"), data[:len(data)/2]} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("decoded %q", bad)
		}
	}
}
