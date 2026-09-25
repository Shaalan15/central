// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics keeps agent metrics: the last hour of raw samples in memory, plus one-minute
// and one-hour rollups persisted as compact chunks (one row per agent per hour of minute points,
// and one row per agent per day of hour points). At 1,000 agents this is ~24k rows per day
// instead of millions, and dashboards read recent data from memory without touching storage.
package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/store"
)

// Resolution of a series.
type Resolution int

// Resolutions.
const (
	Auto Resolution = iota
	Raw
	Minute
	Hour
)

// Retention and limits.
const (
	RawWindow         = time.Hour
	maxRawPoints      = 720 // one hour at the 5s minimum interval
	maxSampleAge      = 2 * time.Hour
	maxFutureSkew     = 5 * time.Minute
	partialFlushEvery = 5 * time.Minute
	// MinuteRetention bounds how long one-minute rollups are kept (hour rollups follow the
	// organization's metrics retention).
	MinuteRetention = 7 * 24 * time.Hour
	maxQuerySpan    = 400 * 24 * time.Hour
)

// Point is one measurement or rollup bucket. For rollups T is the bucket start, values are
// averages over the bucket and the *Max fields are maxima.
type Point struct {
	T         int64 // Unix milliseconds
	CPU       float32
	CPUMax    float32
	Mem       float32 // used %
	Swap      float32 // used %
	Load1     float32
	DiskMax   float32 // highest filesystem usage %
	DiskRead  float64 // bytes/s
	DiskWrite float64
	NetRx     float64
	NetTx     float64
	N         uint32 // raw samples aggregated (1 for raw points)
}

func finite32(v float32, lo, hi float32) float32 {
	if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) || v < lo {
		return lo
	}
	return min(v, hi)
}

func finite64(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return min(v, 1e15)
}

func pct(used, total uint64) float32 {
	if total == 0 {
		return 0
	}
	return finite32(float32(float64(used)/float64(total)*100), 0, 100)
}

// FromSample converts an agent sample into a point, sanitizing hostile or broken values.
func FromSample(s *agentv1.MetricsSample) Point {
	p := Point{
		T:     s.GetTime().AsTime().UnixMilli(),
		CPU:   finite32(s.GetCpuPercent(), 0, 100),
		Mem:   pct(s.GetMemoryUsedBytes(), s.GetMemoryTotalBytes()),
		Swap:  pct(s.GetSwapUsedBytes(), s.GetSwapTotalBytes()),
		Load1: finite32(s.GetLoad1(), 0, 1e6),
		N:     1,
	}
	p.CPUMax = p.CPU
	for _, fs := range s.GetFilesystems() {
		p.DiskMax = max(p.DiskMax, pct(fs.GetUsedBytes(), fs.GetTotalBytes()))
	}
	for _, d := range s.GetDisks() {
		p.DiskRead += finite64(d.GetReadBytesPerSecond())
		p.DiskWrite += finite64(d.GetWriteBytesPerSecond())
	}
	for _, n := range s.GetNetwork() {
		p.NetRx += finite64(n.GetRxBytesPerSecond())
		p.NetTx += finite64(n.GetTxBytesPerSecond())
	}
	return p
}

// acc accumulates points into one bucket (weighted by N).
type acc struct {
	start                             int64
	n                                 uint32
	cpu, mem, swap, load              float64
	cpuMax, diskMaxMax                float32
	diskRead, diskWrite, netRx, netTx float64
}

func (a *acc) add(p Point) {
	w := float64(max(p.N, 1))
	a.n += max(p.N, 1)
	a.cpu += float64(p.CPU) * w
	a.mem += float64(p.Mem) * w
	a.swap += float64(p.Swap) * w
	a.load += float64(p.Load1) * w
	a.diskRead += p.DiskRead * w
	a.diskWrite += p.DiskWrite * w
	a.netRx += p.NetRx * w
	a.netTx += p.NetTx * w
	a.cpuMax = max(a.cpuMax, p.CPUMax, p.CPU)
	a.diskMaxMax = max(a.diskMaxMax, p.DiskMax)
}

func (a *acc) point() Point {
	n := float64(a.n)
	return Point{
		T: a.start, N: a.n,
		CPU: float32(a.cpu / n), CPUMax: a.cpuMax, Mem: float32(a.mem / n), Swap: float32(a.swap / n),
		Load1: float32(a.load / n), DiskMax: a.diskMaxMax,
		DiskRead: a.diskRead / n, DiskWrite: a.diskWrite / n, NetRx: a.netRx / n, NetTx: a.netTx / n,
	}
}

// chunk is a persisted window of rollup points.
type chunk struct {
	resolution string
	start      time.Time
	points     []Point
	merged     bool // existing stored points were merged in
	dirty      bool
	version    uint64 // incremented on every change
	flushedAt  time.Time
}

type series struct {
	orgID string
	raw   []Point
	head  int // next write position once raw is full
	last  int64

	minute  acc
	hourAcc acc
	hour    *chunk
	day     *chunk
	pending []*chunk // finished chunks waiting to be persisted
}

// Store holds per-agent series.
type Store struct {
	holder *store.Holder
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	agents map[string]*series
}

// NewStore returns a metrics store.
func NewStore(holder *store.Holder, log *slog.Logger) *Store {
	return &Store{holder: holder, log: log, now: time.Now, agents: map[string]*series{}}
}

func minuteOf(ms int64) int64 { return ms - ms%60_000 }

func hourOf(ms int64) time.Time { return time.UnixMilli(ms).UTC().Truncate(time.Hour) }

func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Ingest adds samples for an agent and returns the samples accepted (oldest first). Samples out
// of order, far in the future or older than two hours are dropped.
func (s *Store) Ingest(orgID, agentID string, samples []*agentv1.MetricsSample) []*agentv1.MetricsSample {
	now := s.now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.agents[agentID]
	if sr == nil {
		sr = &series{orgID: orgID}
		s.agents[agentID] = sr
	}
	var out []*agentv1.MetricsSample
	for _, sample := range samples {
		p := FromSample(sample)
		if p.T <= sr.last || p.T > now+maxFutureSkew.Milliseconds() || p.T < now-maxSampleAge.Milliseconds() {
			continue
		}
		sr.last = p.T
		sr.addRaw(p)
		sr.addToMinute(p)
		out = append(out, sample)
	}
	return out
}

func (sr *series) addRaw(p Point) {
	if len(sr.raw) < maxRawPoints {
		sr.raw = append(sr.raw, p)
		return
	}
	sr.raw[sr.head] = p
	sr.head = (sr.head + 1) % maxRawPoints
}

func (sr *series) rawPoints() []Point {
	if len(sr.raw) < maxRawPoints {
		return append([]Point(nil), sr.raw...)
	}
	out := make([]Point, 0, maxRawPoints)
	out = append(out, sr.raw[sr.head:]...)
	return append(out, sr.raw[:sr.head]...)
}

func (sr *series) addToMinute(p Point) {
	m := minuteOf(p.T)
	if sr.minute.n > 0 && sr.minute.start != m {
		sr.addMinutePoint(sr.minute.point())
		sr.minute = acc{}
	}
	if sr.minute.n == 0 {
		sr.minute.start = m
	}
	sr.minute.add(p)
}

func (sr *series) addMinutePoint(mp Point) {
	h := hourOf(mp.T)
	if sr.hour != nil && !sr.hour.start.Equal(h) {
		sr.hour.dirty = true
		sr.pending = append(sr.pending, sr.hour)
		if sr.hourAcc.n > 0 {
			sr.addHourPoint(sr.hourAcc.point())
		}
		sr.hour, sr.hourAcc = nil, acc{}
	}
	if sr.hour == nil {
		sr.hour = &chunk{resolution: store.ResolutionMinute, start: h}
		sr.hourAcc = acc{start: h.UnixMilli()}
	}
	sr.hour.points = append(sr.hour.points, mp)
	sr.hour.dirty = true
	sr.hour.version++
	sr.hourAcc.add(mp)
}

func (sr *series) addHourPoint(hp Point) {
	d := dayOf(time.UnixMilli(hp.T))
	if sr.day != nil && !sr.day.start.Equal(d) {
		sr.day.dirty = true
		sr.pending = append(sr.pending, sr.day)
		sr.day = nil
	}
	if sr.day == nil {
		sr.day = &chunk{resolution: store.ResolutionHour, start: d}
	}
	sr.day.points = append(sr.day.points, hp)
	sr.day.dirty = true
	sr.day.version++
}

// Latest returns the most recent raw point of an agent.
func (s *Store) Latest(agentID string) (Point, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.agents[agentID]
	if sr == nil || len(sr.raw) == 0 {
		return Point{}, false
	}
	i := len(sr.raw) - 1
	if len(sr.raw) == maxRawPoints {
		i = (sr.head - 1 + maxRawPoints) % maxRawPoints
	}
	return sr.raw[i], true
}

// Forget drops an agent's in-memory series (persisted chunks stay until retention removes them).
func (s *Store) Forget(agentID string) {
	s.mu.Lock()
	delete(s.agents, agentID)
	s.mu.Unlock()
}

type flushItem struct {
	orgID, agentID string
	c              *chunk
	points         []Point
	version        uint64
}

// Flush persists finished chunks and, every few minutes, the current partial ones. Call it
// periodically and at shutdown (force=true persists every partial chunk).
func (s *Store) Flush(ctx context.Context, force bool) error {
	st := s.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	now := s.now()
	var items []flushItem
	s.mu.Lock()
	for id, sr := range s.agents {
		for _, c := range sr.pending {
			items = append(items, flushItem{sr.orgID, id, c, append([]Point(nil), c.points...), c.version})
		}
		sr.pending = nil
		for _, c := range []*chunk{sr.hour, sr.day} {
			if c != nil && c.dirty && (force || now.Sub(c.flushedAt) >= partialFlushEvery) {
				items = append(items, flushItem{sr.orgID, id, c, append([]Point(nil), c.points...), c.version})
			}
		}
	}
	s.mu.Unlock()

	var errs []error
	for _, it := range items {
		if err := s.persist(ctx, st, it); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func chunkID(agentID, resolution string, start time.Time) string {
	return store.DeriveID(agentID, resolution, strconv.FormatInt(start.UnixMilli(), 10))
}

func (s *Store) persist(ctx context.Context, st *store.Store, it flushItem) error {
	scope := store.Tenant(it.orgID)
	id := chunkID(it.agentID, it.c.resolution, it.c.start)
	s.mu.Lock()
	merged := it.c.merged
	s.mu.Unlock()
	var old []Point
	if !merged {
		// First write of this window by this process: keep points written before a restart.
		existing, err := st.MetricsChunks.Get(ctx, scope, id)
		switch {
		case err == nil:
			old, _ = Decode(existing.Points)
		case !errors.Is(err, store.ErrNotFound):
			s.requeue(it)
			return err
		}
	}
	data, err := Encode(mergePoints(old, it.points))
	if err != nil {
		return err
	}
	err = st.MetricsChunks.Upsert(ctx, scope, &store.MetricsChunk{
		ID: id, OrgID: it.orgID, AgentID: it.agentID, Resolution: it.c.resolution,
		BucketStart: it.c.start, Points: data, UpdatedAt: s.now().UTC(),
	})
	if err != nil {
		s.requeue(it)
		return err
	}
	s.mu.Lock()
	if !it.c.merged {
		if len(old) > 0 {
			it.c.points = mergePoints(old, it.c.points)
		}
		it.c.merged = true
	}
	it.c.flushedAt = s.now()
	if it.c.version == it.version {
		it.c.dirty = false
	}
	s.mu.Unlock()
	return nil
}

// requeue schedules a failed chunk for the next flush.
func (s *Store) requeue(it flushItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it.c.dirty = true
	if sr := s.agents[it.agentID]; sr != nil && sr.hour != it.c && sr.day != it.c {
		sr.pending = append(sr.pending, it.c)
	}
}

// mergePoints unions two point lists by timestamp (b wins on conflicts), sorted by time.
func mergePoints(a, b []Point) []Point {
	m := make(map[int64]Point, len(a)+len(b))
	for _, p := range a {
		m[p.T] = p
	}
	for _, p := range b {
		m[p.T] = p
	}
	out := make([]Point, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

// Series returns points for [start, end] at the requested resolution (Auto picks one from the
// span) and the resolution used.
func (s *Store) Series(ctx context.Context, orgID, agentID string, start, end time.Time, res Resolution) (Resolution, []Point, error) {
	now := s.now()
	if end.IsZero() || end.After(now) {
		end = now
	}
	if start.IsZero() {
		start = end.Add(-time.Hour)
	}
	if !start.Before(end) {
		return res, nil, errors.New("metrics: start must be before end")
	}
	if end.Sub(start) > maxQuerySpan {
		return res, nil, errors.New("metrics: range too large")
	}
	if res == Auto {
		switch span := end.Sub(start); {
		case span <= RawWindow && now.Sub(start) <= RawWindow+time.Minute:
			res = Raw
		case span <= 12*time.Hour && now.Sub(start) <= MinuteRetention:
			res = Minute
		default:
			res = Hour
		}
	}
	lo, hi := start.UnixMilli(), end.UnixMilli()
	var mem []Point
	s.mu.Lock()
	sr := s.agents[agentID]
	if sr != nil && sr.orgID == orgID {
		switch res {
		case Raw:
			mem = sr.rawPoints()
		case Minute:
			if sr.hour != nil {
				mem = append(mem, sr.hour.points...)
			}
			if sr.minute.n > 0 {
				mem = append(mem, sr.minute.point())
			}
		case Hour:
			if sr.day != nil {
				mem = append(mem, sr.day.points...)
			}
			if sr.hourAcc.n > 0 || sr.minute.n > 0 {
				h := sr.hourAcc
				if sr.minute.n > 0 {
					h.add(sr.minute.point())
				}
				mem = append(mem, h.point())
			}
		case Auto:
		}
		for _, c := range sr.pending {
			if (res == Minute && c.resolution == store.ResolutionMinute) || (res == Hour && c.resolution == store.ResolutionHour) {
				mem = append(mem, c.points...)
			}
		}
	}
	s.mu.Unlock()

	var points []Point
	if res != Raw {
		stored, err := s.loadChunks(ctx, orgID, agentID, res, start, end)
		if err != nil {
			return res, nil, err
		}
		points = mergePoints(stored, mem)
	} else {
		points = mem
	}
	out := points[:0:0]
	for _, p := range points {
		if p.T >= lo-bucketMillis(res)+1 && p.T <= hi {
			out = append(out, p)
		}
	}
	return res, out, nil
}

func bucketMillis(res Resolution) int64 {
	switch res {
	case Minute:
		return 60_000
	case Hour:
		return 3_600_000
	default:
		return 1
	}
}

func (s *Store) loadChunks(ctx context.Context, orgID, agentID string, res Resolution, start, end time.Time) ([]Point, error) {
	st := s.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	resolution, from := store.ResolutionMinute, hourOf(start.UnixMilli())
	if res == Hour {
		resolution, from = store.ResolutionHour, dayOf(start)
	}
	q := store.Eq("agent_id", agentID).
		And("resolution", store.OpEq, resolution).
		And("bucket_start", store.OpGte, store.Millis(from)).
		And("bucket_start", store.OpLte, store.Millis(end)).
		Order("bucket_start", false)
	q.Limit = store.MaxLimit
	chunks, _, err := st.MetricsChunks.Find(ctx, store.Tenant(orgID), q)
	if err != nil {
		return nil, err
	}
	var out []Point
	for _, c := range chunks {
		pts, err := Decode(c.Points)
		if err != nil {
			s.log.Warn("metrics: skipping undecodable chunk", "chunk", c.ID, "error", err)
			continue
		}
		out = append(out, pts...)
	}
	return out, nil
}

// Prune deletes an organization's persisted chunks older than the retention windows.
func (s *Store) Prune(ctx context.Context, orgID string, hourRetention time.Duration) error {
	st := s.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	now := s.now()
	scope := store.Tenant(orgID)
	minuteCut := store.Millis(now.Add(-min(MinuteRetention, hourRetention)))
	if _, err := st.MetricsChunks.DeleteWhere(ctx, scope, store.Eq("resolution", store.ResolutionMinute).
		And("bucket_start", store.OpLt, minuteCut)); err != nil {
		return err
	}
	_, err := st.MetricsChunks.DeleteWhere(ctx, scope, store.Eq("resolution", store.ResolutionHour).
		And("bucket_start", store.OpLt, store.Millis(now.Add(-hourRetention))))
	return err
}

// Chunk encoding: gzip(version byte || points), each point little-endian fixed width.
const (
	encodingVersion = 1
	pointSize       = 8 + 6*4 + 4*8 + 4
	maxDecoded      = 1 << 20
)

// Encode packs points for storage.
func Encode(points []Point) ([]byte, error) {
	raw := make([]byte, 1, 1+len(points)*pointSize)
	raw[0] = encodingVersion
	for _, p := range points {
		raw = binary.LittleEndian.AppendUint64(raw, uint64(p.T)) //nolint:gosec // timestamps are positive
		for _, f := range []float32{p.CPU, p.CPUMax, p.Mem, p.Swap, p.Load1, p.DiskMax} {
			raw = binary.LittleEndian.AppendUint32(raw, math.Float32bits(f))
		}
		for _, f := range []float64{p.DiskRead, p.DiskWrite, p.NetRx, p.NetTx} {
			raw = binary.LittleEndian.AppendUint64(raw, math.Float64bits(f))
		}
		raw = binary.LittleEndian.AppendUint32(raw, p.N)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode unpacks stored points.
func Decode(data []byte) ([]Point, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxDecoded+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDecoded || len(raw) == 0 || raw[0] != encodingVersion || (len(raw)-1)%pointSize != 0 {
		return nil, errors.New("metrics: malformed chunk")
	}
	raw = raw[1:]
	out := make([]Point, 0, len(raw)/pointSize)
	for len(raw) >= pointSize {
		p := Point{T: int64(binary.LittleEndian.Uint64(raw))} //nolint:gosec // written by Encode
		off := 8
		f32 := make([]float32, 6)
		for i := range f32 {
			f32[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[off:]))
			off += 4
		}
		f64 := make([]float64, 4)
		for i := range f64 {
			f64[i] = math.Float64frombits(binary.LittleEndian.Uint64(raw[off:]))
			off += 8
		}
		p.CPU, p.CPUMax, p.Mem, p.Swap, p.Load1, p.DiskMax = f32[0], f32[1], f32[2], f32[3], f32[4], f32[5]
		p.DiskRead, p.DiskWrite, p.NetRx, p.NetTx = f64[0], f64[1], f64[2], f64[3]
		p.N = binary.LittleEndian.Uint32(raw[off:])
		out = append(out, p)
		raw = raw[pointSize:]
	}
	return out, nil
}
