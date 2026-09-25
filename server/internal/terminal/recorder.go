// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package terminal

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Shaalan15/central/server/internal/store"
)

// Recording limits.
const (
	MaxRecordingBytes = 64 << 20
	chunkFlushBytes   = 256 << 10
	chunkFlushEvery   = 30 * time.Second
	maxChunkDecoded   = 8 << 20
)

// Recorder writes a terminal session in asciicast v2 format as gzip chunks. Only output is
// recorded: keystrokes (which may include passwords typed at prompts) never are.
type Recorder struct {
	holder *store.Holder
	now    func() time.Time

	mu        sync.Mutex
	rec       store.Recording
	start     time.Time
	buf       bytes.Buffer
	carry     []byte
	seq       int
	lastFlush time.Time
	done      bool
}

// StartRecording creates the recording row and the asciicast header.
func StartRecording(ctx context.Context, holder *store.Holder, rec store.Recording, term string) (*Recorder, error) {
	st := holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	r := &Recorder{holder: holder, now: time.Now, rec: rec, start: rec.StartedAt, lastFlush: rec.StartedAt}
	if err := st.Recordings.Create(ctx, store.Tenant(rec.OrgID), &r.rec); err != nil {
		return nil, err
	}
	header, _ := json.Marshal(map[string]any{
		"version": 2, "width": rec.Cols, "height": rec.Rows, "timestamp": rec.StartedAt.Unix(),
		"title": rec.RunAs + "@" + rec.AgentName, "env": map[string]string{"TERM": term},
	})
	r.buf.Write(header)
	r.buf.WriteByte('\n')
	return r, nil
}

func (r *Recorder) event(kind string, data string) {
	elapsed := r.now().Sub(r.start).Seconds()
	line, _ := json.Marshal([]any{json.Number(strconv.FormatFloat(elapsed, 'f', 6, 64)), kind, data})
	r.buf.Write(line)
	r.buf.WriteByte('\n')
}

// Output records terminal output. Incomplete UTF-8 sequences at the end are carried over to
// the next call so multi-byte characters split across frames are recorded intact.
func (r *Recorder) Output(ctx context.Context, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || r.rec.Truncated {
		return
	}
	if r.rec.OutputBytes+int64(len(data)) > MaxRecordingBytes {
		r.rec.Truncated = true
		return
	}
	r.rec.OutputBytes += int64(len(data))
	all := slices.Concat(r.carry, data)
	cut := len(all)
	for i := 1; i <= 3 && i <= len(all); i++ { // find an incomplete trailing rune
		if b := all[len(all)-i]; utf8.RuneStart(b) {
			if !utf8.FullRune(all[len(all)-i:]) {
				cut = len(all) - i
			}
			break
		}
	}
	r.carry = append([]byte(nil), all[cut:]...)
	if cut > 0 {
		r.event("o", string(all[:cut]))
	}
	r.maybeFlush(ctx)
}

// Resize records a terminal size change.
func (r *Recorder) Resize(ctx context.Context, cols, rows uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || r.rec.Truncated {
		return
	}
	r.event("r", strconv.FormatUint(uint64(cols), 10)+"x"+strconv.FormatUint(uint64(rows), 10))
	r.maybeFlush(ctx)
}

func (r *Recorder) maybeFlush(ctx context.Context) {
	if r.buf.Len() >= chunkFlushBytes || r.now().Sub(r.lastFlush) >= chunkFlushEvery {
		_ = r.flushLocked(ctx)
	}
}

func (r *Recorder) flushLocked(ctx context.Context) error {
	if r.buf.Len() == 0 {
		return nil
	}
	st := r.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(r.buf.Bytes())
	if err := zw.Close(); err != nil {
		return err
	}
	chunk := &store.RecordingChunk{
		ID: store.DeriveID(r.rec.ID, strconv.Itoa(r.seq)), OrgID: r.rec.OrgID, RecordingID: r.rec.ID, Seq: r.seq, Data: z.Bytes(),
	}
	if err := st.RecordingChunks.Create(context.WithoutCancel(ctx), store.Tenant(r.rec.OrgID), chunk); err != nil {
		return err
	}
	r.seq++
	r.rec.Chunks = r.seq
	r.buf.Reset()
	r.lastFlush = r.now()
	return nil
}

// Finish writes the remaining output and closes the recording.
func (r *Recorder) Finish(ctx context.Context, exitCode int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return nil
	}
	r.done = true
	if len(r.carry) > 0 {
		r.event("o", string(r.carry))
		r.carry = nil
	}
	err := r.flushLocked(ctx)
	r.rec.EndedAt, r.rec.ExitCode = r.now().UTC(), exitCode
	if st := r.holder.Get(); st != nil {
		err = errors.Join(err, st.Recordings.Update(context.WithoutCancel(ctx), store.Tenant(r.rec.OrgID), &r.rec))
	}
	return err
}

// ReadChunks streams a recording's asciicast text to emit in order.
func ReadChunks(ctx context.Context, st *store.Store, orgID, recordingID string, emit func([]byte) error) error {
	after := ""
	for {
		q := store.Eq("recording_id", recordingID).Order("seq", false).Page(50, after)
		chunks, next, err := st.RecordingChunks.Find(ctx, store.Tenant(orgID), q)
		if err != nil {
			return err
		}
		for _, c := range chunks {
			zr, err := gzip.NewReader(bytes.NewReader(c.Data))
			if err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(zr, maxChunkDecoded))
			if err != nil {
				return err
			}
			if err := emit(data); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		after = next
	}
}
