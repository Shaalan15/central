// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package terminal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

func TestRecorderKeepsSplitRunes(t *testing.T) {
	ctx := context.Background()
	st := store.Open(memory.New())
	_ = st.Migrate(ctx)
	h := &store.Holder{}
	h.Set(st)
	r, err := StartRecording(ctx, h, store.Recording{ID: "rec1", OrgID: "org", AgentName: "web", RunAs: "root", Cols: 80, Rows: 24, StartedAt: time.Now()}, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	word := []byte("héllo ✓\n")
	for i := range word { // one byte at a time: every multi-byte rune is split
		r.Output(ctx, word[i:i+1])
	}
	r.Resize(ctx, 100, 30)
	if err := r.Finish(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if err := ReadChunks(ctx, st, "org", "rec1", func(b []byte) error { text.Write(b); return nil }); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, line := range strings.Split(text.String(), "\n") {
		if i := strings.Index(line, `"o","`); i >= 0 {
			out.WriteString(strings.TrimSuffix(line[i+5:], `"]`))
		}
	}
	joined := out.String()
	if !strings.Contains(joined, "héllo") || !strings.Contains(joined, "✓") || strings.Contains(text.String(), `�`) {
		t.Fatalf("recording mangled: %s", text.String())
	}
	if !strings.Contains(text.String(), `"r","100x30"`) || !strings.HasPrefix(text.String(), `{"env"`) {
		t.Fatalf("asciicast: %s", text.String())
	}
	rec, _ := st.Recordings.Get(ctx, store.Tenant("org"), "rec1")
	if rec.EndedAt.IsZero() || rec.OutputBytes != int64(len(word)) {
		t.Fatalf("metadata: %+v", rec)
	}
}
