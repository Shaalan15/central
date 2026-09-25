// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

func newStore(t *testing.T) (*store.Holder, *store.Store) {
	t.Helper()
	s := store.Open(memory.New())
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(s)
	return h, s
}

func TestChainAndTamperDetection(t *testing.T) {
	ctx := context.Background()
	h, s := newStore(t)
	r := NewRecorder(h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := range 5 {
		err := r.Record(ctx, Event{
			OrgID: "org1", Actor: store.PrincipalRef{Kind: "user", ID: "u1"},
			Action: "agent.approve", TargetID: string(rune('a' + i)), Details: map[string]string{"k": "v"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A second org has an independent chain.
	if err := r.Record(ctx, Event{OrgID: "org2", Action: "auth.login"}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyChain(ctx, s, "org1", 0, 0)
	if err != nil || !res.Intact || res.Checked != 5 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	if res, _ := VerifyChain(ctx, s, "org2", 0, 0); !res.Intact || res.Checked != 1 {
		t.Fatalf("org2 = %+v", res)
	}

	// A fresh recorder (restart) continues the chain from the stored head.
	r2 := NewRecorder(h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := r2.Record(ctx, Event{OrgID: "org1", Action: "agent.revoke"}); err != nil {
		t.Fatal(err)
	}
	if res, _ := VerifyChain(ctx, s, "org1", 0, 0); !res.Intact || res.Checked != 6 {
		t.Fatalf("after restart = %+v", res)
	}

	// Editing an event breaks the chain at that event.
	ev, _ := s.Audit.FindOne(ctx, store.Tenant("org1"), store.Eq("seq", int64(3)))
	ev.Action = "nothing.to.see"
	if err := s.Audit.Update(ctx, store.Tenant("org1"), ev); err != nil {
		t.Fatal(err)
	}
	if res, _ := VerifyChain(ctx, s, "org1", 0, 0); res.Intact || res.FirstBrokenSeq != 3 {
		t.Fatalf("tampered = %+v", res)
	}

	// Deleting an event is detected as a gap.
	_, s2 := newStore(t)
	h2 := &store.Holder{}
	h2.Set(s2)
	r3 := NewRecorder(h2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for range 3 {
		_ = r3.Record(ctx, Event{OrgID: "o", Action: "x"})
	}
	mid, _ := s2.Audit.FindOne(ctx, store.Tenant("o"), store.Eq("seq", int64(2)))
	_ = s2.Audit.Delete(ctx, store.Tenant("o"), mid.ID)
	if res, _ := VerifyChain(ctx, s2, "o", 0, 0); res.Intact || res.FirstBrokenSeq != 3 {
		t.Fatalf("deleted = %+v", res)
	}
}
