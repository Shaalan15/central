// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package memory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Driver { return New() })
}

func TestContractPersistent(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Driver {
		d, err := Open(filepath.Join(t.TempDir(), "store.json"))
		if err != nil {
			t.Fatal(err)
		}
		return d
	})
}

func TestSnapshotSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	ctx := context.Background()

	d1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1 := store.Open(d1)
	if err := s1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	sc := store.Tenant("org1")
	if err := s1.Audit.Create(ctx, sc, &store.AuditEvent{ID: "e1", OrgID: "org1", Seq: 7, Action: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %o", info.Mode().Perm())
	}

	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s2 := store.Open(d2)
	defer func() { _ = s2.Close() }()
	// Typed index values survive the JSON round trip (int64 comparisons still work).
	n, err := s2.Audit.Count(ctx, sc, store.Where("seq", store.OpGte, int64(7)))
	if err != nil || n != 1 {
		t.Fatalf("count after restart = %d, %v", n, err)
	}
	ev, err := s2.Audit.Get(ctx, sc, "e1")
	if err != nil || ev.Action != "x" {
		t.Fatalf("get after restart = %+v, %v", ev, err)
	}
}
