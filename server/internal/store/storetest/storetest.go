// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package storetest is the contract test suite every storage driver must pass. Drivers call
// Run from their own tests with a factory that returns a fresh, migrated backend.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/Shaalan15/central/server/internal/store"
)

// Factory returns a fresh driver. Run calls Migrate itself.
type Factory func(t *testing.T) store.Driver

// Run executes the contract suite.
func Run(t *testing.T, newDriver Factory) {
	t.Helper()
	open := func(t *testing.T) (*store.Store, context.Context) {
		t.Helper()
		d := newDriver(t)
		s := store.Open(d)
		ctx := context.Background()
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s, ctx
	}

	t.Run("GlobalCRUD", func(t *testing.T) {
		s, ctx := open(t)
		sys := store.System()
		u := &store.User{ID: store.NewID(), Email: "a@example.com", DisplayName: "A", CreatedAt: time.Now().UTC()}
		mustOK(t, s.Users.Create(ctx, sys, u))
		got, err := s.Users.Get(ctx, sys, u.ID)
		mustOK(t, err)
		if got.Email != u.Email || got.DisplayName != "A" {
			t.Fatalf("got %+v", got)
		}
		got.DisplayName = "B"
		mustOK(t, s.Users.Update(ctx, sys, got))
		again, _ := s.Users.Get(ctx, sys, u.ID)
		if again.DisplayName != "B" {
			t.Fatal("update not persisted")
		}
		mustErr(t, s.Users.Create(ctx, sys, u), store.ErrAlreadyExists)
		mustOK(t, s.Users.Delete(ctx, sys, u.ID))
		_, err = s.Users.Get(ctx, sys, u.ID)
		mustErr(t, err, store.ErrNotFound)
		mustErr(t, s.Users.Delete(ctx, sys, u.ID), store.ErrNotFound)
		mustErr(t, s.Users.Update(ctx, sys, u), store.ErrNotFound)
	})

	t.Run("UniqueIndex", func(t *testing.T) {
		s, ctx := open(t)
		sys := store.System()
		mustOK(t, s.Users.Create(ctx, sys, &store.User{ID: store.NewID(), Email: "dup@example.com"}))
		mustErr(t, s.Users.Create(ctx, sys, &store.User{ID: store.NewID(), Email: "dup@example.com"}), store.ErrAlreadyExists)
		u, err := s.Users.FindOne(ctx, sys, store.Eq("email", "dup@example.com"))
		mustOK(t, err)
		if u.Email != "dup@example.com" {
			t.Fatal("FindOne by unique field")
		}
	})

	t.Run("ScopeRules", func(t *testing.T) {
		s, ctx := open(t)
		orgA, orgB := store.Tenant("orga"), store.Tenant("orgb")
		// Global collections require the system scope.
		mustErr(t, s.Users.Create(ctx, orgA, &store.User{ID: store.NewID(), Email: "x@example.com"}), store.ErrScope)
		_, _, err := s.Users.Find(ctx, orgA, store.Query{})
		mustErr(t, err, store.ErrScope)
		// Zero scope is always rejected.
		_, err = s.Agents.Get(ctx, store.Scope{}, "x")
		mustErr(t, err, store.ErrScope)

		a := &store.Agent{ID: store.NewID(), OrgID: "orga", Name: "web-1", MachineID: "m1", Lifecycle: store.AgentActive}
		mustOK(t, s.Agents.Create(ctx, orgA, a))
		// Writing a record for org A with org B's scope is refused.
		mustErr(t, s.Agents.Create(ctx, orgB, &store.Agent{ID: store.NewID(), OrgID: "orga"}), store.ErrScope)
		// Tenant collections refuse records without an org.
		mustErr(t, s.Agents.Create(ctx, store.System(), &store.Agent{ID: store.NewID()}), store.ErrScope)

		// Org B cannot see, update or delete org A's agent.
		_, err = s.Agents.Get(ctx, orgB, a.ID)
		mustErr(t, err, store.ErrNotFound)
		other := *a
		other.OrgID = "orgb"
		if err := s.Agents.Update(ctx, orgB, &other); err == nil {
			t.Fatal("org B updated org A's agent")
		}
		if err := s.Agents.Upsert(ctx, orgB, &other); err == nil {
			t.Fatal("org B upserted over org A's agent")
		}
		mustErr(t, s.Agents.Delete(ctx, orgB, a.ID), store.ErrNotFound)
		items, _, err := s.Agents.Find(ctx, orgB, store.Query{})
		mustOK(t, err)
		if len(items) != 0 {
			t.Fatalf("org B sees %d agents of org A", len(items))
		}
		n, err := s.Agents.Count(ctx, orgB, store.Query{})
		mustOK(t, err)
		if n != 0 {
			t.Fatal("org B counts org A's agents")
		}

		// The system scope sees everything; the record is intact.
		got, err := s.Agents.Get(ctx, store.System(), a.ID)
		mustOK(t, err)
		if got.OrgID != "orga" || got.Name != "web-1" {
			t.Fatalf("record altered: %+v", got)
		}
		// Records cannot move between organizations even with the system scope.
		moved := *got
		moved.OrgID = "orgb"
		if err := s.Agents.Update(ctx, store.System(), &moved); err == nil {
			t.Fatal("record moved between organizations")
		}
	})

	t.Run("Queries", func(t *testing.T) {
		s, ctx := open(t)
		sc := store.Tenant("org1")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := range 25 {
			ev := &store.AuditEvent{
				ID: fmt.Sprintf("ev%02d", i), OrgID: "org1", Seq: int64(i + 1),
				Time:   base.Add(time.Duration(i) * time.Minute),
				Action: []string{"agent.approve", "agent.revoke", "auth.login"}[i%3],
				Actor:  store.PrincipalRef{Kind: store.PrincipalUser, ID: fmt.Sprintf("u%d", i%2)},
				Result: store.AuditSuccess,
			}
			mustOK(t, s.Audit.Create(ctx, sc, ev))
		}
		// Another tenant's data must never appear.
		mustOK(t, s.Audit.Create(ctx, store.Tenant("org2"), &store.AuditEvent{ID: "other", OrgID: "org2", Seq: 1, Action: "agent.approve"}))

		count := func(q store.Query) int {
			t.Helper()
			n, err := s.Audit.Count(ctx, sc, q)
			mustOK(t, err)
			return n
		}
		if n := count(store.Query{}); n != 25 {
			t.Fatalf("count all = %d", n)
		}
		if n := count(store.Eq("action", "auth.login")); n != 8 {
			t.Fatalf("eq = %d", n)
		}
		if n := count(store.Where("action", store.OpPrefix, "agent.")); n != 17 {
			t.Fatalf("prefix = %d", n)
		}
		if n := count(store.Where("seq", store.OpGt, int64(20))); n != 5 {
			t.Fatalf("gt = %d", n)
		}
		if n := count(store.Where("seq", store.OpLte, int64(3))); n != 3 {
			t.Fatalf("lte = %d", n)
		}
		if n := count(store.Where("action", store.OpIn, []string{"agent.revoke", "auth.login"})); n != 16 {
			t.Fatalf("in = %d", n)
		}
		if n := count(store.Where("action", store.OpNe, "auth.login")); n != 17 {
			t.Fatalf("ne = %d", n)
		}
		if n := count(store.Eq("actor_id", "u1").And("action", store.OpEq, "agent.revoke")); n != 4 {
			t.Fatalf("and = %d", n)
		}
		from := base.Add(10 * time.Minute)
		if n := count(store.Where("time", store.OpGte, store.Millis(from))); n != 15 {
			t.Fatalf("time range = %d", n)
		}

		// Ordering and pagination.
		q := store.Query{}.Order("seq", true).Page(10, "")
		var seqs []int64
		pages := 0
		for {
			items, next, err := s.Audit.Find(ctx, sc, q)
			mustOK(t, err)
			pages++
			for _, it := range items {
				seqs = append(seqs, it.Seq)
			}
			if next == "" {
				break
			}
			q.After = next
			if pages > 10 {
				t.Fatal("pagination does not terminate")
			}
		}
		if pages != 3 || len(seqs) != 25 || seqs[0] != 25 || seqs[24] != 1 {
			t.Fatalf("pages=%d len=%d first=%v last=%v", pages, len(seqs), seqs[0], seqs[len(seqs)-1])
		}
		for i := 1; i < len(seqs); i++ {
			if seqs[i] >= seqs[i-1] {
				t.Fatalf("not descending at %d: %v", i, seqs)
			}
		}
		all, err := s.Audit.All(ctx, sc, store.Eq("action", "agent.approve"))
		mustOK(t, err)
		if len(all) != 9 {
			t.Fatalf("All = %d", len(all))
		}

		// Unindexed fields are rejected so drivers behave identically.
		_, _, err = s.Audit.Find(ctx, sc, store.Eq("user_agent", "x"))
		mustErr(t, err, store.ErrInvalidQuery)
		_, _, err = s.Audit.Find(ctx, sc, store.Query{OrderBy: "details"})
		mustErr(t, err, store.ErrInvalidQuery)
	})

	t.Run("UpsertAndDeleteWhere", func(t *testing.T) {
		s, ctx := open(t)
		sc := store.Tenant("org1")
		for i := range 5 {
			inv := &store.Inventory{
				ID: store.DeriveID("a1", strconv.Itoa(i)), OrgID: "org1", AgentID: "a1", Kind: strconv.Itoa(i), ContentHash: "h1",
			}
			mustOK(t, s.Inventory.Upsert(ctx, sc, inv))
		}
		inv := &store.Inventory{ID: store.DeriveID("a1", "0"), OrgID: "org1", AgentID: "a1", Kind: "0", ContentHash: "h2"}
		mustOK(t, s.Inventory.Upsert(ctx, sc, inv))
		got, err := s.Inventory.Get(ctx, sc, inv.ID)
		mustOK(t, err)
		if got.ContentHash != "h2" {
			t.Fatal("upsert did not replace")
		}
		mustOK(t, s.Inventory.Upsert(ctx, sc, &store.Inventory{ID: store.DeriveID("a2", "x"), OrgID: "org1", AgentID: "a2", Kind: "x"}))
		n, err := s.Inventory.DeleteWhere(ctx, sc, store.Eq("agent_id", "a1"))
		mustOK(t, err)
		if n != 5 {
			t.Fatalf("deleted %d", n)
		}
		left, _ := s.Inventory.Count(ctx, sc, store.Query{})
		if left != 1 {
			t.Fatalf("left %d", left)
		}
	})

	t.Run("BinaryAndNestedFields", func(t *testing.T) {
		s, ctx := open(t)
		sc := store.Tenant("org1")
		req := &store.EnrollmentRequest{
			ID: store.NewID(), OrgID: "org1", Status: store.EnrollmentPending,
			CSRDER: []byte{0, 1, 2, 255}, ServerNonce: []byte("nonce"),
			RiskFlags: []store.RiskFlag{{Code: "duplicate_hostname", Severity: "warning"}},
			CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		}
		mustOK(t, s.EnrollmentRequests.Create(ctx, sc, req))
		got, err := s.EnrollmentRequests.Get(ctx, sc, req.ID)
		mustOK(t, err)
		if string(got.CSRDER) != string(req.CSRDER) || len(got.RiskFlags) != 1 || !got.CreatedAt.Equal(req.CreatedAt) {
			t.Fatalf("round trip mismatch: %+v", got)
		}
	})

	t.Run("InvalidIDs", func(t *testing.T) {
		s, ctx := open(t)
		for _, id := range []string{"", "-leading", "has space", "../etc", "x" + string(make([]byte, 40))} {
			if err := s.Settings.Create(ctx, store.System(), &store.Setting{ID: id}); err == nil {
				t.Fatalf("accepted invalid id %q", id)
			}
			if _, err := s.Settings.Get(ctx, store.System(), id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Get(%q) = %v", id, err)
			}
		}
	})

	t.Run("Settings", func(t *testing.T) {
		s, ctx := open(t)
		_, err := s.GetSetting(ctx, "public_url")
		mustErr(t, err, store.ErrNotFound)
		mustOK(t, s.PutSetting(ctx, "public_url", "https://c.example.com"))
		mustOK(t, s.PutSetting(ctx, "public_url", "https://central.example.com"))
		v, err := s.GetSetting(ctx, "public_url")
		mustOK(t, err)
		if v != "https://central.example.com" {
			t.Fatalf("setting = %q", v)
		}
	})
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
