// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/metrics"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

type fakeConn struct {
	mu     sync.Mutex
	msgs   []*agentv1.CentralMessage
	reason agentv1.Disconnect_Reason
}

func (c *fakeConn) Send(m *agentv1.CentralMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *fakeConn) Close(r agentv1.Disconnect_Reason, _ string) {
	c.mu.Lock()
	c.reason = r
	c.mu.Unlock()
}

func (c *fakeConn) closed() agentv1.Disconnect_Reason {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

func newIndex(t *testing.T) (*Index, *store.Holder) {
	t.Helper()
	st := store.Open(memory.New())
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(st)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(h, bus.NewMemory(), metrics.NewStore(h, log), log), h
}

func agent(id, org, name string, tags ...string) *store.Agent {
	return &store.Agent{ID: id, OrgID: org, Name: name, Hostname: name, Lifecycle: store.AgentActive, Tags: tags, CertSerial: "s-" + id}
}

func TestPresenceAndRevocation(t *testing.T) {
	ctx := context.Background()
	x, _ := newIndex(t)
	if err := x.Create(ctx, agent("a1", "org", "web-1")); err != nil {
		t.Fatal(err)
	}
	if err := x.CheckIdentity("org", "a1", "s-a1"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ org, id, serial string }{{"other", "a1", "s-a1"}, {"org", "a1", "old"}, {"org", "zz", "s-a1"}} {
		if err := x.CheckIdentity(c.org, c.id, c.serial); err == nil {
			t.Errorf("identity %+v accepted", c)
		}
	}
	// The previous serial is honoured during the renewal grace period only.
	_, _ = x.Update(ctx, "org", "a1", func(a *store.Agent) error {
		a.PrevCertSerial, a.PrevCertValidUntil, a.CertSerial = "s-a1", time.Now().Add(time.Hour), "s-new"
		return nil
	})
	if x.CheckIdentity("org", "a1", "s-a1") != nil || x.CheckIdentity("org", "a1", "s-new") != nil {
		t.Fatal("renewal grace")
	}

	c1, c2 := &fakeConn{}, &fakeConn{}
	info := ConnectInfo{Facts: &agentv1.HostFacts{Hostname: "web-1b"}, Version: "0.1.0", RemoteIP: "192.0.2.1"}
	if err := x.Connect(ctx, "org", "a1", c1, info); err != nil {
		t.Fatal(err)
	}
	if v, _ := x.Get("a1"); !v.Online || v.Agent.Hostname != "web-1b" || v.Agent.LastIP != "192.0.2.1" || x.Connected() != 1 {
		t.Fatalf("after connect: %+v", v)
	}
	if err := x.Connect(ctx, "org", "a1", c2, info); err != nil {
		t.Fatal(err)
	}
	if c1.closed() != agentv1.Disconnect_REASON_REPLACED || x.Conn("a1") != c2 {
		t.Fatal("old stream not replaced")
	}
	x.Disconnect(ctx, "a1", c1) // stale stream: no effect
	if v, _ := x.Get("a1"); !v.Online {
		t.Fatal("stale disconnect took the agent offline")
	}

	if _, err := x.Revoke(ctx, "other", "a1", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org revoke: %v", err)
	}
	if _, err := x.Revoke(ctx, "org", "a1", "compromised"); err != nil {
		t.Fatal(err)
	}
	if c2.closed() != agentv1.Disconnect_REASON_REVOKED || x.Conn("a1") != nil {
		t.Fatal("revoked agent not disconnected")
	}
	if !errors.Is(x.CheckIdentity("org", "a1", "s-new"), ErrRevoked) {
		t.Fatal("revoked identity accepted")
	}
	if err := x.Connect(ctx, "org", "a1", &fakeConn{}, info); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked agent connected: %v", err)
	}
	if _, err := x.Revoke(ctx, "org", "a1", "again"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("double revoke: %v", err)
	}

	// A fresh index loads the same state.
	y := New(x.holder, nil, nil, x.log)
	if err := y.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := y.Get("a1"); !ok || v.Active() || v.Agent.RevokedReason != "compromised" || v.Facts.GetHostname() != "web-1b" {
		t.Fatalf("reloaded: %+v", v)
	}
}

func TestInventoryFilterSortSummary(t *testing.T) {
	ctx := context.Background()
	x, _ := newIndex(t)
	for _, a := range []*store.Agent{
		agent("a1", "org", "web-1", "web", "prod"), agent("a2", "org", "web-2", "web"),
		agent("a3", "org", "db-1", "db"), agent("b1", "org2", "other"),
	} {
		if err := x.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	_ = x.Connect(ctx, "org", "a1", &fakeConn{}, ConnectInfo{Facts: &agentv1.HostFacts{
		Os:        &agentv1.OSInfo{Id: "ubuntu", PrettyName: "Ubuntu 24.04"},
		Addresses: []*agentv1.InterfaceAddress{{Cidr: "10.1.2.3/24"}},
	}})
	report := &agentv1.InventoryReport{
		Kind: agentv1.InventoryKind_INVENTORY_KIND_UPDATES, ContentHash: "h1",
		Payload: &agentv1.InventoryReport_Updates{Updates: &agentv1.UpdateInventory{
			Updates:        []*agentv1.PendingUpdate{{Name: "openssl", Security: true}, {Name: "vim"}},
			RebootRequired: true,
		}},
	}
	if changed, err := x.SetInventory(ctx, "a1", report); err != nil || !changed {
		t.Fatalf("inventory: %v %v", changed, err)
	}
	if changed, _ := x.SetInventory(ctx, "a1", report); changed {
		t.Fatal("unchanged hash stored again")
	}
	if r, err := x.Inventory(ctx, "org", "a1", agentv1.InventoryKind_INVENTORY_KIND_UPDATES); err != nil || len(r.GetUpdates().GetUpdates()) != 2 {
		t.Fatalf("stored inventory: %v", err)
	}
	if r, _ := x.Inventory(ctx, "org2", "a1", agentv1.InventoryKind_INVENTORY_KIND_UPDATES); r != nil {
		t.Fatal("inventory visible to another organization")
	}
	x.RecordMetrics("a1", []*agentv1.MetricsSample{{Time: timestamppb.Now(), CpuPercent: 95, MemoryTotalBytes: 10, MemoryUsedBytes: 1}})

	all := x.All("org", nil)
	if len(all) != 3 {
		t.Fatalf("org has %d agents", len(all))
	}
	match := func(f Filter) []string {
		var ids []string
		for i := range all {
			if f.Matches(&all[i]) {
				ids = append(ids, all[i].Agent.ID)
			}
		}
		return ids
	}
	online := true
	cases := map[string]struct {
		f    Filter
		want int
	}{
		"tags":     {Filter{Tags: []string{"web", "prod"}}, 1},
		"query":    {Filter{Query: "WEB"}, 2},
		"ip":       {Filter{Query: "10.1.2"}, 1},
		"online":   {Filter{Online: &online}, 1},
		"security": {Filter{HasSecurity: true}, 1},
		"reboot":   {Filter{RebootRequired: true}, 1},
		"os":       {Filter{OSIDs: []string{"debian"}}, 0},
	}
	for name, c := range cases {
		if got := match(c.f); len(got) != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	Sort(all, SortName, false)
	if all[0].Agent.Name != "db-1" || all[2].Agent.Name != "web-2" {
		t.Fatal("sort by name")
	}
	Sort(all, SortCPU, true)
	if all[0].Agent.ID != "a1" {
		t.Fatal("sort by cpu")
	}
	x.AdjustPending("org", 2)
	s := Summarize(all, x.Pending("org"))
	if s.Total != 3 || s.Online != 1 || s.Offline != 2 || s.Pending != 2 || s.TotalUpdates != 2 || s.TotalSecurity != 1 ||
		s.RebootRequired != 1 || s.UnderPressure != 1 {
		t.Fatalf("summary: %+v", s)
	}
}
