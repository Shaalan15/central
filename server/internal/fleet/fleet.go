// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package fleet is Central's in-memory index of enrolled agents: identity, facts, owner policy,
// live connection state, latest metrics and update counters. Listing, filtering and summarizing
// thousands of agents is served from memory; the store is the durable record, written through on
// every administrative or identity change.
//
// The index is also the presence registry: it maps each agent to its current control stream, so
// revocation can disconnect an agent immediately.
package fleet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/metrics"
	"github.com/Shaalan15/central/server/internal/store"
)

// Errors.
var (
	ErrNotFound = errors.New("fleet: agent not found")
	ErrRevoked  = errors.New("fleet: agent revoked")
	ErrIdentity = errors.New("fleet: certificate is not the agent's current certificate")
)

// Conn is an agent's live control stream.
type Conn interface {
	// Send queues a message without blocking.
	Send(msg *agentv1.CentralMessage) error
	// Close tells the agent why and ends the stream.
	Close(reason agentv1.Disconnect_Reason, message string)
}

// View is an immutable snapshot of one agent. Callers must not modify it.
type View struct {
	Agent          store.Agent
	Facts          *agentv1.HostFacts
	Policy         *agentv1.EffectivePolicy
	Online         bool
	ConnectedSince time.Time
	RemoteIP       string
	ClockSkew      time.Duration
	Latest         *agentv1.MetricsSample
	Point          metrics.Point
	HasPoint       bool
}

// Ref returns the authorization reference of the agent.
func (v *View) Ref() authz.AgentRef {
	return authz.AgentRef{ID: v.Agent.ID, GroupID: v.Agent.GroupID, Tags: v.Agent.Tags}
}

// Active reports whether the agent has not been revoked.
func (v *View) Active() bool { return v.Agent.Lifecycle == store.AgentActive }

// Allows reports whether the owner policy (as last reported) permits a capability. Agents that
// have not reported a policy yet are assumed to allow it; the agent enforces the real policy.
func (v *View) Allows(c agentv1.Capability) bool {
	if v.Policy == nil {
		return true
	}
	return slices.Contains(v.Policy.GetAllowed(), c)
}

// Paused reports whether the owner paused remote operations.
func (v *View) Paused() bool { return v.Policy.GetPaused() }

// Change is published on bus.FleetTopic(org) whenever an agent (or the org's counters) change.
type Change struct {
	OrgID   string
	AgentID string // "" for org-level counters (pending enrollments)
}

type entry struct {
	view      View
	invHashes map[string]string
	conn      Conn
}

// Index is the fleet index.
type Index struct {
	holder  *store.Holder
	bus     bus.Bus
	metrics *metrics.Store
	log     *slog.Logger
	now     func() time.Time

	mu      sync.RWMutex
	agents  map[string]*entry
	pending map[string]int
}

// New returns an empty index. Call Load once storage is available.
func New(holder *store.Holder, b bus.Bus, m *metrics.Store, log *slog.Logger) *Index {
	return &Index{
		holder: holder, bus: b, metrics: m, log: log, now: time.Now,
		agents: map[string]*entry{}, pending: map[string]int{},
	}
}

// Metrics returns the metrics store.
func (x *Index) Metrics() *metrics.Store { return x.metrics }

func (x *Index) st() (*store.Store, error) {
	st := x.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	return st, nil
}

// Load reads every agent and the pending enrollment counts from storage.
func (x *Index) Load(ctx context.Context) error {
	st, err := x.st()
	if err != nil {
		return err
	}
	agents := map[string]*entry{}
	after := ""
	for {
		page, next, err := st.Agents.Find(ctx, store.System(), store.Query{}.Page(store.MaxLimit, after))
		if err != nil {
			return fmt.Errorf("fleet: load agents: %w", err)
		}
		for _, a := range page {
			agents[a.ID] = &entry{view: viewOf(a), invHashes: map[string]string{}}
		}
		if next == "" {
			break
		}
		after = next
	}
	pending := map[string]int{}
	after = ""
	for {
		page, next, err := st.EnrollmentRequests.Find(ctx, store.System(),
			store.Eq("status", store.EnrollmentPending).Page(store.MaxLimit, after))
		if err != nil {
			return fmt.Errorf("fleet: load enrollment requests: %w", err)
		}
		for _, r := range page {
			if x.now().Before(r.ExpiresAt) {
				pending[r.OrgID]++
			}
		}
		if next == "" {
			break
		}
		after = next
	}
	x.mu.Lock()
	for id, e := range x.agents { // keep live connections across reloads
		if n := agents[id]; n != nil {
			n.conn, n.view.Online, n.view.ConnectedSince = e.conn, e.view.Online, e.view.ConnectedSince
		}
	}
	x.agents, x.pending = agents, pending
	x.mu.Unlock()
	return nil
}

func viewOf(a *store.Agent) View {
	v := View{Agent: *a}
	if len(a.FactsProto) > 0 {
		f := &agentv1.HostFacts{}
		if proto.Unmarshal(a.FactsProto, f) == nil {
			v.Facts = f
		}
	}
	if len(a.PolicyProto) > 0 {
		p := &agentv1.EffectivePolicy{}
		if proto.Unmarshal(a.PolicyProto, p) == nil {
			v.Policy = p
		}
	}
	return v
}

func (x *Index) publish(orgID, agentID string) {
	if x.bus != nil {
		x.bus.Publish(bus.FleetTopic(orgID), Change{OrgID: orgID, AgentID: agentID})
	}
}

// Get returns an agent by ID.
func (x *Index) Get(agentID string) (View, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e := x.agents[agentID]
	if e == nil {
		return View{}, false
	}
	return e.view, true
}

// GetInOrg returns an agent only if it belongs to orgID.
func (x *Index) GetInOrg(orgID, agentID string) (View, bool) {
	v, ok := x.Get(agentID)
	if !ok || v.Agent.OrgID != orgID {
		return View{}, false
	}
	return v, true
}

// CheckIdentity verifies that a certificate identity belongs to an active agent and is its
// current certificate (or the previous one within the renewal grace period).
func (x *Index) CheckIdentity(orgID, agentID, serial string) error {
	v, ok := x.GetInOrg(orgID, agentID)
	if !ok {
		return ErrNotFound
	}
	if !v.Active() {
		return ErrRevoked
	}
	if serial == v.Agent.CertSerial {
		return nil
	}
	if serial != "" && serial == v.Agent.PrevCertSerial && x.now().Before(v.Agent.PrevCertValidUntil) {
		return nil
	}
	return ErrIdentity
}

// Create adds a newly enrolled agent (persisting it).
func (x *Index) Create(ctx context.Context, a *store.Agent) error {
	st, err := x.st()
	if err != nil {
		return err
	}
	if err := st.Agents.Create(ctx, store.Tenant(a.OrgID), a); err != nil {
		return err
	}
	x.mu.Lock()
	x.agents[a.ID] = &entry{view: viewOf(a), invHashes: map[string]string{}}
	x.mu.Unlock()
	x.publish(a.OrgID, a.ID)
	return nil
}

// Update applies fn to a copy of the agent record, persists it and updates the index.
func (x *Index) Update(ctx context.Context, orgID, agentID string, fn func(a *store.Agent) error) (View, error) {
	st, err := x.st()
	if err != nil {
		return View{}, err
	}
	x.mu.RLock()
	e := x.agents[agentID]
	var cp store.Agent
	if e != nil {
		cp = e.view.Agent
	}
	x.mu.RUnlock()
	if e == nil || cp.OrgID != orgID {
		return View{}, ErrNotFound
	}
	cp.Tags, cp.Features = slices.Clone(cp.Tags), slices.Clone(cp.Features)
	cp.FactsProto, cp.PolicyProto = slices.Clone(cp.FactsProto), slices.Clone(cp.PolicyProto)
	if err := fn(&cp); err != nil {
		return View{}, err
	}
	cp.UpdatedAt = x.now().UTC()
	if err := st.Agents.Update(ctx, store.Tenant(orgID), &cp); err != nil {
		return View{}, err
	}
	x.mu.Lock()
	cur := x.agents[agentID]
	if cur == nil {
		x.mu.Unlock()
		return View{}, ErrNotFound
	}
	nv := viewOf(&cp)
	nv.Online, nv.ConnectedSince, nv.RemoteIP, nv.ClockSkew = cur.view.Online, cur.view.ConnectedSince, cur.view.RemoteIP, cur.view.ClockSkew
	nv.Latest, nv.Point, nv.HasPoint = cur.view.Latest, cur.view.Point, cur.view.HasPoint
	cur.view = nv
	x.mu.Unlock()
	x.publish(orgID, agentID)
	return nv, nil
}

// Revoke revokes an agent and disconnects it immediately.
func (x *Index) Revoke(ctx context.Context, orgID, agentID, reason string) (View, error) {
	v, err := x.Update(ctx, orgID, agentID, func(a *store.Agent) error {
		if a.Lifecycle == store.AgentRevoked {
			return ErrRevoked
		}
		a.Lifecycle, a.RevokedAt, a.RevokedReason = store.AgentRevoked, x.now().UTC(), reason
		return nil
	})
	if err != nil {
		return View{}, err
	}
	x.mu.Lock()
	var conn Conn
	if e := x.agents[agentID]; e != nil {
		conn, e.conn = e.conn, nil
		e.view.Online = false
	}
	x.mu.Unlock()
	if conn != nil {
		conn.Close(agentv1.Disconnect_REASON_REVOKED, "this agent was revoked in Central")
	}
	if x.metrics != nil {
		x.metrics.Forget(agentID)
	}
	x.publish(orgID, agentID)
	return v, nil
}

// ConnectInfo is what an agent reports in Hello.
type ConnectInfo struct {
	Facts     *agentv1.HostFacts
	Policy    *agentv1.EffectivePolicy
	Version   string
	Features  []string
	RemoteIP  string
	ClockSkew time.Duration
}

// Connect registers a new control stream for an agent, replacing (and closing) any previous
// one, and records the agent's Hello.
func (x *Index) Connect(ctx context.Context, orgID, agentID string, conn Conn, info ConnectInfo) error {
	now := x.now().UTC()
	facts, _ := proto.Marshal(info.Facts)
	pol, _ := proto.Marshal(info.Policy)
	_, err := x.Update(ctx, orgID, agentID, func(a *store.Agent) error {
		if a.Lifecycle != store.AgentActive {
			return ErrRevoked
		}
		a.FactsProto, a.PolicyProto, a.AgentVersion, a.Features = facts, pol, info.Version, info.Features
		if h := info.Facts.GetHostname(); h != "" {
			a.Hostname = h
		}
		a.LastSeenAt, a.LastIP = now, info.RemoteIP
		return nil
	})
	if err != nil {
		return err
	}
	x.mu.Lock()
	e := x.agents[agentID]
	if e == nil {
		x.mu.Unlock()
		return ErrNotFound
	}
	if !e.view.Active() { // revoked between the update and now
		x.mu.Unlock()
		return ErrRevoked
	}
	prev := e.conn
	e.conn = conn
	e.view.Online, e.view.ConnectedSince, e.view.RemoteIP, e.view.ClockSkew = true, now, info.RemoteIP, info.ClockSkew
	x.mu.Unlock()
	if prev != nil && prev != conn {
		prev.Close(agentv1.Disconnect_REASON_REPLACED, "a newer connection from this agent replaced this one")
	}
	x.publish(orgID, agentID)
	return nil
}

// Disconnect marks an agent offline if conn is still its current stream.
func (x *Index) Disconnect(ctx context.Context, agentID string, conn Conn) {
	x.mu.Lock()
	e := x.agents[agentID]
	if e == nil || e.conn != conn {
		x.mu.Unlock()
		return
	}
	e.conn = nil
	e.view.Online = false
	orgID, active := e.view.Agent.OrgID, e.view.Active()
	x.mu.Unlock()
	if active {
		if _, err := x.Update(ctx, orgID, agentID, func(a *store.Agent) error {
			a.LastSeenAt = x.now().UTC()
			return nil
		}); err != nil {
			x.log.Warn("fleet: recording disconnect failed", "agent", agentID, "error", err)
		}
	}
	x.publish(orgID, agentID)
}

// Conn returns an agent's current control stream (nil if offline).
func (x *Index) Conn(agentID string) Conn {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if e := x.agents[agentID]; e != nil {
		return e.conn
	}
	return nil
}

// CloseAll ends every live control stream (shutdown).
func (x *Index) CloseAll(reason agentv1.Disconnect_Reason, message string) {
	x.mu.RLock()
	conns := make([]Conn, 0, len(x.agents))
	for _, e := range x.agents {
		if e.conn != nil {
			conns = append(conns, e.conn)
		}
	}
	x.mu.RUnlock()
	for _, c := range conns {
		c.Close(reason, message)
	}
}

// Touch records liveness (heartbeats) without persisting.
func (x *Index) Touch(agentID string) {
	x.mu.Lock()
	if e := x.agents[agentID]; e != nil {
		e.view.Agent.LastSeenAt = x.now().UTC()
	}
	x.mu.Unlock()
}

// RecordMetrics ingests samples and returns the accepted ones.
func (x *Index) RecordMetrics(agentID string, samples []*agentv1.MetricsSample) []*agentv1.MetricsSample {
	v, ok := x.Get(agentID)
	if !ok || x.metrics == nil {
		return nil
	}
	accepted := x.metrics.Ingest(v.Agent.OrgID, agentID, samples)
	if len(accepted) == 0 {
		return nil
	}
	p, hasPoint := x.metrics.Latest(agentID)
	x.mu.Lock()
	if e := x.agents[agentID]; e != nil {
		e.view.Latest, e.view.Point, e.view.HasPoint = accepted[len(accepted)-1], p, hasPoint
		e.view.Agent.LastSeenAt = x.now().UTC()
	}
	x.mu.Unlock()
	if x.bus != nil {
		for _, s := range accepted {
			x.bus.Publish(bus.AgentMetricsTopic(agentID), s)
		}
	}
	x.publish(v.Agent.OrgID, agentID)
	return accepted
}

// SetPolicy records a new effective owner policy.
func (x *Index) SetPolicy(ctx context.Context, agentID string, p *agentv1.EffectivePolicy) error {
	v, ok := x.Get(agentID)
	if !ok {
		return ErrNotFound
	}
	data, err := proto.Marshal(p)
	if err != nil {
		return err
	}
	_, err = x.Update(ctx, v.Agent.OrgID, agentID, func(a *store.Agent) error {
		a.PolicyProto = data
		return nil
	})
	return err
}

// SetRebootRequired records the reboot-required flag from an agent event.
func (x *Index) SetRebootRequired(ctx context.Context, agentID string, required bool) error {
	v, ok := x.Get(agentID)
	if !ok {
		return ErrNotFound
	}
	if v.Agent.RebootRequired == required {
		return nil
	}
	_, err := x.Update(ctx, v.Agent.OrgID, agentID, func(a *store.Agent) error {
		a.RebootRequired = required
		return nil
	})
	return err
}

// MaxInventoryBytes bounds one serialized inventory report.
const MaxInventoryBytes = 8 << 20

// InventoryKindName returns the storage name of an inventory kind ("" if invalid).
func InventoryKindName(k agentv1.InventoryKind) string {
	if k == agentv1.InventoryKind_INVENTORY_KIND_UNSPECIFIED {
		return ""
	}
	name, ok := agentv1.InventoryKind_name[int32(k)]
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(name, "INVENTORY_KIND_"))
}

// SetInventory stores an inventory report unless its content hash is unchanged. It returns
// whether anything changed.
func (x *Index) SetInventory(ctx context.Context, agentID string, r *agentv1.InventoryReport) (bool, error) {
	kind := InventoryKindName(r.GetKind())
	if kind == "" {
		return false, errors.New("fleet: unknown inventory kind")
	}
	v, ok := x.Get(agentID)
	if !ok {
		return false, ErrNotFound
	}
	hash := r.GetContentHash()
	if len(hash) > 64 {
		return false, errors.New("fleet: invalid content hash")
	}
	x.mu.RLock()
	same := hash != "" && x.agents[agentID] != nil && x.agents[agentID].invHashes[kind] == hash
	x.mu.RUnlock()
	if same {
		return false, nil
	}
	data, err := proto.Marshal(r)
	if err != nil {
		return false, err
	}
	if len(data) > MaxInventoryBytes {
		return false, fmt.Errorf("fleet: %s inventory is too large (%d bytes)", kind, len(data))
	}
	st, err := x.st()
	if err != nil {
		return false, err
	}
	orgID := v.Agent.OrgID
	now := x.now().UTC()
	if err := st.Inventory.Upsert(ctx, store.Tenant(orgID), &store.Inventory{
		ID: store.DeriveID(agentID, kind), OrgID: orgID, AgentID: agentID, Kind: kind, ContentHash: hash,
		ReportProto: data, CollectedAt: r.GetCollectedAt().AsTime(), UpdatedAt: now,
	}); err != nil {
		return false, err
	}
	x.mu.Lock()
	if e := x.agents[agentID]; e != nil {
		e.invHashes[kind] = hash
	}
	x.mu.Unlock()
	if u := r.GetUpdates(); u != nil && r.GetKind() == agentv1.InventoryKind_INVENTORY_KIND_UPDATES {
		security := 0
		for _, p := range u.GetUpdates() {
			if p.GetSecurity() {
				security++
			}
		}
		if _, err := x.Update(ctx, orgID, agentID, func(a *store.Agent) error {
			a.UpdatesAvailable, a.SecurityUpdates, a.RebootRequired = len(u.GetUpdates()), security, u.GetRebootRequired()
			return nil
		}); err != nil {
			return true, err
		}
	} else {
		x.publish(orgID, agentID)
	}
	return true, nil
}

// Inventory returns the stored report of one kind (nil if none).
func (x *Index) Inventory(ctx context.Context, orgID, agentID string, k agentv1.InventoryKind) (*agentv1.InventoryReport, error) {
	kind := InventoryKindName(k)
	if kind == "" {
		return nil, errors.New("fleet: unknown inventory kind")
	}
	st, err := x.st()
	if err != nil {
		return nil, err
	}
	row, err := st.Inventory.Get(ctx, store.Tenant(orgID), store.DeriveID(agentID, kind))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r := &agentv1.InventoryReport{}
	if err := proto.Unmarshal(row.ReportProto, r); err != nil {
		return nil, err
	}
	return r, nil
}

// AdjustPending changes an organization's pending enrollment count.
func (x *Index) AdjustPending(orgID string, delta int) {
	x.mu.Lock()
	x.pending[orgID] = max(0, x.pending[orgID]+delta)
	x.mu.Unlock()
	x.publish(orgID, "")
}

// Pending returns an organization's pending enrollment count.
func (x *Index) Pending(orgID string) int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.pending[orgID]
}

// Connected returns the number of agents with a live control stream.
func (x *Index) Connected() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	n := 0
	for _, e := range x.agents {
		if e.conn != nil {
			n++
		}
	}
	return n
}

// PersistLastSeen writes the in-memory last-seen time of online agents (periodic and at
// shutdown).
func (x *Index) PersistLastSeen(ctx context.Context) {
	type item struct{ org, id string }
	var items []item
	x.mu.RLock()
	for id, e := range x.agents {
		if e.view.Online {
			items = append(items, item{e.view.Agent.OrgID, id})
		}
	}
	x.mu.RUnlock()
	for _, it := range items {
		_, _ = x.Update(ctx, it.org, it.id, func(*store.Agent) error { return nil }) // persists the touched copy
	}
}

// GroupCounts returns the number of active agents per group in an organization.
func (x *Index) GroupCounts(orgID string) map[string]int {
	out := map[string]int{}
	x.mu.RLock()
	defer x.mu.RUnlock()
	for _, e := range x.agents {
		if e.view.Agent.OrgID == orgID && e.view.Active() && e.view.Agent.GroupID != "" {
			out[e.view.Agent.GroupID]++
		}
	}
	return out
}

// All returns every agent of an organization accepted by allow (nil allows all).
func (x *Index) All(orgID string, allow func(*View) bool) []View {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]View, 0, len(x.agents))
	for _, e := range x.agents {
		if e.view.Agent.OrgID != orgID {
			continue
		}
		if allow != nil && !allow(&e.view) {
			continue
		}
		out = append(out, e.view)
	}
	return out
}

// Filter selects agents (mirrors api.v1.AgentFilter).
type Filter struct {
	Query          string
	Online         *bool
	Tags           []string
	GroupIDs       []string
	HasUpdates     bool
	HasSecurity    bool
	RebootRequired bool
	OSIDs          []string
	IncludeRevoked bool
}

// Matches reports whether v passes the filter.
func (f *Filter) Matches(v *View) bool {
	if !f.IncludeRevoked && !v.Active() {
		return false
	}
	if f.Online != nil && *f.Online != v.Online {
		return false
	}
	for _, t := range f.Tags {
		if !slices.Contains(v.Agent.Tags, t) {
			return false
		}
	}
	if len(f.GroupIDs) > 0 && !slices.Contains(f.GroupIDs, v.Agent.GroupID) {
		return false
	}
	if (f.HasUpdates && v.Agent.UpdatesAvailable == 0) || (f.HasSecurity && v.Agent.SecurityUpdates == 0) ||
		(f.RebootRequired && !v.Agent.RebootRequired) {
		return false
	}
	if len(f.OSIDs) > 0 && !slices.Contains(f.OSIDs, v.Facts.GetOs().GetId()) {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" {
		if !strings.Contains(strings.ToLower(v.Agent.Name), q) && !strings.Contains(strings.ToLower(v.Agent.Hostname), q) &&
			!slices.ContainsFunc(v.Agent.Tags, func(t string) bool { return strings.Contains(t, q) }) &&
			!slices.ContainsFunc(v.Facts.GetAddresses(), func(a *agentv1.InterfaceAddress) bool {
				return strings.HasPrefix(a.GetCidr(), q)
			}) {
			return false
		}
	}
	return true
}

// SortField selects the sort key.
type SortField int

// Sort fields.
const (
	SortName SortField = iota
	SortLastSeen
	SortCPU
	SortMemory
	SortDisk
	SortUpdates
	SortOS
)

// Sort orders views in place (ties broken by name, then ID).
func Sort(views []View, by SortField, desc bool) {
	slices.SortStableFunc(views, func(a, b View) int {
		var c int
		switch by {
		case SortLastSeen:
			c = a.Agent.LastSeenAt.Compare(b.Agent.LastSeenAt)
		case SortCPU:
			c = cmp.Compare(a.Point.CPU, b.Point.CPU)
		case SortMemory:
			c = cmp.Compare(a.Point.Mem, b.Point.Mem)
		case SortDisk:
			c = cmp.Compare(a.Point.DiskMax, b.Point.DiskMax)
		case SortUpdates:
			c = cmp.Or(cmp.Compare(a.Agent.SecurityUpdates, b.Agent.SecurityUpdates), cmp.Compare(a.Agent.UpdatesAvailable, b.Agent.UpdatesAvailable))
		case SortOS:
			c = cmp.Compare(a.Facts.GetOs().GetPrettyName(), b.Facts.GetOs().GetPrettyName())
		case SortName:
		}
		if desc {
			c = -c
		}
		return cmp.Or(c, cmp.Compare(strings.ToLower(a.Agent.Name), strings.ToLower(b.Agent.Name)), cmp.Compare(a.Agent.ID, b.Agent.ID))
	})
}

// Summary is fleet-wide counters for a set of agents.
type Summary struct {
	Total, Online, Offline, Pending            int
	WithUpdates, WithSecurity, RebootRequired  int
	TotalUpdates, TotalSecurity, UnderPressure int
}

// UnderPressure reports whether an online agent is above 90% CPU, memory or disk.
func UnderPressure(v *View) bool {
	return v.Online && v.HasPoint && (v.Point.CPU > 90 || v.Point.Mem > 90 || v.Point.DiskMax > 90)
}

// Summarize computes counters over active agents.
func Summarize(views []View, pending int) Summary {
	s := Summary{Pending: pending}
	for i := range views {
		v := &views[i]
		if !v.Active() {
			continue
		}
		s.Total++
		if v.Online {
			s.Online++
		} else {
			s.Offline++
		}
		if v.Agent.UpdatesAvailable > 0 {
			s.WithUpdates++
		}
		if v.Agent.SecurityUpdates > 0 {
			s.WithSecurity++
		}
		if v.Agent.RebootRequired {
			s.RebootRequired++
		}
		s.TotalUpdates += v.Agent.UpdatesAvailable
		s.TotalSecurity += v.Agent.SecurityUpdates
		if UnderPressure(v) {
			s.UnderPressure++
		}
	}
	return s
}
