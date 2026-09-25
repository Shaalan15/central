// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/metrics"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/validate"
)

// FleetService implements FleetService.
type FleetService struct {
	apiv1connect.UnimplementedFleetServiceHandler
	D *Deps
}

// MetricsService implements MetricsService.
type MetricsService struct {
	apiv1connect.UnimplementedMetricsServiceHandler
	D *Deps
}

var errAgentNotFound = connect.NewError(connect.CodeNotFound, errors.New("agent not found"))

// agentFor loads an agent of the caller's organization and checks perm on it. Agents outside
// the caller's scope are indistinguishable from missing ones.
func (d *Deps) agentFor(ctx context.Context, perm, agentID string) (*authz.Principal, fleet.View, error) {
	if _, err := d.Store(); err != nil {
		return nil, fleet.View{}, err
	}
	p := authz.From(ctx)
	if p == nil || p.OrgID == "" {
		_, err := authz.Require(ctx, perm)
		return nil, fleet.View{}, err
	}
	v, ok := d.Fleet.GetInOrg(p.OrgID, agentID)
	if !ok {
		return nil, fleet.View{}, errAgentNotFound
	}
	if !p.HasOnAgent(authz.FleetView, v.Ref()) {
		return nil, fleet.View{}, errAgentNotFound
	}
	// The agent is visible: missing permissions are reported as such.
	if _, err := authz.Require(ctx, perm); err != nil {
		return nil, fleet.View{}, err
	}
	if !p.HasOnAgent(perm, v.Ref()) {
		return nil, fleet.View{}, connect.NewError(connect.CodePermissionDenied, errors.New("missing permission "+perm+" on this agent"))
	}
	return p, v, nil
}

func primaryIP(f *agentv1.HostFacts) string {
	for _, a := range f.GetAddresses() {
		if pfx, err := netip.ParsePrefix(a.GetCidr()); err == nil && !pfx.Addr().IsLoopback() && !pfx.Addr().IsLinkLocalUnicast() {
			return pfx.Addr().String()
		}
	}
	return ""
}

func summaryProto(v *fleet.View) *apiv1.AgentSummary {
	a := &v.Agent
	f := v.Facts
	out := &apiv1.AgentSummary{
		Id: a.ID, Name: a.Name, Hostname: a.Hostname, Connection: apiv1.ConnectionState_CONNECTION_STATE_OFFLINE,
		Lifecycle: apiv1.AgentLifecycle_AGENT_LIFECYCLE_ACTIVE, Tags: a.Tags, GroupId: a.GroupID,
		OsPrettyName: f.GetOs().GetPrettyName(), OsId: f.GetOs().GetId(), OsVersion: f.GetOs().GetVersionId(),
		Arch: f.GetArch(), AgentVersion: a.AgentVersion, PrimaryIp: primaryIP(f), LastSeenAt: ts(a.LastSeenAt),
		UpdatesAvailable: uint32(max(a.UpdatesAvailable, 0)), SecurityUpdates: uint32(max(a.SecurityUpdates, 0)), //nolint:gosec // bounded
		RebootRequired: a.RebootRequired, PolicyProfile: v.Policy.GetProfile(), PolicyPaused: v.Policy.GetPaused(),
		CpuThreads: f.GetCpu().GetThreads(),
	}
	if !v.Active() {
		out.Lifecycle = apiv1.AgentLifecycle_AGENT_LIFECYCLE_REVOKED
	}
	if v.Online {
		out.Connection = apiv1.ConnectionState_CONNECTION_STATE_ONLINE
		out.ConnectedSince = ts(v.ConnectedSince)
		if v.HasPoint {
			out.CpuPercent, out.MemoryUsedPercent, out.DiskUsedPercentMax, out.Load1 = v.Point.CPU, v.Point.Mem, v.Point.DiskMax, v.Point.Load1
		}
		out.UptimeSeconds = v.Latest.GetUptimeSeconds()
	}
	return out
}

func agentProto(v *fleet.View) *apiv1.Agent {
	a := &v.Agent
	out := &apiv1.Agent{
		Summary: summaryProto(v), Facts: v.Facts, Policy: v.Policy, Features: a.Features, CertificateSerial: a.CertSerial,
		CertificateExpiresAt: ts(a.CertNotAfter), EnrolledAt: ts(a.EnrolledAt), EnrollmentTokenId: a.EnrollmentTokenID,
		RemoteIp: a.LastIP, RevokedAt: ts(a.RevokedAt), RevokedReason: a.RevokedReason,
	}
	if a.ApprovedBy != "" {
		kind := store.PrincipalUser
		if a.ApprovedBy == "auto-approval" {
			kind = store.PrincipalSystem
		}
		out.ApprovedBy = principalProto(store.PrincipalRef{Kind: kind, ID: a.ApprovedBy, Display: a.ApprovedByName})
	}
	if v.Online {
		out.ClockSkew = durationpb.New(v.ClockSkew)
		out.LatestMetrics = v.Latest
		out.RemoteIp = v.RemoteIP
	}
	return out
}

func filterFromProto(f *apiv1.AgentFilter) fleet.Filter {
	out := fleet.Filter{
		Query: f.GetQuery(), Tags: f.GetTags(), GroupIDs: f.GetGroupIds(), HasUpdates: f.GetHasUpdates(),
		HasSecurity: f.GetHasSecurityUpdates(), RebootRequired: f.GetRebootRequired(), OSIDs: f.GetOsIds(),
		IncludeRevoked: f.GetIncludeRevoked(),
	}
	on := slices.Contains(f.GetConnection(), apiv1.ConnectionState_CONNECTION_STATE_ONLINE)
	off := slices.Contains(f.GetConnection(), apiv1.ConnectionState_CONNECTION_STATE_OFFLINE)
	if on != off {
		out.Online = &on
	}
	if len(out.Query) > 256 {
		out.Query = out.Query[:256]
	}
	return out
}

var sortFields = map[apiv1.AgentSortField]fleet.SortField{
	apiv1.AgentSortField_AGENT_SORT_FIELD_NAME:      fleet.SortName,
	apiv1.AgentSortField_AGENT_SORT_FIELD_LAST_SEEN: fleet.SortLastSeen,
	apiv1.AgentSortField_AGENT_SORT_FIELD_CPU:       fleet.SortCPU,
	apiv1.AgentSortField_AGENT_SORT_FIELD_MEMORY:    fleet.SortMemory,
	apiv1.AgentSortField_AGENT_SORT_FIELD_DISK:      fleet.SortDisk,
	apiv1.AgentSortField_AGENT_SORT_FIELD_UPDATES:   fleet.SortUpdates,
	apiv1.AgentSortField_AGENT_SORT_FIELD_OS:        fleet.SortOS,
}

func viewable(p *authz.Principal) func(v *fleet.View) bool {
	return func(v *fleet.View) bool { return p.HasOnAgent(authz.FleetView, v.Ref()) }
}

// ListAgents implements FleetService.
func (s *FleetService) ListAgents(ctx context.Context, req *connect.Request[apiv1.ListAgentsRequest]) (*connect.Response[apiv1.ListAgentsResponse], error) {
	if _, err := s.D.Store(); err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	f := filterFromProto(m.GetFilter())
	allow := viewable(p)
	views := s.D.Fleet.All(p.OrgID, func(v *fleet.View) bool { return allow(v) && f.Matches(v) })
	fleet.Sort(views, sortFields[m.GetSortBy()], m.GetDescending())
	size := int(min(max(m.GetPage().GetPageSize(), 1), 500))
	if m.GetPage().GetPageSize() == 0 {
		size = 50
	}
	offset, _ := strconv.Atoi(m.GetPage().GetPageToken())
	offset = min(max(offset, 0), len(views))
	end := min(offset+size, len(views))
	out := &apiv1.ListAgentsResponse{Page: &apiv1.PageResponse{TotalSize: uint64(len(views))}}
	if end < len(views) {
		out.Page.NextPageToken = strconv.Itoa(end)
	}
	for i := offset; i < end; i++ {
		out.Agents = append(out.Agents, summaryProto(&views[i]))
	}
	return connect.NewResponse(out), nil
}

// GetAgent implements FleetService.
func (s *FleetService) GetAgent(ctx context.Context, req *connect.Request[apiv1.GetAgentRequest]) (*connect.Response[apiv1.GetAgentResponse], error) {
	_, v, err := s.D.agentFor(ctx, authz.FleetView, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.GetAgentResponse{Agent: agentProto(&v)}), nil
}

func (s *FleetService) checkGroup(ctx context.Context, st *store.Store, orgID, groupID string) error {
	if groupID == "" {
		return nil
	}
	if _, err := st.AgentGroups.Get(ctx, store.Tenant(orgID), groupID); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the group does not exist"))
	}
	return nil
}

// UpdateAgent implements FleetService.
func (s *FleetService) UpdateAgent(ctx context.Context, req *connect.Request[apiv1.UpdateAgentRequest]) (*connect.Response[apiv1.UpdateAgentResponse], error) {
	p, v, err := s.D.agentFor(ctx, authz.AgentsManage, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	st, _ := s.D.Store()
	m := req.Msg
	name, tags, group := v.Agent.Name, v.Agent.Tags, v.Agent.GroupID
	if m.Name != nil {
		if name, err = validate.DisplayText("name", m.GetName(), 100); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if m.Tags != nil {
		if tags, err = validate.Tags(m.GetTags().GetTags()); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if m.GroupId != nil {
		group = m.GetGroupId()
		if err := s.checkGroup(ctx, st, p.OrgID, group); err != nil {
			return nil, err
		}
	}
	// Re-tagging or regrouping must not widen the caller's own access to the agent (a scoped
	// role could otherwise move an agent into the scope of a more powerful binding).
	before := p.PermissionsOn(v.Ref())
	after := p.PermissionsOn(authz.AgentRef{ID: v.Agent.ID, GroupID: group, Tags: tags})
	for perm := range after {
		if !before[perm] {
			return nil, connect.NewError(connect.CodePermissionDenied,
				errors.New("this change would grant you additional permissions ("+perm+") on the agent"))
		}
	}
	nv, err := s.D.Fleet.Update(ctx, p.OrgID, v.Agent.ID, func(a *store.Agent) error {
		a.Name, a.Tags, a.GroupID = name, tags, group
		return nil
	})
	if err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "agent.updated", TargetType: "agent", TargetID: nv.Agent.ID, TargetDisplay: nv.Agent.Name,
		Details: map[string]string{"name": name, "tags": strings.Join(tags, ","), "group_id": group},
	})
	return connect.NewResponse(&apiv1.UpdateAgentResponse{Agent: summaryProto(&nv)}), nil
}

// RevokeAgent implements FleetService.
func (s *FleetService) RevokeAgent(ctx context.Context, req *connect.Request[apiv1.RevokeAgentRequest]) (*connect.Response[apiv1.RevokeAgentResponse], error) {
	p, v, err := s.D.agentFor(ctx, authz.AgentsRevoke, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	reason, err := validate.OptionalText("reason", req.Msg.GetReason(), 500)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if !v.Active() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the agent is already revoked"))
	}
	uninstall := "not requested"
	if req.Msg.GetUninstall() {
		uninstall = s.uninstall(ctx, p, v)
	}
	nv, err := s.D.Fleet.Revoke(ctx, p.OrgID, v.Agent.ID, reason)
	if err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "agent.revoked", TargetType: "agent", TargetID: v.Agent.ID, TargetDisplay: v.Agent.Name,
		Details: map[string]string{"reason": reason, "uninstall": uninstall},
	})
	return connect.NewResponse(&apiv1.RevokeAgentResponse{Agent: summaryProto(&nv)}), nil
}

// uninstall asks an online agent to remove itself before revocation and reports the outcome.
func (s *FleetService) uninstall(ctx context.Context, p *authz.Principal, v fleet.View) string {
	if !v.Online {
		return "skipped: agent offline"
	}
	if !v.Allows(agentv1.Capability_CAPABILITY_AGENT_UNINSTALL) {
		return "skipped: the owner policy does not allow remote uninstall"
	}
	rec, err := s.D.Dispatch.Submit(ctx, dispatch.Request{
		OrgID: p.OrgID, AgentID: v.Agent.ID, Issuer: p.Ref(), SourceIP: clientIP(ctx), TTL: time.Minute,
		Operation: &agentv1.Operation{Kind: &agentv1.Operation_AgentUninstall{AgentUninstall: &agentv1.AgentUninstall{}}},
	})
	if err != nil {
		return "failed: " + err.Error()
	}
	rec, _ = s.D.Dispatch.Wait(ctx, p.OrgID, rec.ID, 20*time.Second)
	return rec.State
}

// GetFleetSummary implements FleetService.
func (s *FleetService) GetFleetSummary(ctx context.Context, _ *connect.Request[apiv1.GetFleetSummaryRequest]) (*connect.Response[apiv1.GetFleetSummaryResponse], error) {
	if _, err := s.D.Store(); err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.GetFleetSummaryResponse{Summary: s.summary(p)}), nil
}

func (s *FleetService) summary(p *authz.Principal) *apiv1.FleetSummary {
	sum := fleet.Summarize(s.D.Fleet.All(p.OrgID, viewable(p)), s.D.Fleet.Pending(p.OrgID))
	u := func(n int) uint32 { return uint32(max(n, 0)) } //nolint:gosec // counts
	return &apiv1.FleetSummary{
		Total: u(sum.Total), Online: u(sum.Online), Offline: u(sum.Offline), PendingEnrollments: u(sum.Pending),
		AgentsWithUpdates: u(sum.WithUpdates), AgentsWithSecurityUpdates: u(sum.WithSecurity),
		AgentsRebootRequired: u(sum.RebootRequired), TotalUpdates: u(sum.TotalUpdates),
		TotalSecurityUpdates: u(sum.TotalSecurity), AgentsUnderPressure: u(sum.UnderPressure),
	}
}

// streamRecheck is how often long-lived streams re-validate the caller.
const streamRecheck = time.Minute

// refreshPrincipal re-validates a streaming caller: the session or API key must still be valid,
// and role bindings are re-resolved so scope and role changes apply to open streams. It returns
// nil when the caller is no longer authorized.
func (d *Deps) refreshPrincipal(ctx context.Context, p *authz.Principal) *authz.Principal {
	st := d.Holder.Get()
	if st == nil {
		return nil
	}
	now := time.Now()
	var fresh *authz.Principal
	switch {
	case p.Session != nil:
		s, err := st.Sessions.Get(ctx, store.System(), p.Session.ID)
		if err != nil || !now.Before(s.ExpiresAt) || s.Stage != store.SessionStageFull || s.ActiveOrgID != p.OrgID {
			return nil
		}
		u, err := st.Users.Get(ctx, store.System(), s.UserID)
		if err != nil || u.Disabled {
			return nil
		}
		if fresh, err = d.Resolver.ForUser(ctx, u, s); err != nil {
			return nil
		}
	case p.Kind == store.PrincipalAPIKey:
		k, err := st.APIKeys.Get(ctx, store.Tenant(p.OrgID), p.ID)
		if err != nil || !k.RevokedAt.IsZero() || (!k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt)) {
			return nil
		}
		if fresh, err = d.Resolver.ForAPIKey(ctx, k); err != nil {
			return nil
		}
	default:
		return nil
	}
	if fresh.OrgID != p.OrgID {
		return nil
	}
	return fresh
}

var errStreamAuth = connect.NewError(connect.CodeUnauthenticated, errors.New("the session ended"))

// WatchFleet implements FleetService.
func (s *FleetService) WatchFleet(ctx context.Context, req *connect.Request[apiv1.WatchFleetRequest], stream *connect.ServerStream[apiv1.WatchFleetResponse]) error {
	if _, err := s.D.Store(); err != nil {
		return err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return err
	}
	f := filterFromProto(req.Msg.GetFilter())
	match := func(v *fleet.View) bool { return p.HasOnAgent(authz.FleetView, v.Ref()) && f.Matches(v) }
	sub := s.D.Bus.Subscribe(bus.FleetTopic(p.OrgID), 4096)
	defer sub.Close()

	sent := map[string]bool{}
	snapshot := func() error {
		views := s.D.Fleet.All(p.OrgID, match)
		fleet.Sort(views, fleet.SortName, false)
		snap := &apiv1.FleetSnapshot{Summary: s.summary(p)}
		sent = map[string]bool{}
		for i := range views {
			snap.Agents = append(snap.Agents, summaryProto(&views[i]))
			sent[views[i].Agent.ID] = true
		}
		return stream.Send(&apiv1.WatchFleetResponse{Event: &apiv1.WatchFleetResponse_Snapshot{Snapshot: snap}})
	}
	if err := snapshot(); err != nil {
		return err
	}
	dropped := sub.Dropped()
	dirty := map[string]bool{}
	summaryDirty := false
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	recheck := time.NewTicker(streamRecheck)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-sub.C:
			if !ok {
				return nil
			}
			if ch, ok := msg.(fleet.Change); ok {
				summaryDirty = true
				if ch.AgentID != "" {
					dirty[ch.AgentID] = true
				}
			}
		case <-recheck.C:
			fresh := s.D.refreshPrincipal(ctx, p)
			if fresh == nil || !fresh.Has(authz.FleetView) {
				return errStreamAuth
			}
			changed := fresh.Fingerprint() != p.Fingerprint()
			p = fresh
			if changed { // roles or scopes changed: resend what the caller may now see
				if err := snapshot(); err != nil {
					return err
				}
				clear(dirty)
			}
		case <-flush.C:
			if d := sub.Dropped(); d != dropped {
				dropped = d
				clear(dirty)
				summaryDirty = false
				if err := snapshot(); err != nil {
					return err
				}
				continue
			}
			for id := range dirty {
				v, ok := s.D.Fleet.GetInOrg(p.OrgID, id)
				var ev *apiv1.WatchFleetResponse
				switch {
				case ok && match(&v):
					sent[id] = true
					ev = &apiv1.WatchFleetResponse{Event: &apiv1.WatchFleetResponse_Upsert{Upsert: summaryProto(&v)}}
				case sent[id]:
					delete(sent, id)
					ev = &apiv1.WatchFleetResponse{Event: &apiv1.WatchFleetResponse_Removed{Removed: id}}
				}
				if ev != nil {
					if err := stream.Send(ev); err != nil {
						return err
					}
				}
			}
			clear(dirty)
			if summaryDirty {
				summaryDirty = false
				if err := stream.Send(&apiv1.WatchFleetResponse{Event: &apiv1.WatchFleetResponse_Summary{Summary: s.summary(p)}}); err != nil {
					return err
				}
			}
		}
	}
}

// GetAgentInventory implements FleetService.
func (s *FleetService) GetAgentInventory(ctx context.Context, req *connect.Request[apiv1.GetAgentInventoryRequest]) (*connect.Response[apiv1.GetAgentInventoryResponse], error) {
	p, v, err := s.D.agentFor(ctx, authz.FleetView, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	if fleet.InventoryKindName(req.Msg.GetKind()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown inventory kind"))
	}
	r, err := s.D.Fleet.Inventory(ctx, p.OrgID, v.Agent.ID, req.Msg.GetKind())
	if err != nil {
		return nil, s.D.internal(err)
	}
	if r == nil {
		r = &agentv1.InventoryReport{Kind: req.Msg.GetKind()}
	}
	return connect.NewResponse(&apiv1.GetAgentInventoryResponse{Inventory: r}), nil
}

func groupProto(g *store.AgentGroup, count int) *apiv1.AgentGroup {
	out := &apiv1.AgentGroup{
		Id: g.ID, Name: g.Name, Description: g.Description, AgentCount: uint32(max(count, 0)), CreatedAt: ts(g.CreatedAt), //nolint:gosec // count
	}
	if g.MetricsIntervalSec > 0 {
		out.MetricsInterval = dur(g.MetricsIntervalSec)
	}
	return out
}

// ListGroups implements FleetService.
func (s *FleetService) ListGroups(ctx context.Context, _ *connect.Request[apiv1.ListGroupsRequest]) (*connect.Response[apiv1.ListGroupsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	groups, err := st.AgentGroups.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	slices.SortFunc(groups, func(a, b *store.AgentGroup) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	counts := s.D.Fleet.GroupCounts(p.OrgID)
	out := &apiv1.ListGroupsResponse{}
	for _, g := range groups {
		out.Groups = append(out.Groups, groupProto(g, counts[g.ID]))
	}
	return connect.NewResponse(out), nil
}

// requireGroupAdmin allows group management only with org-wide agents.manage: groups define
// permission scopes.
func requireGroupAdmin(ctx context.Context) (*authz.Principal, error) {
	p, err := authz.Require(ctx, authz.AgentsManage)
	if err != nil {
		return nil, err
	}
	if !p.AllAgents(authz.AgentsManage) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("managing groups requires agents.manage on all agents"))
	}
	return p, nil
}

func groupFields(name, description string, interval *durationpb.Duration) (string, string, int, error) {
	n, err := validate.DisplayText("name", name, 64)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInvalidArgument, err)
	}
	desc, err := validate.OptionalText("description", description, 500)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInvalidArgument, err)
	}
	sec := 0
	if interval != nil && interval.AsDuration() != 0 {
		if sec, err = boundSec(interval, 5*time.Second, 5*time.Minute, "metrics_interval"); err != nil {
			return "", "", 0, err
		}
	}
	return n, desc, sec, nil
}

func (s *FleetService) nameTaken(ctx context.Context, st *store.Store, orgID, name, exceptID string) (bool, error) {
	groups, err := st.AgentGroups.All(ctx, store.Tenant(orgID), store.Query{})
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(groups, func(g *store.AgentGroup) bool {
		return g.ID != exceptID && strings.EqualFold(g.Name, name)
	}), nil
}

// CreateGroup implements FleetService.
func (s *FleetService) CreateGroup(ctx context.Context, req *connect.Request[apiv1.CreateGroupRequest]) (*connect.Response[apiv1.CreateGroupResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := requireGroupAdmin(ctx)
	if err != nil {
		return nil, err
	}
	name, desc, sec, err := groupFields(req.Msg.GetName(), req.Msg.GetDescription(), req.Msg.GetMetricsInterval())
	if err != nil {
		return nil, err
	}
	if taken, err := s.nameTaken(ctx, st, p.OrgID, name, ""); err != nil {
		return nil, s.D.internal(err)
	} else if taken {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("a group with this name exists"))
	}
	now := time.Now().UTC()
	g := &store.AgentGroup{ID: store.NewID(), OrgID: p.OrgID, Name: name, Description: desc, MetricsIntervalSec: sec, CreatedAt: now, UpdatedAt: now}
	if err := st.AgentGroups.Create(ctx, store.Tenant(p.OrgID), g); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "group.created", TargetType: "agent_group", TargetID: g.ID, TargetDisplay: name})
	return connect.NewResponse(&apiv1.CreateGroupResponse{Group: groupProto(g, 0)}), nil
}

// UpdateGroup implements FleetService.
func (s *FleetService) UpdateGroup(ctx context.Context, req *connect.Request[apiv1.UpdateGroupRequest]) (*connect.Response[apiv1.UpdateGroupResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := requireGroupAdmin(ctx)
	if err != nil {
		return nil, err
	}
	g, err := st.AgentGroups.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetGroupId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	name, desc, sec, err := groupFields(req.Msg.GetName(), req.Msg.GetDescription(), req.Msg.GetMetricsInterval())
	if err != nil {
		return nil, err
	}
	if taken, err := s.nameTaken(ctx, st, p.OrgID, name, g.ID); err != nil {
		return nil, s.D.internal(err)
	} else if taken {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("a group with this name exists"))
	}
	g.Name, g.Description, g.MetricsIntervalSec, g.UpdatedAt = name, desc, sec, time.Now().UTC()
	if err := st.AgentGroups.Update(ctx, store.Tenant(p.OrgID), g); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "group.updated", TargetType: "agent_group", TargetID: g.ID, TargetDisplay: name})
	return connect.NewResponse(&apiv1.UpdateGroupResponse{Group: groupProto(g, s.D.Fleet.GroupCounts(p.OrgID)[g.ID])}), nil
}

// DeleteGroup implements FleetService.
func (s *FleetService) DeleteGroup(ctx context.Context, req *connect.Request[apiv1.DeleteGroupRequest]) (*connect.Response[apiv1.DeleteGroupResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := requireGroupAdmin(ctx)
	if err != nil {
		return nil, err
	}
	g, err := st.AgentGroups.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetGroupId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	if n := s.D.Fleet.GroupCounts(p.OrgID)[g.ID]; n > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("move the group's "+strconv.Itoa(n)+" agents to another group first"))
	}
	if err := st.AgentGroups.Delete(ctx, store.Tenant(p.OrgID), g.ID); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "group.deleted", TargetType: "agent_group", TargetID: g.ID, TargetDisplay: g.Name})
	return connect.NewResponse(&apiv1.DeleteGroupResponse{}), nil
}

// ---- Metrics ----

var resolutions = map[apiv1.MetricsResolution]metrics.Resolution{
	apiv1.MetricsResolution_METRICS_RESOLUTION_UNSPECIFIED: metrics.Auto,
	apiv1.MetricsResolution_METRICS_RESOLUTION_RAW:         metrics.Raw,
	apiv1.MetricsResolution_METRICS_RESOLUTION_MINUTE:      metrics.Minute,
	apiv1.MetricsResolution_METRICS_RESOLUTION_HOUR:        metrics.Hour,
}

func resolutionProto(r metrics.Resolution) apiv1.MetricsResolution {
	for k, v := range resolutions {
		if v == r && k != apiv1.MetricsResolution_METRICS_RESOLUTION_UNSPECIFIED {
			return k
		}
	}
	return apiv1.MetricsResolution_METRICS_RESOLUTION_UNSPECIFIED
}

// GetAgentMetrics implements MetricsService.
func (s *MetricsService) GetAgentMetrics(ctx context.Context, req *connect.Request[apiv1.GetAgentMetricsRequest]) (*connect.Response[apiv1.GetAgentMetricsResponse], error) {
	p, v, err := s.D.agentFor(ctx, authz.FleetView, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	m := req.Msg
	var start, end time.Time
	if m.GetStart() != nil {
		start = m.GetStart().AsTime()
	}
	if m.GetEnd() != nil {
		end = m.GetEnd().AsTime()
	}
	res, ok := resolutions[m.GetResolution()]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown resolution"))
	}
	used, points, err := s.D.Fleet.Metrics().Series(ctx, p.OrgID, v.Agent.ID, start, end, res)
	if err != nil {
		if errors.Is(err, store.ErrUnavailable) {
			return nil, s.D.internal(err)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	series := &apiv1.MetricSeries{Resolution: resolutionProto(used)}
	for _, pt := range points {
		series.TimestampsMs = append(series.TimestampsMs, pt.T)
		series.CpuPercent = append(series.CpuPercent, pt.CPU)
		series.CpuPercentMax = append(series.CpuPercentMax, pt.CPUMax)
		series.MemoryUsedPercent = append(series.MemoryUsedPercent, pt.Mem)
		series.SwapUsedPercent = append(series.SwapUsedPercent, pt.Swap)
		series.Load1 = append(series.Load1, pt.Load1)
		series.DiskUsedPercentMax = append(series.DiskUsedPercentMax, pt.DiskMax)
		series.DiskReadBytesPerSecond = append(series.DiskReadBytesPerSecond, pt.DiskRead)
		series.DiskWriteBytesPerSecond = append(series.DiskWriteBytesPerSecond, pt.DiskWrite)
		series.NetRxBytesPerSecond = append(series.NetRxBytesPerSecond, pt.NetRx)
		series.NetTxBytesPerSecond = append(series.NetTxBytesPerSecond, pt.NetTx)
	}
	return connect.NewResponse(&apiv1.GetAgentMetricsResponse{Series: series}), nil
}

// WatchAgentMetrics implements MetricsService.
func (s *MetricsService) WatchAgentMetrics(ctx context.Context, req *connect.Request[apiv1.WatchAgentMetricsRequest], stream *connect.ServerStream[apiv1.WatchAgentMetricsResponse]) error {
	p, v, err := s.D.agentFor(ctx, authz.FleetView, req.Msg.GetAgentId())
	if err != nil {
		return err
	}
	sub := s.D.Bus.Subscribe(bus.AgentMetricsTopic(v.Agent.ID), 64)
	defer sub.Close()
	if v.Latest != nil {
		if err := stream.Send(&apiv1.WatchAgentMetricsResponse{Sample: v.Latest}); err != nil {
			return err
		}
	}
	recheck := time.NewTicker(streamRecheck)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-recheck.C:
			if p = s.D.refreshPrincipal(ctx, p); p == nil {
				return errStreamAuth
			}
			if cur, ok := s.D.Fleet.GetInOrg(p.OrgID, v.Agent.ID); !ok || !p.HasOnAgent(authz.FleetView, cur.Ref()) {
				return errAgentNotFound
			}
		case msg, ok := <-sub.C:
			if !ok {
				return nil
			}
			if sample, ok := msg.(*agentv1.MetricsSample); ok {
				if err := stream.Send(&apiv1.WatchAgentMetricsResponse{Sample: sample}); err != nil {
					return err
				}
			}
		}
	}
}
