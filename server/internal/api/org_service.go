// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/validate"
)

// OrgService implements OrganizationService, MemberService, RoleService and ApiKeyService.
type OrgService struct {
	apiv1connect.UnimplementedOrganizationServiceHandler
	D *Deps
}

// MemberService implements MemberService.
type MemberService struct {
	apiv1connect.UnimplementedMemberServiceHandler
	D *Deps
}

// RoleService implements RoleService.
type RoleService struct {
	apiv1connect.UnimplementedRoleServiceHandler
	D *Deps
}

// APIKeyService implements ApiKeyService.
type APIKeyService struct {
	apiv1connect.UnimplementedApiKeyServiceHandler
	D *Deps
}

func dur(sec int) *durationpb.Duration { return durationpb.New(time.Duration(sec) * time.Second) }

func orgProto(o *store.Org) *apiv1.Organization {
	s := o.Settings
	return &apiv1.Organization{
		Id: o.ID, Name: o.Name, CreatedAt: ts(o.CreatedAt),
		Settings: &apiv1.OrganizationSettings{
			MetricsInterval:            dur(s.MetricsIntervalSec),
			SessionIdleTimeout:         dur(s.SessionIdleTimeoutSec),
			SessionMaxLifetime:         dur(s.SessionMaxLifetimeSec),
			StepUpWindow:               dur(s.StepUpWindowSec),
			MassActionConfirmThreshold: uint32(max(s.MassActionConfirmThreshold, 0)), //nolint:gosec // bounded
			AuditRetention:             dur(s.AuditRetentionDays * 86400),
			MetricsRetention:           dur(s.MetricsRetentionDays * 86400),
			RecordingRetention:         dur(s.RecordingRetentionDays * 86400),
			RecordTerminalSessions:     s.RecordTerminalSessions,
		},
	}
}

// GetOrganization implements OrganizationService.
func (s *OrgService) GetOrganization(ctx context.Context, _ *connect.Request[apiv1.GetOrganizationRequest]) (*connect.Response[apiv1.GetOrganizationResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	org, err := st.Orgs.Get(ctx, store.System(), p.OrgID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	return connect.NewResponse(&apiv1.GetOrganizationResponse{Organization: orgProto(org)}), nil
}

func boundSec(d *durationpb.Duration, lo, hi time.Duration, field string) (int, error) {
	if d == nil {
		return 0, nil
	}
	v := d.AsDuration()
	if v < lo || v > hi {
		return 0, fmt.Errorf("%s must be between %s and %s", field, lo, hi)
	}
	return int(v.Seconds()), nil
}

// UpdateOrganization implements OrganizationService.
func (s *OrgService) UpdateOrganization(ctx context.Context, req *connect.Request[apiv1.UpdateOrganizationRequest]) (*connect.Response[apiv1.UpdateOrganizationResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.OrgSettings)
	if err != nil {
		return nil, err
	}
	org, err := st.Orgs.Get(ctx, store.System(), p.OrgID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	if name := req.Msg.GetName(); name != "" {
		if org.Name, err = validate.DisplayText("name", name, 100); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if in := req.Msg.GetSettings(); in != nil {
		cur := &org.Settings
		type rule struct {
			d      *durationpb.Duration
			lo, hi time.Duration
			name   string
			dst    *int
			days   bool
		}
		day := 24 * time.Hour
		for _, r := range []rule{
			{in.GetMetricsInterval(), 5 * time.Second, 5 * time.Minute, "metrics interval", &cur.MetricsIntervalSec, false},
			{in.GetSessionIdleTimeout(), 5 * time.Minute, 8 * time.Hour, "session idle timeout", &cur.SessionIdleTimeoutSec, false},
			{in.GetSessionMaxLifetime(), time.Hour, 7 * day, "session lifetime", &cur.SessionMaxLifetimeSec, false},
			{in.GetStepUpWindow(), time.Minute, 30 * time.Minute, "step-up window", &cur.StepUpWindowSec, false},
			{in.GetAuditRetention(), 90 * day, 10 * 365 * day, "audit retention", &cur.AuditRetentionDays, true},
			{in.GetMetricsRetention(), day, 400 * day, "metrics retention", &cur.MetricsRetentionDays, true},
			{in.GetRecordingRetention(), day, 3650 * day, "recording retention", &cur.RecordingRetentionDays, true},
		} {
			v, err := boundSec(r.d, r.lo, r.hi, r.name)
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, err)
			}
			if r.d == nil {
				continue
			}
			if r.days {
				v /= 86400
			}
			*r.dst = v
		}
		if t := in.GetMassActionConfirmThreshold(); t > 0 {
			cur.MassActionConfirmThreshold = int(min(t, 100000))
		}
		cur.RecordTerminalSessions = in.GetRecordTerminalSessions()
	}
	org.UpdatedAt = time.Now().UTC()
	if err := st.Orgs.Update(ctx, store.System(), org); err != nil {
		return nil, s.D.internal(err)
	}
	s.D.Resolver.Invalidate()
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "org.settings_updated", TargetType: "org", TargetID: org.ID, TargetDisplay: org.Name})
	return connect.NewResponse(&apiv1.UpdateOrganizationResponse{Organization: orgProto(org)}), nil
}

// --- members -------------------------------------------------------------------------------

func scopeFromProto(sc *apiv1.AgentScope) (store.AgentScopeSpec, error) {
	if sc == nil || sc.GetAllAgents() {
		return store.AgentScopeSpec{AllAgents: true}, nil
	}
	tags, err := validate.Tags(sc.GetTags())
	if err != nil {
		return store.AgentScopeSpec{}, err
	}
	for _, g := range sc.GetGroupIds() {
		if err := validate.ID("group_id", g); err != nil {
			return store.AgentScopeSpec{}, err
		}
	}
	out := store.AgentScopeSpec{GroupIDs: sc.GetGroupIds(), Tags: tags}
	if out.IsAll() {
		out.AllAgents = true
	}
	return out, nil
}

func scopeProto(s store.AgentScopeSpec) *apiv1.AgentScope {
	return &apiv1.AgentScope{AllAgents: s.IsAll(), GroupIds: s.GroupIDs, Tags: s.Tags}
}

// bindingsFromProto validates role bindings. Only owners may grant the owner role.
func bindingsFromProto(ctx context.Context, st *store.Store, p *authz.Principal, in []*apiv1.RoleBinding) ([]store.RoleBinding, error) {
	if len(in) == 0 || len(in) > 16 {
		return nil, errors.New("between 1 and 16 role bindings are required")
	}
	isOwner := p.Has(authz.SystemKeyExport) // only owners hold key export
	var out []store.RoleBinding
	for _, b := range in {
		id := b.GetRoleId()
		if _, ok := authz.Builtin(id); !ok {
			if _, err := st.Roles.Get(ctx, store.Tenant(p.OrgID), id); err != nil {
				return nil, fmt.Errorf("unknown role %q", id)
			}
		}
		if id == authz.RoleOwner && !isOwner {
			return nil, errors.New("only owners can grant the owner role")
		}
		sc, err := scopeFromProto(b.GetScope())
		if err != nil {
			return nil, err
		}
		if (id == authz.RoleOwner || id == authz.RoleAdmin) && !sc.IsAll() {
			// Org-wide roles carry organization permissions that cannot be limited to agents;
			// refuse instead of silently widening the requested scope.
			return nil, fmt.Errorf("the %s role applies to the whole organization and cannot be limited to agents", id)
		}
		out = append(out, store.RoleBinding{RoleID: id, Scope: sc})
	}
	return out, nil
}

func bindingsProto(ctx context.Context, st *store.Store, orgID string, in []store.RoleBinding) []*apiv1.RoleBinding {
	var out []*apiv1.RoleBinding
	for _, b := range in {
		name := b.RoleID
		if r, ok := authz.Builtin(b.RoleID); ok {
			name = r.Name
		} else if role, err := st.Roles.Get(ctx, store.Tenant(orgID), b.RoleID); err == nil {
			name = role.Name
		}
		out = append(out, &apiv1.RoleBinding{RoleId: b.RoleID, RoleName: name, Scope: scopeProto(b.Scope)})
	}
	return out
}

// ListMembers implements MemberService.
func (s *MemberService) ListMembers(ctx context.Context, req *connect.Request[apiv1.ListMembersRequest]) (*connect.Response[apiv1.ListMembersResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	ms, err := st.Memberships.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	q := strings.ToLower(strings.TrimSpace(req.Msg.GetQuery()))
	out := &apiv1.ListMembersResponse{Page: &apiv1.PageResponse{}}
	for _, m := range ms {
		u, err := st.Users.Get(ctx, store.System(), m.UserID)
		if err != nil {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(u.Email+" "+u.DisplayName), q) {
			continue
		}
		mfa, _ := st.MFA.Count(ctx, store.System(), store.Eq("user_id", u.ID))
		out.Members = append(out.Members, &apiv1.Member{
			User: userProto(u, mfa > 0), RoleBindings: bindingsProto(ctx, st, p.OrgID, m.RoleBindings), JoinedAt: ts(m.JoinedAt),
		})
	}
	out.Page.TotalSize = uint64(len(out.Members))
	return connect.NewResponse(out), nil
}

// InviteMember implements MemberService.
func (s *MemberService) InviteMember(ctx context.Context, req *connect.Request[apiv1.InviteMemberRequest]) (*connect.Response[apiv1.InviteMemberResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.MembersManage)
	if err != nil {
		return nil, err
	}
	email, err := validate.Email(req.Msg.GetEmail())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	bindings, err := bindingsFromProto(ctx, st, p, req.Msg.GetRoleBindings())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	validity := 72 * time.Hour
	if d := req.Msg.GetExpiresIn(); d != nil {
		validity = min(max(d.AsDuration(), time.Hour), 14*24*time.Hour)
	}
	if u, err := st.Users.FindOne(ctx, store.System(), store.Eq("email", email)); err == nil {
		if _, err := st.Memberships.Get(ctx, store.Tenant(p.OrgID), store.DeriveID(p.OrgID, u.ID)); err == nil {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("this person is already a member"))
		}
	}
	secret := crypto.RandomToken(32)
	now := time.Now().UTC()
	inv := &store.Invite{
		ID: store.NewID(), OrgID: p.OrgID, Email: email, TokenHash: crypto.HashToken("invite", secret),
		RoleBindings: bindings, CreatedBy: p.ID, CreatedAt: now, ExpiresAt: now.Add(validity),
	}
	if err := st.Invites.Create(ctx, store.Tenant(p.OrgID), inv); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "member.invited", TargetType: "invite", TargetID: inv.ID, TargetDisplay: email})
	// The token travels in the URL fragment, which browsers never send to servers or proxies.
	link := strings.TrimRight(s.D.PublicURL(ctx), "/") + "/invite#" + InvitePrefix + inv.ID + "." + secret
	return connect.NewResponse(&apiv1.InviteMemberResponse{Invite: inviteProto(ctx, st, inv), InviteUrl: link}), nil
}

func inviteProto(ctx context.Context, st *store.Store, inv *store.Invite) *apiv1.Invite {
	return &apiv1.Invite{
		Id: inv.ID, Email: inv.Email, RoleBindings: bindingsProto(ctx, st, inv.OrgID, inv.RoleBindings),
		CreatedBy: &apiv1.PrincipalRef{Kind: apiv1.PrincipalRef_KIND_USER, Id: inv.CreatedBy},
		CreatedAt: ts(inv.CreatedAt), ExpiresAt: ts(inv.ExpiresAt),
	}
}

// ListInvites implements MemberService.
func (s *MemberService) ListInvites(ctx context.Context, _ *connect.Request[apiv1.ListInvitesRequest]) (*connect.Response[apiv1.ListInvitesResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.MembersManage)
	if err != nil {
		return nil, err
	}
	invs, err := st.Invites.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListInvitesResponse{}
	now := time.Now()
	for _, inv := range invs {
		if inv.AcceptedAt.IsZero() && inv.RevokedAt.IsZero() && now.Before(inv.ExpiresAt) {
			out.Invites = append(out.Invites, inviteProto(ctx, st, inv))
		}
	}
	return connect.NewResponse(out), nil
}

// RevokeInvite implements MemberService.
func (s *MemberService) RevokeInvite(ctx context.Context, req *connect.Request[apiv1.RevokeInviteRequest]) (*connect.Response[apiv1.RevokeInviteResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.MembersManage)
	if err != nil {
		return nil, err
	}
	inv, err := st.Invites.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetInviteId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("invite not found"))
	}
	inv.RevokedAt = time.Now().UTC()
	if err := st.Invites.Update(ctx, store.Tenant(p.OrgID), inv); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "member.invite_revoked", TargetType: "invite", TargetID: inv.ID, TargetDisplay: inv.Email})
	return connect.NewResponse(&apiv1.RevokeInviteResponse{}), nil
}

func ownersOf(ms []*store.Membership) []string {
	var out []string
	for _, m := range ms {
		for _, b := range m.RoleBindings {
			if b.RoleID == authz.RoleOwner {
				out = append(out, m.UserID)
				break
			}
		}
	}
	return out
}

// UpdateMember implements MemberService.
func (s *MemberService) UpdateMember(ctx context.Context, req *connect.Request[apiv1.UpdateMemberRequest]) (*connect.Response[apiv1.UpdateMemberResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.MembersManage)
	if err != nil {
		return nil, err
	}
	m, err := st.Memberships.Get(ctx, store.Tenant(p.OrgID), store.DeriveID(p.OrgID, req.Msg.GetUserId()))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("member not found"))
	}
	bindings, err := bindingsFromProto(ctx, st, p, req.Msg.GetRoleBindings())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	all, err := st.Memberships.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	wasOwner := slices.Contains(ownersOf([]*store.Membership{m}), m.UserID)
	stillOwner := slices.ContainsFunc(bindings, func(b store.RoleBinding) bool { return b.RoleID == authz.RoleOwner })
	if wasOwner && !p.Has(authz.SystemKeyExport) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only owners can change an owner's roles"))
	}
	if wasOwner && !stillOwner && len(ownersOf(all)) <= 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("an organization must keep at least one owner"))
	}
	m.RoleBindings = bindings
	if err := st.Memberships.Update(ctx, store.Tenant(p.OrgID), m); err != nil {
		return nil, s.D.internal(err)
	}
	s.D.Resolver.Invalidate()
	u, _ := st.Users.Get(ctx, store.System(), m.UserID)
	display := m.UserID
	if u != nil {
		display = u.Email
	}
	roles := make([]string, 0, len(bindings))
	for _, b := range bindings {
		roles = append(roles, b.RoleID)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "member.roles_changed", TargetType: "user", TargetID: m.UserID,
		TargetDisplay: display, Details: map[string]string{"roles": strings.Join(roles, ",")},
	})
	mfa := 0
	if u != nil {
		mfa, _ = st.MFA.Count(ctx, store.System(), store.Eq("user_id", u.ID))
	} else {
		u = &store.User{ID: m.UserID}
	}
	return connect.NewResponse(&apiv1.UpdateMemberResponse{Member: &apiv1.Member{
		User: userProto(u, mfa > 0), RoleBindings: bindingsProto(ctx, st, p.OrgID, m.RoleBindings), JoinedAt: ts(m.JoinedAt),
	}}), nil
}

// RemoveMember implements MemberService.
func (s *MemberService) RemoveMember(ctx context.Context, req *connect.Request[apiv1.RemoveMemberRequest]) (*connect.Response[apiv1.RemoveMemberResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.MembersManage)
	if err != nil {
		return nil, err
	}
	m, err := st.Memberships.Get(ctx, store.Tenant(p.OrgID), store.DeriveID(p.OrgID, req.Msg.GetUserId()))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("member not found"))
	}
	all, err := st.Memberships.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	if slices.Contains(ownersOf([]*store.Membership{m}), m.UserID) {
		if !p.Has(authz.SystemKeyExport) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only owners can remove an owner"))
		}
		if len(ownersOf(all)) <= 1 {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("an organization must keep at least one owner"))
		}
	}
	if err := st.Memberships.Delete(ctx, store.Tenant(p.OrgID), m.ID); err != nil {
		return nil, s.D.internal(err)
	}
	s.D.Resolver.Invalidate()
	// Sessions with this org active lose access immediately (the resolver finds no membership).
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "member.removed", TargetType: "user", TargetID: m.UserID})
	return connect.NewResponse(&apiv1.RemoveMemberResponse{}), nil
}

// --- roles ---------------------------------------------------------------------------------

// ListRoles implements RoleService.
func (s *RoleService) ListRoles(ctx context.Context, _ *connect.Request[apiv1.ListRolesRequest]) (*connect.Response[apiv1.ListRolesResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	out := &apiv1.ListRolesResponse{}
	for _, r := range authz.BuiltinRoles {
		out.Roles = append(out.Roles, &apiv1.Role{Id: r.ID, Name: r.Name, Description: r.Description, Builtin: true, Permissions: r.Permissions})
	}
	custom, err := st.Roles.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	for _, r := range custom {
		out.Roles = append(out.Roles, &apiv1.Role{Id: r.ID, Name: r.Name, Description: r.Description, Permissions: r.Permissions})
	}
	return connect.NewResponse(out), nil
}

// ListPermissions implements RoleService.
func (s *RoleService) ListPermissions(ctx context.Context, _ *connect.Request[apiv1.ListPermissionsRequest]) (*connect.Response[apiv1.ListPermissionsResponse], error) {
	if _, err := authz.Require(ctx, authz.FleetView); err != nil {
		return nil, err
	}
	out := &apiv1.ListPermissionsResponse{}
	for _, pi := range authz.Catalog {
		out.Permissions = append(out.Permissions, &apiv1.Permission{
			Name: pi.Name, Description: pi.Description, Category: pi.Category, RequiresStepUp: pi.StepUp, AgentScoped: pi.AgentScoped,
		})
	}
	return connect.NewResponse(out), nil
}

// --- API keys ------------------------------------------------------------------------------

func apiKeyProto(ctx context.Context, st *store.Store, k *store.APIKey) *apiv1.ApiKey {
	b := bindingsProto(ctx, st, k.OrgID, []store.RoleBinding{k.RoleBinding})
	var rb *apiv1.RoleBinding
	if len(b) > 0 {
		rb = b[0]
	}
	return &apiv1.ApiKey{
		Id: k.ID, Name: k.Name, Prefix: k.Prefix, RoleBinding: rb,
		CreatedBy: &apiv1.PrincipalRef{Kind: apiv1.PrincipalRef_KIND_USER, Id: k.CreatedBy},
		CreatedAt: ts(k.CreatedAt), ExpiresAt: ts(k.ExpiresAt), LastUsedAt: ts(k.LastUsedAt), RevokedAt: ts(k.RevokedAt),
	}
}

// CreateApiKey implements ApiKeyService.
func (s *APIKeyService) CreateApiKey(ctx context.Context, req *connect.Request[apiv1.CreateApiKeyRequest]) (*connect.Response[apiv1.CreateApiKeyResponse], error) { //nolint:revive // generated name
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.APIKeysManage)
	if err != nil {
		return nil, err
	}
	name, err := validate.DisplayText("name", req.Msg.GetName(), 64)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	bindings, err := bindingsFromProto(ctx, st, p, []*apiv1.RoleBinding{req.Msg.GetRoleBinding()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if bindings[0].RoleID == authz.RoleOwner {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("API keys cannot have the owner role"))
	}
	validity := 90 * 24 * time.Hour
	if d := req.Msg.GetExpiresIn(); d != nil {
		validity = min(max(d.AsDuration(), time.Hour), 365*24*time.Hour)
	}
	id := store.NewID()
	secret := crypto.RandomToken(32)
	now := time.Now().UTC()
	k := &store.APIKey{
		ID: id, OrgID: p.OrgID, Name: name, Prefix: APIKeyPrefix + id[:8], SecretHash: crypto.HashToken("api_key", secret),
		RoleBinding: bindings[0], CreatedBy: p.ID, CreatedAt: now, ExpiresAt: now.Add(validity),
	}
	if err := st.APIKeys.Create(ctx, store.Tenant(p.OrgID), k); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "apikey.created", TargetType: "api_key", TargetID: k.ID, TargetDisplay: name,
		Details: map[string]string{"role": k.RoleBinding.RoleID},
	})
	return connect.NewResponse(&apiv1.CreateApiKeyResponse{ApiKey: apiKeyProto(ctx, st, k), Secret: APIKeyPrefix + id + "." + secret}), nil
}

// ListApiKeys implements ApiKeyService.
func (s *APIKeyService) ListApiKeys(ctx context.Context, _ *connect.Request[apiv1.ListApiKeysRequest]) (*connect.Response[apiv1.ListApiKeysResponse], error) { //nolint:revive // generated name
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.APIKeysManage)
	if err != nil {
		return nil, err
	}
	keys, err := st.APIKeys.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListApiKeysResponse{}
	for _, k := range keys {
		out.ApiKeys = append(out.ApiKeys, apiKeyProto(ctx, st, k))
	}
	return connect.NewResponse(out), nil
}

// RevokeApiKey implements ApiKeyService.
func (s *APIKeyService) RevokeApiKey(ctx context.Context, req *connect.Request[apiv1.RevokeApiKeyRequest]) (*connect.Response[apiv1.RevokeApiKeyResponse], error) { //nolint:revive // generated name
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.APIKeysManage)
	if err != nil {
		return nil, err
	}
	k, err := st.APIKeys.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetApiKeyId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("API key not found"))
	}
	k.RevokedAt = time.Now().UTC()
	if err := st.APIKeys.Update(ctx, store.Tenant(p.OrgID), k); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "apikey.revoked", TargetType: "api_key", TargetID: k.ID, TargetDisplay: k.Name})
	return connect.NewResponse(&apiv1.RevokeApiKeyResponse{}), nil
}
