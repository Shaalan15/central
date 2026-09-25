// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/store"
)

// EnrollmentAdminService implements EnrollmentAdminService.
type EnrollmentAdminService struct {
	apiv1connect.UnimplementedEnrollmentAdminServiceHandler
	D *Deps
}

func approvalProto(m string) apiv1.ApprovalMode {
	if m == store.ApprovalAuto {
		return apiv1.ApprovalMode_APPROVAL_MODE_AUTO
	}
	return apiv1.ApprovalMode_APPROVAL_MODE_MANUAL
}

func tokenStateProto(s string) apiv1.EnrollmentTokenState {
	switch s {
	case enrollment.TokenActive:
		return apiv1.EnrollmentTokenState_ENROLLMENT_TOKEN_STATE_ACTIVE
	case enrollment.TokenExpired:
		return apiv1.EnrollmentTokenState_ENROLLMENT_TOKEN_STATE_EXPIRED
	case enrollment.TokenExhausted:
		return apiv1.EnrollmentTokenState_ENROLLMENT_TOKEN_STATE_EXHAUSTED
	case enrollment.TokenRevoked:
		return apiv1.EnrollmentTokenState_ENROLLMENT_TOKEN_STATE_REVOKED
	}
	return apiv1.EnrollmentTokenState_ENROLLMENT_TOKEN_STATE_UNSPECIFIED
}

// userRef resolves a user ID to a principal reference (display = email).
func userRef(ctx context.Context, st *store.Store, id string) *apiv1.PrincipalRef {
	if id == "" {
		return nil
	}
	ref := store.PrincipalRef{Kind: store.PrincipalUser, ID: id}
	if u, err := st.Users.Get(ctx, store.System(), id); err == nil {
		ref.Display = u.Email
	}
	return principalProto(ref)
}

func tokenProto(ctx context.Context, st *store.Store, t *store.EnrollmentToken) *apiv1.EnrollmentToken {
	return &apiv1.EnrollmentToken{
		Id: t.ID, Name: t.Name, State: tokenStateProto(enrollment.TokenState(t, time.Now())),
		ApprovalMode: approvalProto(t.ApprovalMode), MaxUses: uint32(max(t.MaxUses, 0)), Uses: uint32(max(t.Uses, 0)), //nolint:gosec // bounded
		AllowedCidrs: t.AllowedCIDRs, HostnamePattern: t.HostnamePattern, DefaultTags: t.DefaultTags,
		DefaultGroupId: t.DefaultGroupID, CreatedBy: userRef(ctx, st, t.CreatedBy), CreatedAt: ts(t.CreatedAt),
		ExpiresAt: ts(t.ExpiresAt), LastUsedAt: ts(t.LastUsedAt), RevokedAt: ts(t.RevokedAt),
	}
}

// InstallCommand is the suggested one-liner for Ubuntu/Debian hosts. The key is never on the
// command line: the installer prompts for it (or reads it from stdin with --key-file -).
func InstallCommand(publicURL, agentURL string) string {
	base := strings.TrimRight(publicURL, "/")
	return "curl -fsSLo install-agent.sh '" + base + "/install-agent.sh' && sudo bash install-agent.sh --url '" + agentURL + "'"
}

// CreateEnrollmentToken implements EnrollmentAdminService.
func (s *EnrollmentAdminService) CreateEnrollmentToken(ctx context.Context, req *connect.Request[apiv1.CreateEnrollmentTokenRequest]) (*connect.Response[apiv1.CreateEnrollmentTokenResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.TokensManage)
	if err != nil {
		return nil, err
	}
	agentURL := s.D.AgentURL(ctx)
	if agentURL == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("configure the agent URL first (Settings → System)"))
	}
	m := req.Msg
	mode := store.ApprovalManual
	if m.GetApprovalMode() == apiv1.ApprovalMode_APPROVAL_MODE_AUTO {
		mode = store.ApprovalAuto
	}
	t, key, err := s.D.Enroll.CreateToken(ctx, p.OrgID, p.Ref(), enrollment.TokenSpec{
		Name: m.GetName(), ApprovalMode: mode, MaxUses: int(m.GetMaxUses()), ExpiresIn: m.GetExpiresIn().AsDuration(),
		AllowedCIDRs: m.GetAllowedCidrs(), HostnamePattern: m.GetHostnamePattern(), DefaultTags: m.GetDefaultTags(),
		DefaultGroupID: m.GetDefaultGroupId(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.CreateEnrollmentTokenResponse{
		Token: tokenProto(ctx, st, t), EnrollmentKey: key, AgentUrl: agentURL,
		InstallCommand: InstallCommand(s.D.PublicURL(ctx), agentURL),
	}), nil
}

// ListEnrollmentTokens implements EnrollmentAdminService.
func (s *EnrollmentAdminService) ListEnrollmentTokens(ctx context.Context, req *connect.Request[apiv1.ListEnrollmentTokensRequest]) (*connect.Response[apiv1.ListEnrollmentTokensResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.RequireHeld(ctx, authz.TokensManage)
	if err != nil {
		return nil, err
	}
	tokens, err := st.EnrollmentTokens.All(ctx, store.Tenant(p.OrgID), store.Query{})
	if err != nil {
		return nil, s.D.internal(err)
	}
	slices.SortFunc(tokens, func(a, b *store.EnrollmentToken) int { return b.CreatedAt.Compare(a.CreatedAt) })
	out := &apiv1.ListEnrollmentTokensResponse{}
	now := time.Now()
	for _, t := range tokens {
		if !req.Msg.GetIncludeInactive() && enrollment.TokenState(t, now) != enrollment.TokenActive {
			continue
		}
		out.Tokens = append(out.Tokens, tokenProto(ctx, st, t))
	}
	return connect.NewResponse(out), nil
}

// RevokeEnrollmentToken implements EnrollmentAdminService.
func (s *EnrollmentAdminService) RevokeEnrollmentToken(ctx context.Context, req *connect.Request[apiv1.RevokeEnrollmentTokenRequest]) (*connect.Response[apiv1.RevokeEnrollmentTokenResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.TokensManage)
	if err != nil {
		return nil, err
	}
	if !enrollment.ValidTokenID(req.Msg.GetTokenId()) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
	}
	t, err := s.D.Enroll.RevokeToken(ctx, p.OrgID, req.Msg.GetTokenId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.RevokeEnrollmentTokenResponse{Token: tokenProto(ctx, st, t)}), nil
}

func requestStatusProto(s string) apiv1.EnrollmentRequestStatus {
	switch s {
	case store.EnrollmentPending:
		return apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_PENDING
	case store.EnrollmentApproved:
		return apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_APPROVED
	case store.EnrollmentDenied:
		return apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_DENIED
	case store.EnrollmentExpired:
		return apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_EXPIRED
	}
	return apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_UNSPECIFIED
}

func requestStatusName(s apiv1.EnrollmentRequestStatus) string {
	switch s {
	case apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_PENDING:
		return store.EnrollmentPending
	case apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_APPROVED:
		return store.EnrollmentApproved
	case apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_DENIED:
		return store.EnrollmentDenied
	case apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_EXPIRED:
		return store.EnrollmentExpired
	case apiv1.EnrollmentRequestStatus_ENROLLMENT_REQUEST_STATUS_UNSPECIFIED:
	}
	return ""
}

func severityProto(s string) apiv1.RiskSeverity {
	switch s {
	case enrollment.SeverityInfo:
		return apiv1.RiskSeverity_RISK_SEVERITY_INFO
	case enrollment.SeverityWarning:
		return apiv1.RiskSeverity_RISK_SEVERITY_WARNING
	case enrollment.SeverityCritical:
		return apiv1.RiskSeverity_RISK_SEVERITY_CRITICAL
	}
	return apiv1.RiskSeverity_RISK_SEVERITY_UNSPECIFIED
}

func requestProto(r *store.EnrollmentRequest, tokenName string) *apiv1.EnrollmentRequest {
	facts := &agentv1.HostFacts{}
	_ = proto.Unmarshal(r.FactsProto, facts)
	out := &apiv1.EnrollmentRequest{
		Id: r.ID, Status: requestStatusProto(r.Status), TokenId: r.TokenID, TokenName: tokenName,
		PairingCode: r.PairingCode, Facts: facts, AgentVersion: r.AgentVersion, SourceIp: r.SourceIP,
		PublicKeySha256: r.PublicKeySHA256, ReplacesAgentId: r.ReplacesAgentID, CreatedAt: ts(r.CreatedAt),
		ExpiresAt: ts(r.ExpiresAt), DecidedAt: ts(r.DecidedAt), DecisionNote: r.DecisionNote, AgentId: r.AgentID,
	}
	if r.Status != store.EnrollmentPending {
		// The pairing code is only useful (and only shown) while a decision is pending.
		out.PairingCode = ""
	}
	if r.DecidedBy != "" {
		kind := store.PrincipalUser
		if r.DecidedBy == "auto-approval" {
			kind = store.PrincipalSystem
		}
		out.DecidedBy = principalProto(store.PrincipalRef{Kind: kind, ID: r.DecidedBy, Display: r.DecidedByName})
	}
	for _, f := range r.RiskFlags {
		out.RiskFlags = append(out.RiskFlags, &apiv1.RiskFlag{Code: f.Code, Severity: severityProto(f.Severity), Message: f.Message})
	}
	return out
}

func tokenNames(ctx context.Context, st *store.Store, orgID string) map[string]string {
	out := map[string]string{}
	if tokens, err := st.EnrollmentTokens.All(ctx, store.Tenant(orgID), store.Query{}); err == nil {
		for _, t := range tokens {
			out[t.ID] = t.Name
		}
	}
	return out
}

// ListEnrollmentRequests implements EnrollmentAdminService.
func (s *EnrollmentAdminService) ListEnrollmentRequests(ctx context.Context, req *connect.Request[apiv1.ListEnrollmentRequestsRequest]) (*connect.Response[apiv1.ListEnrollmentRequestsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.RequireHeld(ctx, authz.AgentsApprove)
	if err != nil {
		return nil, err
	}
	statuses := []string{}
	for _, v := range req.Msg.GetStatuses() {
		if n := requestStatusName(v); n != "" {
			statuses = append(statuses, n)
		}
	}
	if len(statuses) == 0 {
		statuses = []string{store.EnrollmentPending}
	}
	size := int(min(max(req.Msg.GetPage().GetPageSize(), 1), 500))
	if req.Msg.GetPage().GetPageSize() == 0 {
		size = 50
	}
	q := store.Where("status", store.OpIn, statuses).Order("created_at", true).Page(size, req.Msg.GetPage().GetPageToken())
	rows, next, err := st.EnrollmentRequests.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	names := tokenNames(ctx, st, p.OrgID)
	out := &apiv1.ListEnrollmentRequestsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	now := time.Now()
	for _, r := range rows {
		if r.Status == store.EnrollmentPending && !now.Before(r.ExpiresAt) {
			r.Status = store.EnrollmentExpired // housekeeping persists this shortly
			if !slices.Contains(statuses, store.EnrollmentExpired) {
				continue
			}
		}
		out.Requests = append(out.Requests, requestProto(r, names[r.TokenID]))
	}
	return connect.NewResponse(out), nil
}

// GetEnrollmentRequest implements EnrollmentAdminService.
func (s *EnrollmentAdminService) GetEnrollmentRequest(ctx context.Context, req *connect.Request[apiv1.GetEnrollmentRequestRequest]) (*connect.Response[apiv1.GetEnrollmentRequestResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.RequireHeld(ctx, authz.AgentsApprove)
	if err != nil {
		return nil, err
	}
	r, err := st.EnrollmentRequests.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetRequestId())
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("enrollment request not found"))
	}
	if err != nil {
		return nil, s.D.internal(err)
	}
	return connect.NewResponse(&apiv1.GetEnrollmentRequestResponse{Request: requestProto(r, tokenNames(ctx, st, p.OrgID)[r.TokenID])}), nil
}

// ApproveEnrollmentRequest implements EnrollmentAdminService.
func (s *EnrollmentAdminService) ApproveEnrollmentRequest(ctx context.Context, req *connect.Request[apiv1.ApproveEnrollmentRequestRequest]) (*connect.Response[apiv1.ApproveEnrollmentRequestResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.AgentsApprove)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	in := enrollment.ApproveInput{PairingCode: m.GetPairingCode(), Name: m.GetName(), GroupID: m.GetGroupId(), Note: m.GetNote()}
	if len(m.GetTags()) > 0 {
		in.Tags = m.GetTags()
	}
	r, err := s.D.Enroll.Approve(ctx, p.OrgID, m.GetRequestId(), p.Ref(), in)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.ApproveEnrollmentRequestResponse{Request: requestProto(r, tokenNames(ctx, st, p.OrgID)[r.TokenID])}), nil
}

// DenyEnrollmentRequest implements EnrollmentAdminService.
func (s *EnrollmentAdminService) DenyEnrollmentRequest(ctx context.Context, req *connect.Request[apiv1.DenyEnrollmentRequestRequest]) (*connect.Response[apiv1.DenyEnrollmentRequestResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.AgentsApprove)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if m.GetRevokeToken() && !p.Has(authz.TokensManage) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("missing permission "+authz.TokensManage+" to revoke the token"))
	}
	r, err := s.D.Enroll.Deny(ctx, p.OrgID, m.GetRequestId(), p.Ref(), enrollment.DenyInput{
		Reason: m.GetReason(), BlockKey: m.GetBlockKey(), RevokeToken: m.GetRevokeToken(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.DenyEnrollmentRequestResponse{Request: requestProto(r, tokenNames(ctx, st, p.OrgID)[r.TokenID])}), nil
}
