// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/auth"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/validate"
)

// AuthService implements sign-in, MFA, step-up and self-service account management.
type AuthService struct {
	apiv1connect.UnimplementedAuthServiceHandler
	D *Deps
}

var errBadCredentials = connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))

const (
	lockoutThreshold = 5
	maxLockout       = time.Hour
	pendingTOTPTTL   = 10 * time.Minute
)

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func stageProto(stage string) apiv1.SessionStage {
	switch stage {
	case store.SessionStageMFARequired:
		return apiv1.SessionStage_SESSION_STAGE_MFA_REQUIRED
	case store.SessionStageMFAEnrollment:
		return apiv1.SessionStage_SESSION_STAGE_MFA_ENROLLMENT
	case store.SessionStageFull:
		return apiv1.SessionStage_SESSION_STAGE_FULL
	}
	return apiv1.SessionStage_SESSION_STAGE_UNSPECIFIED
}

// orgTimeouts returns session timeouts for an org (defaults if unknown).
func (s *AuthService) orgTimeouts(ctx context.Context, st *store.Store, orgID string) auth.SessionTimeouts {
	if orgID != "" {
		if org, err := st.Orgs.Get(ctx, store.System(), orgID); err == nil {
			return auth.TimeoutsFor(org.Settings)
		}
	}
	return auth.TimeoutsFor(store.DefaultOrgSettings())
}

func (s *AuthService) memberships(ctx context.Context, st *store.Store, userID string) ([]*store.Membership, error) {
	// Deliberate cross-tenant read: a user's own memberships across organizations.
	ms, err := st.Memberships.All(ctx, store.System(), store.Eq("user_id", userID))
	if err != nil {
		return nil, err
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].JoinedAt.Before(ms[j].JoinedAt) })
	return ms, nil
}

func (s *AuthService) mfaMethods(ctx context.Context, st *store.Store, userID string) ([]*store.MFACredential, error) {
	return st.MFA.All(ctx, store.System(), store.Eq("user_id", userID))
}

func (s *AuthService) recordLogin(ctx context.Context, st *store.Store, u *store.User, result, method, reason string) {
	ms, _ := s.memberships(ctx, st, u.ID)
	details := map[string]string{}
	if method != "" {
		details["method"] = method
	}
	if reason != "" {
		details["reason"] = reason
	}
	for _, m := range ms {
		_ = s.D.Audit.Record(ctx, audit.Event{
			OrgID: m.OrgID, Actor: store.PrincipalRef{Kind: store.PrincipalUser, ID: u.ID, Display: u.Email},
			Action: "auth.login", TargetType: "user", TargetID: u.ID, TargetDisplay: u.Email,
			Result: result, Details: details,
		})
	}
}

// Login implements AuthService.
func (s *AuthService) Login(ctx context.Context, req *connect.Request[apiv1.LoginRequest]) (*connect.Response[apiv1.LoginResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	ip := clientIP(ctx)
	email := store.NormalizeEmail(req.Msg.GetEmail())
	if !d.limits.loginIP.Allow(ip) || !d.limits.loginEmail.Allow(email) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many sign-in attempts; wait a few minutes"))
	}
	password := req.Msg.GetPassword()
	u, err := st.Users.FindOne(ctx, store.System(), store.Eq("email", email))
	if err != nil {
		auth.VerifyDummy(ctx, password)
		d.Log.Info("audit", "action", "auth.login", "result", "failure", "reason", "unknown_user", "ip", ip)
		return nil, errBadCredentials
	}
	now := time.Now().UTC()
	locked := now.Before(u.LockedUntil)
	rehash, verr := auth.VerifyPassword(ctx, u.PasswordHash, password)
	if locked {
		s.recordLogin(ctx, st, u, store.AuditDenied, "password", "locked")
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("account temporarily locked after failed sign-ins; try again later"))
	}
	if verr != nil {
		u.FailedLogins++
		if u.FailedLogins >= lockoutThreshold {
			backoff := time.Minute << min(u.FailedLogins-lockoutThreshold, 6)
			u.LockedUntil = now.Add(min(backoff, maxLockout))
		}
		_ = st.Users.Update(ctx, store.System(), u)
		s.recordLogin(ctx, st, u, store.AuditFailure, "password", "bad_password")
		return nil, errBadCredentials
	}
	if u.Disabled {
		s.recordLogin(ctx, st, u, store.AuditDenied, "password", "disabled")
		return nil, errBadCredentials
	}
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	if rehash {
		if h, err := auth.HashPassword(ctx, password); err == nil {
			u.PasswordHash = h
		}
	}
	if err := st.Users.Update(ctx, store.System(), u); err != nil {
		return nil, d.internal(err)
	}

	ms, err := s.memberships(ctx, st, u.ID)
	if err != nil {
		return nil, d.internal(err)
	}
	orgID := ""
	if len(ms) > 0 {
		orgID = ms[0].OrgID
	}
	methods, err := s.mfaMethods(ctx, st, u.ID)
	if err != nil {
		return nil, d.internal(err)
	}
	stage := store.SessionStageMFAEnrollment
	var available []apiv1.MfaMethodType
	if len(methods) > 0 {
		stage = store.SessionStageMFARequired
		for _, m := range methods {
			t := apiv1.MfaMethodType_MFA_METHOD_TYPE_TOTP
			if m.Type == store.MFATypePasskey {
				t = apiv1.MfaMethodType_MFA_METHOD_TYPE_PASSKEY
			}
			if !slices.Contains(available, t) {
				available = append(available, t)
			}
		}
		if n, _ := auth.CountRecoveryCodes(ctx, st, u.ID); n > 0 {
			available = append(available, apiv1.MfaMethodType_MFA_METHOD_TYPE_RECOVERY_CODE)
		}
	}
	token, sess, err := d.Sessions.Create(ctx, u.ID, orgID, stage, ip, audit.UserAgentFrom(ctx), s.orgTimeouts(ctx, st, orgID))
	if err != nil {
		return nil, d.internal(err)
	}
	res := connect.NewResponse(&apiv1.LoginResponse{Stage: stageProto(stage), MfaMethods: available})
	d.Cookies.Set(ctx, res.Header(), SessionCookie, token, time.Until(sess.ExpiresAt))
	return res, nil
}

// currentSession returns the principal and session of the caller.
func currentSession(ctx context.Context) (*authz.Principal, *store.Session, error) {
	p := authz.From(ctx)
	if p == nil || p.Session == nil {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	}
	return p, p.Session, nil
}

// completeLogin upgrades a partial session to a full one (new token).
func (s *AuthService) completeLogin(ctx context.Context, st *store.Store, sess *store.Session, h http.Header, method string) error {
	token, full, err := s.D.Sessions.Rotate(ctx, sess, store.SessionStageFull, s.orgTimeouts(ctx, st, sess.ActiveOrgID))
	if err != nil {
		return s.D.internal(err)
	}
	s.D.Cookies.Set(ctx, h, SessionCookie, token, time.Until(full.ExpiresAt))
	if u, err := st.Users.Get(ctx, store.System(), sess.UserID); err == nil {
		u.LastLoginAt = time.Now().UTC()
		_ = st.Users.Update(ctx, store.System(), u)
		s.recordLogin(ctx, st, u, store.AuditSuccess, method, "")
	}
	return nil
}

// mfaAttempt enforces MFA attempt limits: a per-session cap (the session is revoked when it is
// exhausted) and a per-user failure budget shared by all of the user's sessions.
func (s *AuthService) mfaAttempt(ctx context.Context, sess *store.Session) error {
	if s.D.limits.mfaUserFailures.Blocked(sess.UserID) {
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many failed attempts; try again later"))
	}
	if !s.D.limits.mfaSession.Allow(sess.ID) {
		_ = s.D.Sessions.Revoke(ctx, sess)
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts; sign in again"))
	}
	return nil
}

// mfaFailed records a failed MFA attempt against the user's failure budget.
func (s *AuthService) mfaFailed(userID string) { s.D.limits.mfaUserFailures.Allow(userID) }

func (s *AuthService) verifyTOTP(ctx context.Context, st *store.Store, userID, code string) (bool, error) {
	methods, err := s.mfaMethods(ctx, st, userID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, m := range methods {
		if m.Type != store.MFATypeTOTP {
			continue
		}
		step, err := auth.VerifyTOTP(s.D.Keyring, m, code, now)
		if err != nil {
			continue
		}
		m.TOTPLastStep, m.LastUsedAt = step, now.UTC()
		if err := st.MFA.Update(ctx, store.System(), m); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// VerifyTotp implements AuthService.
func (s *AuthService) VerifyTotp(ctx context.Context, req *connect.Request[apiv1.VerifyTotpRequest]) (*connect.Response[apiv1.VerifyTotpResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if sess.Stage != store.SessionStageMFARequired {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no sign-in in progress"))
	}
	if err := s.mfaAttempt(ctx, sess); err != nil {
		return nil, err
	}
	ok, err := s.verifyTOTP(ctx, st, sess.UserID, req.Msg.GetCode())
	if err != nil {
		return nil, s.D.internal(err)
	}
	if !ok {
		s.mfaFailed(sess.UserID)
		if u, err := st.Users.Get(ctx, store.System(), sess.UserID); err == nil {
			s.recordLogin(ctx, st, u, store.AuditFailure, "totp", "bad_code")
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid code"))
	}
	res := connect.NewResponse(&apiv1.VerifyTotpResponse{Stage: apiv1.SessionStage_SESSION_STAGE_FULL})
	if err := s.completeLogin(ctx, st, sess, res.Header(), "totp"); err != nil {
		return nil, err
	}
	return res, nil
}

// UseRecoveryCode implements AuthService.
func (s *AuthService) UseRecoveryCode(ctx context.Context, req *connect.Request[apiv1.UseRecoveryCodeRequest]) (*connect.Response[apiv1.UseRecoveryCodeResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if sess.Stage != store.SessionStageMFARequired {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no sign-in in progress"))
	}
	if err := s.mfaAttempt(ctx, sess); err != nil {
		return nil, err
	}
	remaining, err := auth.UseRecoveryCode(ctx, st, sess.UserID, req.Msg.GetCode())
	if errors.Is(err, auth.ErrInvalidCode) {
		s.mfaFailed(sess.UserID)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid recovery code"))
	}
	if err != nil {
		return nil, s.D.internal(err)
	}
	res := connect.NewResponse(&apiv1.UseRecoveryCodeResponse{
		Stage: apiv1.SessionStage_SESSION_STAGE_FULL, RemainingCodes: uint32(remaining), //nolint:gosec // small count
	})
	if err := s.completeLogin(ctx, st, sess, res.Header(), "recovery_code"); err != nil {
		return nil, err
	}
	return res, nil
}

// BeginPasskeyLogin implements AuthService. With a partial session it starts the MFA assertion
// for that user; without one it starts a passwordless (discoverable) login.
func (s *AuthService) BeginPasskeyLogin(ctx context.Context, _ *connect.Request[apiv1.BeginPasskeyLoginRequest]) (*connect.Response[apiv1.BeginPasskeyLoginResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	if !d.limits.loginIP.Allow(clientIP(ctx)) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts"))
	}
	if p := authz.From(ctx); p != nil && p.Session != nil && p.Session.Stage == store.SessionStageMFARequired {
		u, err := st.Users.Get(ctx, store.System(), p.Session.UserID)
		if err != nil {
			return nil, d.internal(err)
		}
		opts, state, err := d.Passkeys.BeginLogin(ctx, u)
		if err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		p.Session.PendingWebAuthn, p.Session.PendingUntil = state, time.Now().Add(5*time.Minute)
		if err := d.Sessions.Update(ctx, p.Session); err != nil {
			return nil, d.internal(err)
		}
		return connect.NewResponse(&apiv1.BeginPasskeyLoginResponse{OptionsJson: opts}), nil
	}
	opts, ceremony, err := d.Passkeys.BeginDiscoverable(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	res := connect.NewResponse(&apiv1.BeginPasskeyLoginResponse{OptionsJson: opts})
	d.Cookies.Set(ctx, res.Header(), PasskeyCookie, ceremony, 5*time.Minute)
	return res, nil
}

// FinishPasskeyLogin implements AuthService.
func (s *AuthService) FinishPasskeyLogin(ctx context.Context, req *connect.Request[apiv1.FinishPasskeyLoginRequest]) (*connect.Response[apiv1.FinishPasskeyLoginResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	res := connect.NewResponse(&apiv1.FinishPasskeyLoginResponse{Stage: apiv1.SessionStage_SESSION_STAGE_FULL})
	if p := authz.From(ctx); p != nil && p.Session != nil && p.Session.Stage == store.SessionStageMFARequired {
		sess := p.Session
		if err := s.mfaAttempt(ctx, sess); err != nil {
			return nil, err
		}
		u, err := st.Users.Get(ctx, store.System(), sess.UserID)
		if err != nil {
			return nil, d.internal(err)
		}
		if err := d.Passkeys.FinishLogin(ctx, u, sess.PendingWebAuthn, req.Msg.GetCredentialJson()); err != nil {
			s.mfaFailed(sess.UserID)
			s.recordLogin(ctx, st, u, store.AuditFailure, "passkey", "assertion_failed")
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("passkey verification failed"))
		}
		if err := s.completeLogin(ctx, st, sess, res.Header(), "passkey"); err != nil {
			return nil, err
		}
		return res, nil
	}

	// Passwordless: the passkey (with user verification) is itself multi-factor.
	ceremony := d.Cookies.Read(ctx, req.Header(), PasskeyCookie)
	d.Cookies.Clear(ctx, res.Header(), PasskeyCookie)
	u, err := d.Passkeys.FinishDiscoverable(ctx, ceremony, req.Msg.GetCredentialJson())
	if err != nil || u.Disabled {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("passkey sign-in failed"))
	}
	ms, err := s.memberships(ctx, st, u.ID)
	if err != nil {
		return nil, d.internal(err)
	}
	orgID := ""
	if len(ms) > 0 {
		orgID = ms[0].OrgID
	}
	token, sess, err := d.Sessions.Create(ctx, u.ID, orgID, store.SessionStageFull, clientIP(ctx), audit.UserAgentFrom(ctx), s.orgTimeouts(ctx, st, orgID))
	if err != nil {
		return nil, d.internal(err)
	}
	sess.StepUpAt = time.Now().UTC()
	_ = d.Sessions.Update(ctx, sess)
	d.Cookies.Set(ctx, res.Header(), SessionCookie, token, time.Until(sess.ExpiresAt))
	u.LastLoginAt = time.Now().UTC()
	_ = st.Users.Update(ctx, store.System(), u)
	s.recordLogin(ctx, st, u, store.AuditSuccess, "passkey_passwordless", "")
	return res, nil
}

// Logout implements AuthService.
func (s *AuthService) Logout(ctx context.Context, _ *connect.Request[apiv1.LogoutRequest]) (*connect.Response[apiv1.LogoutResponse], error) {
	res := connect.NewResponse(&apiv1.LogoutResponse{})
	if _, sess, err := currentSession(ctx); err == nil {
		_ = s.D.Sessions.Revoke(ctx, sess)
	}
	s.D.Cookies.Clear(ctx, res.Header(), SessionCookie)
	return res, nil
}

// GetSession implements AuthService.
func (s *AuthService) GetSession(ctx context.Context, _ *connect.Request[apiv1.GetSessionRequest]) (*connect.Response[apiv1.GetSessionResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	u, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	methods, _ := s.mfaMethods(ctx, st, u.ID)
	out := &apiv1.GetSessionResponse{
		Stage: stageProto(sess.Stage), User: userProto(u, len(methods) > 0), CsrfToken: sess.CSRFToken,
		ExpiresAt: ts(sess.ExpiresAt), IdleExpiresAt: ts(sess.IdleExpiresAt),
	}
	if sess.Stage == store.SessionStageFull {
		ms, err := s.memberships(ctx, st, u.ID)
		if err != nil {
			return nil, d.internal(err)
		}
		for _, m := range ms {
			org, err := st.Orgs.Get(ctx, store.System(), m.OrgID)
			if err != nil {
				continue
			}
			ref := &apiv1.OrganizationRef{Id: org.ID, Name: org.Name, Roles: roleNames(ctx, st, m)}
			out.Organizations = append(out.Organizations, ref)
			if org.ID == p.OrgID {
				out.ActiveOrganization = ref
			}
		}
		out.Permissions = p.Permissions()
		out.StepUpValidUntil = ts(p.StepUpValidUntil())
	}
	return connect.NewResponse(out), nil
}

func roleNames(ctx context.Context, st *store.Store, m *store.Membership) []string {
	var names []string
	for _, rb := range m.RoleBindings {
		if r, ok := authz.Builtin(rb.RoleID); ok {
			names = append(names, r.Name)
		} else if role, err := st.Roles.Get(ctx, store.Tenant(m.OrgID), rb.RoleID); err == nil {
			names = append(names, role.Name)
		}
	}
	return names
}

func userProto(u *store.User, mfa bool) *apiv1.User {
	return &apiv1.User{
		Id: u.ID, Email: u.Email, DisplayName: u.DisplayName, CreatedAt: ts(u.CreatedAt),
		LastLoginAt: ts(u.LastLoginAt), Disabled: u.Disabled, MfaEnabled: mfa,
	}
}

// SwitchOrganization implements AuthService.
func (s *AuthService) SwitchOrganization(ctx context.Context, req *connect.Request[apiv1.SwitchOrganizationRequest]) (*connect.Response[apiv1.SwitchOrganizationResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	orgID := req.Msg.GetOrganizationId()
	if err := validate.ID("organization_id", orgID); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	m, err := st.Memberships.Get(ctx, store.Tenant(orgID), store.DeriveID(orgID, sess.UserID))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("organization not found"))
	}
	org, err := st.Orgs.Get(ctx, store.System(), orgID)
	if err != nil {
		return nil, d.internal(err)
	}
	sess.ActiveOrgID = orgID
	sess.StepUpAt = time.Time{} // step-up does not carry across organizations
	if err := d.Sessions.Update(ctx, sess); err != nil {
		return nil, d.internal(err)
	}
	return connect.NewResponse(&apiv1.SwitchOrganizationResponse{
		ActiveOrganization: &apiv1.OrganizationRef{Id: org.ID, Name: org.Name, Roles: roleNames(ctx, st, m)},
	}), nil
}

// BeginStepUp implements AuthService.
func (s *AuthService) BeginStepUp(ctx context.Context, _ *connect.Request[apiv1.BeginStepUpRequest]) (*connect.Response[apiv1.BeginStepUpResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	methods, err := s.mfaMethods(ctx, st, sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	out := &apiv1.BeginStepUpResponse{}
	hasPasskey := false
	for _, m := range methods {
		switch m.Type {
		case store.MFATypeTOTP:
			if !slices.Contains(out.Methods, apiv1.MfaMethodType_MFA_METHOD_TYPE_TOTP) {
				out.Methods = append(out.Methods, apiv1.MfaMethodType_MFA_METHOD_TYPE_TOTP)
			}
		case store.MFATypePasskey:
			hasPasskey = true
		}
	}
	if hasPasskey {
		u, err := st.Users.Get(ctx, store.System(), sess.UserID)
		if err != nil {
			return nil, d.internal(err)
		}
		opts, state, err := d.Passkeys.BeginLogin(ctx, u)
		if err == nil {
			out.Methods = append(out.Methods, apiv1.MfaMethodType_MFA_METHOD_TYPE_PASSKEY)
			out.PasskeyOptionsJson = opts
			sess.PendingWebAuthn, sess.PendingUntil = state, time.Now().Add(5*time.Minute)
			if err := d.Sessions.Update(ctx, sess); err != nil {
				return nil, d.internal(err)
			}
		}
	}
	return connect.NewResponse(out), nil
}

// FinishStepUp implements AuthService.
func (s *AuthService) FinishStepUp(ctx context.Context, req *connect.Request[apiv1.FinishStepUpRequest]) (*connect.Response[apiv1.FinishStepUpResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.mfaAttempt(ctx, sess); err != nil {
		return nil, err
	}
	var ok bool
	var method string
	switch proof := req.Msg.GetProof().(type) {
	case *apiv1.FinishStepUpRequest_TotpCode:
		method = "totp"
		ok, err = s.verifyTOTP(ctx, st, sess.UserID, proof.TotpCode)
		if err != nil {
			return nil, d.internal(err)
		}
	case *apiv1.FinishStepUpRequest_PasskeyCredentialJson:
		method = "passkey"
		u, err := st.Users.Get(ctx, store.System(), sess.UserID)
		if err != nil {
			return nil, d.internal(err)
		}
		ok = d.Passkeys.FinishLogin(ctx, u, sess.PendingWebAuthn, proof.PasskeyCredentialJson) == nil
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a TOTP code or passkey assertion is required"))
	}
	_ = d.Audit.Record(ctx, audit.Event{
		Action: "auth.step_up", TargetType: "user", TargetID: sess.UserID,
		Result: map[bool]string{true: store.AuditSuccess, false: store.AuditFailure}[ok], Details: map[string]string{"method": method},
	})
	if !ok {
		s.mfaFailed(sess.UserID)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("verification failed"))
	}
	sess.StepUpAt = time.Now().UTC()
	sess.PendingWebAuthn = nil
	if err := d.Sessions.Update(ctx, sess); err != nil {
		return nil, d.internal(err)
	}
	p.Session = sess
	return connect.NewResponse(&apiv1.FinishStepUpResponse{StepUpValidUntil: ts(p.StepUpValidUntil())}), nil
}

// requireFactorChangeAllowed: adding or removing factors on an account that already has MFA
// requires a recent step-up, so a stolen session cannot enroll the attacker's authenticator.
func (s *AuthService) requireFactorChangeAllowed(ctx context.Context, st *store.Store, p *authz.Principal, sess *store.Session) error {
	if sess.Stage == store.SessionStageMFAEnrollment {
		return nil
	}
	methods, err := s.mfaMethods(ctx, st, sess.UserID)
	if err != nil {
		return s.D.internal(err)
	}
	if len(methods) == 0 {
		return nil
	}
	return authz.RequireStepUp(p)
}

// BeginTotpEnrollment implements AuthService.
func (s *AuthService) BeginTotpEnrollment(ctx context.Context, _ *connect.Request[apiv1.BeginTotpEnrollmentRequest]) (*connect.Response[apiv1.BeginTotpEnrollmentResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireFactorChangeAllowed(ctx, st, p, sess); err != nil {
		return nil, err
	}
	u, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	secret, uri := auth.NewTOTPSecret("Central", u.Email)
	id := store.NewID()
	sealed, err := d.Keyring.SealString(secret, "mfa.totp.pending:"+sess.ID+":"+id)
	if err != nil {
		return nil, d.internal(err)
	}
	sess.PendingTOTPSealed, sess.PendingTOTPID, sess.PendingUntil = sealed, id, time.Now().Add(pendingTOTPTTL)
	if err := d.Sessions.Update(ctx, sess); err != nil {
		return nil, d.internal(err)
	}
	return connect.NewResponse(&apiv1.BeginTotpEnrollmentResponse{EnrollmentId: id, Secret: secret, OtpauthUri: uri}), nil
}

// ConfirmTotpEnrollment implements AuthService.
func (s *AuthService) ConfirmTotpEnrollment(ctx context.Context, req *connect.Request[apiv1.ConfirmTotpEnrollmentRequest]) (*connect.Response[apiv1.ConfirmTotpEnrollmentResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireFactorChangeAllowed(ctx, st, p, sess); err != nil {
		return nil, err
	}
	if err := s.mfaAttempt(ctx, sess); err != nil {
		return nil, err
	}
	if sess.PendingTOTPID == "" || sess.PendingTOTPID != req.Msg.GetEnrollmentId() || time.Now().After(sess.PendingUntil) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("enrollment expired; start again"))
	}
	secret, err := d.Keyring.OpenString(sess.PendingTOTPSealed, "mfa.totp.pending:"+sess.ID+":"+sess.PendingTOTPID)
	if err != nil {
		return nil, d.internal(err)
	}
	step, err := auth.VerifyTOTPSecret(secret, req.Msg.GetCode(), time.Now())
	if err != nil {
		s.mfaFailed(sess.UserID)
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the code does not match; check the time on your device"))
	}
	name, err := validate.OptionalText("name", req.Msg.GetName(), 64)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if name == "" {
		name = "Authenticator app"
	}
	cred := &store.MFACredential{
		ID: store.NewID(), UserID: sess.UserID, Type: store.MFATypeTOTP, Name: name,
		TOTPLastStep: step, CreatedAt: time.Now().UTC(),
	}
	if cred.TOTPSecretSealed, err = auth.SealTOTP(d.Keyring, cred.ID, secret); err != nil {
		return nil, d.internal(err)
	}
	res := connect.NewResponse(&apiv1.ConfirmTotpEnrollmentResponse{MethodId: cred.ID})
	codes, stage, err := s.finishFactorEnrollment(ctx, st, sess, cred, res.Header())
	if err != nil {
		return nil, err
	}
	res.Msg.RecoveryCodes, res.Msg.Stage = codes, stageProto(stage)
	return res, nil
}

// finishFactorEnrollment stores a new factor, issues recovery codes for the first factor and
// upgrades an enrollment-stage session to full (setting the new session cookie on h).
func (s *AuthService) finishFactorEnrollment(ctx context.Context, st *store.Store, sess *store.Session, cred *store.MFACredential, h http.Header) ([]string, string, error) {
	d := s.D
	existing, err := s.mfaMethods(ctx, st, sess.UserID)
	if err != nil {
		return nil, "", d.internal(err)
	}
	if err := st.MFA.Create(ctx, store.System(), cred); err != nil {
		return nil, "", d.internal(err)
	}
	var codes []string
	if len(existing) == 0 {
		if codes, err = auth.ReplaceRecoveryCodes(ctx, st, sess.UserID); err != nil {
			return nil, "", d.internal(err)
		}
	}
	_ = d.Audit.Record(ctx, audit.Event{
		Action: "auth.mfa_added", TargetType: "user", TargetID: sess.UserID,
		Details: map[string]string{"type": cred.Type, "name": cred.Name},
	})
	sess.PendingTOTPSealed, sess.PendingTOTPID, sess.PendingWebAuthn = "", "", nil
	if sess.Stage == store.SessionStageMFAEnrollment {
		if err := s.completeLogin(ctx, st, sess, h, "mfa_enrollment"); err != nil {
			return nil, "", err
		}
		return codes, store.SessionStageFull, nil
	}
	if err := d.Sessions.Update(ctx, sess); err != nil {
		return nil, "", d.internal(err)
	}
	return codes, sess.Stage, nil
}

// BeginPasskeyRegistration implements AuthService.
func (s *AuthService) BeginPasskeyRegistration(ctx context.Context, _ *connect.Request[apiv1.BeginPasskeyRegistrationRequest]) (*connect.Response[apiv1.BeginPasskeyRegistrationResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireFactorChangeAllowed(ctx, st, p, sess); err != nil {
		return nil, err
	}
	u, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	opts, state, err := d.Passkeys.BeginRegistration(ctx, u)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	sess.PendingWebAuthn, sess.PendingUntil = state, time.Now().Add(5*time.Minute)
	if err := d.Sessions.Update(ctx, sess); err != nil {
		return nil, d.internal(err)
	}
	return connect.NewResponse(&apiv1.BeginPasskeyRegistrationResponse{OptionsJson: opts}), nil
}

// FinishPasskeyRegistration implements AuthService.
func (s *AuthService) FinishPasskeyRegistration(ctx context.Context, req *connect.Request[apiv1.FinishPasskeyRegistrationRequest]) (*connect.Response[apiv1.FinishPasskeyRegistrationResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireFactorChangeAllowed(ctx, st, p, sess); err != nil {
		return nil, err
	}
	u, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	cred, err := d.Passkeys.FinishRegistration(ctx, u, sess.PendingWebAuthn, req.Msg.GetCredentialJson())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("passkey registration failed"))
	}
	name, err := validate.OptionalText("name", req.Msg.GetName(), 64)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if name == "" {
		name = "Passkey"
	}
	cred.Name = name
	res := connect.NewResponse(&apiv1.FinishPasskeyRegistrationResponse{MethodId: cred.ID})
	codes, stage, err := s.finishFactorEnrollment(ctx, st, sess, cred, res.Header())
	if err != nil {
		return nil, err
	}
	res.Msg.RecoveryCodes, res.Msg.Stage = codes, stageProto(stage)
	return res, nil
}

// ListMfaMethods implements AuthService.
func (s *AuthService) ListMfaMethods(ctx context.Context, _ *connect.Request[apiv1.ListMfaMethodsRequest]) (*connect.Response[apiv1.ListMfaMethodsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	methods, err := s.mfaMethods(ctx, st, sess.UserID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListMfaMethodsResponse{}
	for _, m := range methods {
		t := apiv1.MfaMethodType_MFA_METHOD_TYPE_TOTP
		if m.Type == store.MFATypePasskey {
			t = apiv1.MfaMethodType_MFA_METHOD_TYPE_PASSKEY
		}
		out.Methods = append(out.Methods, &apiv1.MfaMethod{Id: m.ID, Type: t, Name: m.Name, CreatedAt: ts(m.CreatedAt), LastUsedAt: ts(m.LastUsedAt)})
	}
	n, _ := auth.CountRecoveryCodes(ctx, st, sess.UserID)
	out.RecoveryCodesRemaining = uint32(n) //nolint:gosec // small count
	return connect.NewResponse(out), nil
}

// DeleteMfaMethod implements AuthService.
func (s *AuthService) DeleteMfaMethod(ctx context.Context, req *connect.Request[apiv1.DeleteMfaMethodRequest]) (*connect.Response[apiv1.DeleteMfaMethodResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := authz.RequireStepUp(p); err != nil {
		return nil, err
	}
	methods, err := s.mfaMethods(ctx, st, sess.UserID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	idx := slices.IndexFunc(methods, func(m *store.MFACredential) bool { return m.ID == req.Msg.GetMethodId() })
	if idx < 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("method not found"))
	}
	if len(methods) == 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot remove your last second factor"))
	}
	if err := st.MFA.Delete(ctx, store.System(), methods[idx].ID); err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "auth.mfa_removed", TargetType: "user", TargetID: sess.UserID,
		Details: map[string]string{"type": methods[idx].Type, "name": methods[idx].Name},
	})
	return connect.NewResponse(&apiv1.DeleteMfaMethodResponse{}), nil
}

// RegenerateRecoveryCodes implements AuthService.
func (s *AuthService) RegenerateRecoveryCodes(ctx context.Context, _ *connect.Request[apiv1.RegenerateRecoveryCodesRequest]) (*connect.Response[apiv1.RegenerateRecoveryCodesResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := authz.RequireStepUp(p); err != nil {
		return nil, err
	}
	codes, err := auth.ReplaceRecoveryCodes(ctx, st, sess.UserID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "auth.recovery_codes_regenerated", TargetType: "user", TargetID: sess.UserID})
	return connect.NewResponse(&apiv1.RegenerateRecoveryCodesResponse{RecoveryCodes: codes}), nil
}

// ChangePassword implements AuthService.
func (s *AuthService) ChangePassword(ctx context.Context, req *connect.Request[apiv1.ChangePasswordRequest]) (*connect.Response[apiv1.ChangePasswordResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if !d.limits.loginEmail.Allow("pwchange:" + sess.UserID) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts"))
	}
	u, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil {
		return nil, d.internal(err)
	}
	if _, err := auth.VerifyPassword(ctx, u.PasswordHash, req.Msg.GetCurrentPassword()); err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("current password is incorrect"))
	}
	if err := auth.CheckPasswordPolicy(req.Msg.GetNewPassword(), u.Email, u.DisplayName); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h, err := auth.HashPassword(ctx, req.Msg.GetNewPassword())
	if err != nil {
		return nil, d.internal(err)
	}
	u.PasswordHash, u.PasswordChangedAt, u.UpdatedAt = h, time.Now().UTC(), time.Now().UTC()
	if err := st.Users.Update(ctx, store.System(), u); err != nil {
		return nil, d.internal(err)
	}
	if err := d.Sessions.RevokeUser(ctx, u.ID, sess.ID); err != nil {
		return nil, d.internal(err)
	}
	_ = d.Audit.Record(ctx, audit.Event{Action: "auth.password_changed", TargetType: "user", TargetID: u.ID, TargetDisplay: u.Email})
	return connect.NewResponse(&apiv1.ChangePasswordResponse{}), nil
}

// ListSessions implements AuthService.
func (s *AuthService) ListSessions(ctx context.Context, _ *connect.Request[apiv1.ListSessionsRequest]) (*connect.Response[apiv1.ListSessionsResponse], error) {
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	all, err := s.D.Sessions.List(ctx, sess.UserID)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListSessionsResponse{}
	for _, x := range all {
		out.Sessions = append(out.Sessions, &apiv1.SessionInfo{
			Id: x.ID, CreatedAt: ts(x.CreatedAt), LastSeenAt: ts(x.LastSeenAt), Ip: x.IP, UserAgent: x.UserAgent,
			Current: x.ID == sess.ID,
		})
	}
	return connect.NewResponse(out), nil
}

// RevokeSession implements AuthService.
func (s *AuthService) RevokeSession(ctx context.Context, req *connect.Request[apiv1.RevokeSessionRequest]) (*connect.Response[apiv1.RevokeSessionResponse], error) {
	_, sess, err := currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.GetAllOthers() {
		if err := s.D.Sessions.RevokeUser(ctx, sess.UserID, sess.ID); err != nil {
			return nil, s.D.internal(err)
		}
	} else {
		all, err := s.D.Sessions.List(ctx, sess.UserID)
		if err != nil {
			return nil, s.D.internal(err)
		}
		idx := slices.IndexFunc(all, func(x *store.Session) bool { return x.ID == req.Msg.GetSessionId() })
		if idx < 0 {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
		}
		if err := s.D.Sessions.Revoke(ctx, all[idx]); err != nil {
			return nil, s.D.internal(err)
		}
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "auth.session_revoked", TargetType: "user", TargetID: sess.UserID})
	return connect.NewResponse(&apiv1.RevokeSessionResponse{}), nil
}

// AcceptInvite implements AuthService.
func (s *AuthService) AcceptInvite(ctx context.Context, req *connect.Request[apiv1.AcceptInviteRequest]) (*connect.Response[apiv1.AcceptInviteResponse], error) {
	d := s.D
	st, err := d.Store()
	if err != nil {
		return nil, err
	}
	if !d.limits.invite.Allow(clientIP(ctx)) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts"))
	}
	invalid := connect.NewError(connect.CodePermissionDenied, errors.New("this invitation is invalid or has expired"))
	raw := strings.TrimSpace(req.Msg.GetInviteToken())
	if !strings.HasPrefix(raw, InvitePrefix) {
		return nil, invalid
	}
	id, secret, ok := strings.Cut(strings.TrimPrefix(raw, InvitePrefix), ".")
	if !ok || !store.ValidID(id) {
		return nil, invalid
	}
	// Deliberate cross-tenant lookup: the invite's org is only known after finding it.
	inv, err := st.Invites.Get(ctx, store.System(), id)
	if err != nil || !crypto.EqualHashes(inv.TokenHash, crypto.HashToken("invite", secret)) ||
		!inv.AcceptedAt.IsZero() || !inv.RevokedAt.IsZero() || time.Now().After(inv.ExpiresAt) {
		return nil, invalid
	}
	now := time.Now().UTC()
	u, err := st.Users.FindOne(ctx, store.System(), store.Eq("email", inv.Email))
	switch {
	case errors.Is(err, store.ErrNotFound):
		name, err := validate.DisplayText("display name", req.Msg.GetDisplayName(), 100)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if err := auth.CheckPasswordPolicy(req.Msg.GetPassword(), inv.Email, name); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		h, err := auth.HashPassword(ctx, req.Msg.GetPassword())
		if err != nil {
			return nil, d.internal(err)
		}
		u = &store.User{
			ID: store.NewID(), Email: inv.Email, DisplayName: name, PasswordHash: h, CreatedAt: now,
			UpdatedAt: now, PasswordChangedAt: now, WebAuthnID: crypto.RandomBytes(32),
		}
		if err := st.Users.Create(ctx, store.System(), u); err != nil {
			return nil, d.internal(err)
		}
	case err != nil:
		return nil, d.internal(err)
	default:
		// Existing account: the password proves it is theirs before joining another org.
		if _, err := auth.VerifyPassword(ctx, u.PasswordHash, req.Msg.GetPassword()); err != nil {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("an account with this email exists: enter its password to accept"))
		}
	}
	memID := store.DeriveID(inv.OrgID, u.ID)
	if _, err := st.Memberships.Get(ctx, store.Tenant(inv.OrgID), memID); errors.Is(err, store.ErrNotFound) {
		m := &store.Membership{ID: memID, OrgID: inv.OrgID, UserID: u.ID, RoleBindings: inv.RoleBindings, JoinedAt: now}
		if err := st.Memberships.Create(ctx, store.Tenant(inv.OrgID), m); err != nil {
			return nil, d.internal(err)
		}
	}
	inv.AcceptedAt = now
	if err := st.Invites.Update(ctx, store.Tenant(inv.OrgID), inv); err != nil {
		return nil, d.internal(err)
	}
	d.Resolver.Invalidate()
	_ = d.Audit.Record(ctx, audit.Event{
		OrgID: inv.OrgID, Actor: store.PrincipalRef{Kind: store.PrincipalUser, ID: u.ID, Display: u.Email},
		Action: "member.joined", TargetType: "user", TargetID: u.ID, TargetDisplay: u.Email,
	})
	return connect.NewResponse(&apiv1.AcceptInviteResponse{Email: u.Email}), nil
}
