// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package api implements Central's ConnectRPC services for the web UI and automation.
//
// Authentication and coarse authorization happen in the Guard interceptor, which is
// default-deny: every procedure requires a fully authenticated session (or an API key) unless it
// is explicitly listed as public or allowed during a partial (MFA pending) session. Handlers then
// perform fine-grained checks with authz.Require / authz.RequireOnAgent.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/auth"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/ratelimit"
	"github.com/Shaalan15/central/server/internal/setup"
	"github.com/Shaalan15/central/server/internal/store"
)

// Cookie and header names.
const (
	SessionCookie  = "central-session"
	PasskeyCookie  = "central-pk"
	CSRFHeader     = "X-CSRF-Token"
	APIKeyPrefix   = "cak1."
	InvitePrefix   = "cinv1."
	bearerPrefix   = "Bearer "
	sessionCtxKind = "session"
)

// Deps are shared by all services.
type Deps struct {
	Config   *config.Config
	Log      *slog.Logger
	Holder   *store.Holder
	Keyring  *crypto.Keyring
	Sessions *auth.Sessions
	Passkeys *auth.Passkeys
	Resolver *authz.Resolver
	Audit    *audit.Recorder
	Cookies  httpx.Cookies
	Setup    *setup.State
	Version  string
	Commit   string
	Started  time.Time

	limits limits
}

type limits struct {
	loginIP, loginEmail, mfaSession, mfaUserFailures, invite, apiKey *ratelimit.Keyed
}

// Init prepares rate limiters; call once after constructing Deps.
func (d *Deps) Init() {
	d.limits = limits{
		loginIP:    ratelimit.New(30, 10*time.Minute, 15),
		loginEmail: ratelimit.New(10, 10*time.Minute, 8),
		// Attempts per (partial or full) session, and failures per user across sessions.
		mfaSession:      ratelimit.New(10, 10*time.Minute, 8),
		mfaUserFailures: ratelimit.New(10, 15*time.Minute, 10),
		invite:          ratelimit.New(20, 10*time.Minute, 10),
		apiKey:          ratelimit.New(600, time.Minute, 120),
	}
}

// Store returns the active store or an Unavailable error.
func (d *Deps) Store() (*store.Store, error) {
	st := d.Holder.Get()
	if st == nil || !d.Setup.Complete() {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("central is not set up yet"))
	}
	return st, nil
}

// PublicURL returns the configured public UI URL (config override, else wizard setting).
func (d *Deps) PublicURL(ctx context.Context) string {
	if d.Config.PublicURL != "" {
		return d.Config.PublicURL
	}
	if st := d.Holder.Get(); st != nil {
		if v, err := st.GetSetting(ctx, setup.SettingPublicURL); err == nil {
			return v
		}
	}
	return ""
}

// AgentURL returns the URL agents use.
func (d *Deps) AgentURL(ctx context.Context) string {
	if d.Config.AgentURL != "" {
		return d.Config.AgentURL
	}
	if st := d.Holder.Get(); st != nil {
		if v, err := st.GetSetting(ctx, setup.SettingAgentURL); err == nil {
			return v
		}
	}
	return ""
}

func (d *Deps) internal(err error) error {
	d.Log.Error("api: internal error", "error", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// procedures reachable without any session.
var publicProcedures = map[string]bool{
	apiv1connect.AuthServiceLoginProcedure:              true,
	apiv1connect.AuthServiceBeginPasskeyLoginProcedure:  true,
	apiv1connect.AuthServiceFinishPasskeyLoginProcedure: true,
	apiv1connect.AuthServiceAcceptInviteProcedure:       true,
}

// procedures allowed per partial session stage.
var stageProcedures = map[string]map[string]bool{
	store.SessionStageMFARequired: {
		apiv1connect.AuthServiceVerifyTotpProcedure:      true,
		apiv1connect.AuthServiceUseRecoveryCodeProcedure: true,
		apiv1connect.AuthServiceGetSessionProcedure:      true,
		apiv1connect.AuthServiceLogoutProcedure:          true,
	},
	store.SessionStageMFAEnrollment: {
		apiv1connect.AuthServiceBeginTotpEnrollmentProcedure:       true,
		apiv1connect.AuthServiceConfirmTotpEnrollmentProcedure:     true,
		apiv1connect.AuthServiceBeginPasskeyRegistrationProcedure:  true,
		apiv1connect.AuthServiceFinishPasskeyRegistrationProcedure: true,
		apiv1connect.AuthServiceGetSessionProcedure:                true,
		apiv1connect.AuthServiceLogoutProcedure:                    true,
	},
}

// csrfExempt procedures are safe without the CSRF header (read-only session bootstrap).
var csrfExempt = map[string]bool{
	apiv1connect.AuthServiceGetSessionProcedure: true,
}

// Guard is the authentication interceptor.
type Guard struct{ D *Deps }

func isSetup(procedure string) bool {
	return strings.HasPrefix(procedure, "/"+apiv1connect.SetupServiceName+"/")
}

func isAuthService(procedure string) bool {
	return strings.HasPrefix(procedure, "/"+apiv1connect.AuthServiceName+"/")
}

// authenticate resolves the caller and enforces the procedure's session requirements.
func (g *Guard) authenticate(ctx context.Context, procedure string, header http.Header) (context.Context, error) {
	ctx = audit.WithUserAgent(ctx, header.Get("User-Agent"))
	if isSetup(procedure) {
		return ctx, nil // SetupService authenticates with the setup token itself.
	}
	d := g.D
	if authz := header.Get("Authorization"); strings.HasPrefix(authz, bearerPrefix) {
		if isAuthService(procedure) {
			return ctx, connect.NewError(connect.CodePermissionDenied, errors.New("API keys cannot use session endpoints"))
		}
		p, err := g.apiKeyPrincipal(ctx, strings.TrimPrefix(authz, bearerPrefix))
		if err != nil {
			return ctx, err
		}
		return authz0(ctx, p), nil
	}

	token := d.Cookies.Read(ctx, header, SessionCookie)
	var sess *store.Session
	if token != "" {
		s, err := d.Sessions.Lookup(ctx, token)
		if err != nil && !errors.Is(err, auth.ErrNoSession) {
			return ctx, d.internal(err)
		}
		sess = s
	}
	public := publicProcedures[procedure]
	if sess == nil {
		if public {
			return ctx, nil
		}
		return ctx, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	}
	st := d.Holder.Get()
	if st == nil {
		return ctx, connect.NewError(connect.CodeUnavailable, errors.New("storage unavailable"))
	}
	user, err := st.Users.Get(ctx, store.System(), sess.UserID)
	if err != nil || user.Disabled {
		_ = d.Sessions.Revoke(ctx, sess)
		return ctx, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	}
	if !public && sess.Stage != store.SessionStageFull && !stageProcedures[sess.Stage][procedure] {
		return ctx, connect.NewError(connect.CodePermissionDenied, errors.New("complete multi-factor authentication first"))
	}
	if !public && !csrfExempt[procedure] {
		if !crypto.EqualHashes(header.Get(CSRFHeader), sess.CSRFToken) {
			return ctx, connect.NewError(connect.CodePermissionDenied, errors.New("missing or invalid CSRF token"))
		}
	}
	p, err := d.Resolver.ForUser(ctx, user, sess)
	if err != nil {
		return ctx, d.internal(err)
	}
	return authz0(ctx, p), nil
}

func authz0(ctx context.Context, p *authz.Principal) context.Context {
	return authz.WithPrincipal(ctx, p)
}

func (g *Guard) apiKeyPrincipal(ctx context.Context, token string) (*authz.Principal, error) {
	d := g.D
	unauth := connect.NewError(connect.CodeUnauthenticated, errors.New("invalid API key"))
	if !strings.HasPrefix(token, APIKeyPrefix) {
		return nil, unauth
	}
	id, secret, ok := strings.Cut(strings.TrimPrefix(token, APIKeyPrefix), ".")
	if !ok || !store.ValidID(id) || len(secret) < 32 {
		return nil, unauth
	}
	if !d.limits.apiKey.Allow(id) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("API key rate limit exceeded"))
	}
	st := d.Holder.Get()
	if st == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("storage unavailable"))
	}
	// Deliberate cross-tenant lookup: the key's org is only known after finding it.
	k, err := st.APIKeys.Get(ctx, store.System(), id)
	if err != nil {
		return nil, unauth
	}
	now := time.Now()
	if !crypto.EqualHashes(k.SecretHash, crypto.HashToken("api_key", secret)) || !k.RevokedAt.IsZero() ||
		(!k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)) {
		return nil, unauth
	}
	if now.Sub(k.LastUsedAt) > time.Minute {
		k.LastUsedAt = now.UTC()
		_ = st.APIKeys.Update(ctx, store.Tenant(k.OrgID), k)
	}
	return d.Resolver.ForAPIKey(ctx, k)
}

// WrapUnary implements connect.Interceptor.
func (g *Guard) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := g.authenticate(ctx, req.Spec().Procedure, req.Header())
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor (no-op on the server).
func (g *Guard) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (g *Guard) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := g.authenticate(ctx, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// clientIP returns the request's client IP string.
func clientIP(ctx context.Context) string {
	if ip := httpx.ClientIPFrom(ctx); ip.IsValid() {
		return ip.String()
	}
	return ""
}
