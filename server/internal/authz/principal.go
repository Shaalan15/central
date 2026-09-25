// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/Shaalan15/central/server/internal/store"
)

// Principal is the authenticated caller of an API request.
type Principal struct {
	Kind    string // store.PrincipalUser or store.PrincipalAPIKey
	ID      string // user ID or API key ID
	Display string
	OrgID   string // active organization ("" if the user has none)
	// Session is set for browser sessions.
	Session *store.Session
	// StepUpWindow is the org's step-up validity.
	StepUpWindow time.Duration

	bindings []binding
}

type binding struct {
	perms map[string]bool
	scope store.AgentScopeSpec
}

// AgentRef is the subset of an agent needed for scoped authorization.
type AgentRef struct {
	ID      string
	GroupID string
	Tags    []string
}

// Ref returns a store.PrincipalRef for audit and issuer fields.
func (p *Principal) Ref() store.PrincipalRef {
	return store.PrincipalRef{Kind: p.Kind, ID: p.ID, Display: p.Display}
}

// Has reports whether any role binding grants perm (for at least some agents).
func (p *Principal) Has(perm string) bool {
	if p.Kind == store.PrincipalAPIKey && apiKeyForbidden[perm] {
		return false
	}
	for _, b := range p.bindings {
		if b.perms[perm] {
			return true
		}
	}
	return false
}

// HasOnAgent reports whether perm is granted for a specific agent.
func (p *Principal) HasOnAgent(perm string, a AgentRef) bool {
	if p.Kind == store.PrincipalAPIKey && apiKeyForbidden[perm] {
		return false
	}
	for _, b := range p.bindings {
		if b.perms[perm] && scopeMatches(b.scope, a) {
			return true
		}
	}
	return false
}

// AllAgents reports whether perm is granted on every agent (unscoped).
func (p *Principal) AllAgents(perm string) bool {
	for _, b := range p.bindings {
		if b.perms[perm] && b.scope.IsAll() {
			return p.Kind != store.PrincipalAPIKey || !apiKeyForbidden[perm]
		}
	}
	return false
}

func scopeMatches(s store.AgentScopeSpec, a AgentRef) bool {
	if s.IsAll() {
		return true
	}
	if len(s.GroupIDs) > 0 && slices.Contains(s.GroupIDs, a.GroupID) {
		return true
	}
	if len(s.Tags) > 0 {
		for _, t := range s.Tags {
			if !slices.Contains(a.Tags, t) {
				return false
			}
		}
		return true
	}
	return false
}

// Permissions lists every permission the principal holds (in any scope).
func (p *Principal) Permissions() []string {
	set := map[string]bool{}
	for _, b := range p.bindings {
		for perm := range b.perms {
			if p.Kind != store.PrincipalAPIKey || !apiKeyForbidden[perm] {
				set[perm] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for perm := range set {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

// StepUpValidUntil returns when the current step-up expires (zero if none).
func (p *Principal) StepUpValidUntil() time.Time {
	if p.Session == nil || p.Session.StepUpAt.IsZero() {
		return time.Time{}
	}
	return p.Session.StepUpAt.Add(p.StepUpWindow)
}

// apiKeyForbidden are permissions API keys can never exercise, whatever their role: they need
// an interactive human with MFA.
var apiKeyForbidden = map[string]bool{
	TerminalOpen: true, SystemKeyExport: true, APIKeysManage: true, MembersManage: true,
	RolesManage: true, OrgSettings: true,
}

type ctxKey struct{}

// WithPrincipal stores the principal in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// From returns the principal from ctx (nil if unauthenticated).
func From(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// ReasonHeader carries a machine-readable error reason for the UI.
const ReasonHeader = "Central-Reason"

// Error reasons.
const (
	ReasonStepUpRequired = "step_up_required"
	ReasonNoOrganization = "no_organization"
)

func reasonErr(code connect.Code, reason, msg string) *connect.Error {
	err := connect.NewError(code, errors.New(msg))
	err.Meta().Set(ReasonHeader, reason)
	return err
}

// Require returns the principal if it holds perm (and, for step-up permissions used by a
// browser session, has re-authenticated recently).
func Require(ctx context.Context, perm string) (*Principal, error) {
	p := From(ctx)
	if p == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	}
	if p.OrgID == "" {
		return nil, reasonErr(connect.CodePermissionDenied, ReasonNoOrganization, "you are not a member of any organization")
	}
	if !p.Has(perm) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("missing permission "+perm))
	}
	if err := checkStepUp(p, perm); err != nil {
		return nil, err
	}
	return p, nil
}

// RequireOnAgent is Require for an action on a specific agent.
func RequireOnAgent(ctx context.Context, perm string, a AgentRef) (*Principal, error) {
	p, err := Require(ctx, perm)
	if err != nil {
		return nil, err
	}
	if !p.HasOnAgent(perm, a) {
		// Indistinguishable from a missing agent: do not reveal agents outside the scope.
		return nil, connect.NewError(connect.CodeNotFound, errors.New("agent not found"))
	}
	return p, nil
}

// RequireStepUp enforces a recent re-authentication regardless of permission metadata.
func RequireStepUp(p *Principal) error {
	if p.Kind != store.PrincipalUser || p.Session == nil {
		return nil
	}
	if time.Now().Before(p.StepUpValidUntil()) {
		return nil
	}
	return reasonErr(connect.CodeFailedPrecondition, ReasonStepUpRequired, "re-authenticate to continue (step-up required)")
}

func checkStepUp(p *Principal, perm string) error {
	if !RequiresStepUp(perm) {
		return nil
	}
	return RequireStepUp(p)
}

// Resolver builds principals from sessions and API keys.
type Resolver struct {
	holder *store.Holder

	mu    sync.Mutex
	cache map[string]cachedBindings
}

type cachedBindings struct {
	bindings []binding
	window   time.Duration
	at       time.Time
}

// NewResolver returns a resolver.
func NewResolver(holder *store.Holder) *Resolver {
	return &Resolver{holder: holder, cache: map[string]cachedBindings{}}
}

const bindingCacheTTL = 15 * time.Second

// Invalidate drops cached role bindings (call after membership or role changes).
func (r *Resolver) Invalidate() {
	r.mu.Lock()
	r.cache = map[string]cachedBindings{}
	r.mu.Unlock()
}

// ForUser resolves a user's principal in their active org.
func (r *Resolver) ForUser(ctx context.Context, u *store.User, s *store.Session) (*Principal, error) {
	p := &Principal{Kind: store.PrincipalUser, ID: u.ID, Display: u.Email, Session: s, OrgID: s.ActiveOrgID}
	if s.ActiveOrgID == "" {
		return p, nil
	}
	b, window, err := r.bindingsFor(ctx, s.ActiveOrgID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		p.OrgID = "" // membership removed since the session started
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	p.bindings, p.StepUpWindow = b, window
	return p, nil
}

// ForAPIKey resolves an API key principal.
func (r *Resolver) ForAPIKey(ctx context.Context, k *store.APIKey) (*Principal, error) {
	b, err := r.resolveBindings(ctx, k.OrgID, []store.RoleBinding{k.RoleBinding})
	if err != nil {
		return nil, err
	}
	return &Principal{Kind: store.PrincipalAPIKey, ID: k.ID, Display: "api-key:" + k.Name, OrgID: k.OrgID, bindings: b}, nil
}

func (r *Resolver) bindingsFor(ctx context.Context, orgID, userID string) ([]binding, time.Duration, error) {
	key := orgID + "/" + userID
	r.mu.Lock()
	c, ok := r.cache[key]
	r.mu.Unlock()
	if ok && time.Since(c.at) < bindingCacheTTL {
		return c.bindings, c.window, nil
	}
	st := r.holder.Get()
	if st == nil {
		return nil, 0, store.ErrUnavailable
	}
	m, err := st.Memberships.Get(ctx, store.Tenant(orgID), store.DeriveID(orgID, userID))
	if err != nil {
		return nil, 0, err
	}
	org, err := st.Orgs.Get(ctx, store.System(), orgID)
	if err != nil {
		return nil, 0, err
	}
	b, err := r.resolveBindings(ctx, orgID, m.RoleBindings)
	if err != nil {
		return nil, 0, err
	}
	window := time.Duration(org.Settings.StepUpWindowSec) * time.Second
	if window <= 0 || window > 30*time.Minute {
		window = 10 * time.Minute
	}
	r.mu.Lock()
	r.cache[key] = cachedBindings{bindings: b, window: window, at: time.Now()}
	r.mu.Unlock()
	return b, window, nil
}

func (r *Resolver) resolveBindings(ctx context.Context, orgID string, rbs []store.RoleBinding) ([]binding, error) {
	st := r.holder.Get()
	var out []binding
	for _, rb := range rbs {
		perms := map[string]bool{}
		if builtin, ok := Builtin(rb.RoleID); ok {
			for _, p := range builtin.Permissions {
				perms[p] = true
			}
		} else if st != nil {
			role, err := st.Roles.Get(ctx, store.Tenant(orgID), rb.RoleID)
			if errors.Is(err, store.ErrNotFound) {
				continue // deleted role grants nothing
			}
			if err != nil {
				return nil, err
			}
			for _, p := range role.Permissions {
				if _, known := Lookup(p); known {
					perms[p] = true
				}
			}
		}
		out = append(out, binding{perms: perms, scope: rb.Scope})
	}
	return out, nil
}

// HTTPStatusForbidden is exported for non-Connect handlers (WebSocket, downloads).
const HTTPStatusForbidden = http.StatusForbidden
