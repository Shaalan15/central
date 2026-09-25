// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

func principal(t *testing.T, kind string, bindings ...store.RoleBinding) *Principal {
	t.Helper()
	r := NewResolver(&store.Holder{})
	b, err := r.resolveBindings(context.Background(), "org", bindings)
	if err != nil {
		t.Fatal(err)
	}
	return &Principal{Kind: kind, ID: "p1", OrgID: "org", bindings: b, StepUpWindow: 10 * time.Minute}
}

func TestScopedBindings(t *testing.T) {
	p := principal(t, store.PrincipalUser,
		store.RoleBinding{RoleID: RoleViewer, Scope: store.AgentScopeSpec{AllAgents: true}},
		store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{Tags: []string{"web", "prod"}}},
		store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{GroupIDs: []string{"g-db"}}},
	)
	web := AgentRef{ID: "a1", Tags: []string{"web", "prod", "eu"}}
	webStaging := AgentRef{ID: "a2", Tags: []string{"web", "staging"}}
	db := AgentRef{ID: "a3", GroupID: "g-db"}
	other := AgentRef{ID: "a4"}

	for _, a := range []AgentRef{web, webStaging, db, other} {
		if !p.HasOnAgent(FleetView, a) {
			t.Errorf("viewer everywhere: %s", a.ID)
		}
	}
	cases := map[string]bool{"a1": true, "a2": false, "a3": true, "a4": false}
	for _, a := range []AgentRef{web, webStaging, db, other} {
		if got := p.HasOnAgent(PackagesManage, a); got != cases[a.ID] {
			t.Errorf("packages.manage on %s = %v", a.ID, got)
		}
	}
	if !p.Has(PackagesManage) || p.AllAgents(PackagesManage) {
		t.Error("scoped permission must count as held but not org-wide")
	}
	if p.Has(TerminalOpen) || p.HasOnAgent(TerminalOpen, web) {
		t.Error("operator must not open terminals")
	}
}

func TestAPIKeyForbiddenPermissions(t *testing.T) {
	p := principal(t, store.PrincipalAPIKey, store.RoleBinding{RoleID: RoleAdmin, Scope: store.AgentScopeSpec{AllAgents: true}})
	for perm := range apiKeyForbidden {
		if p.Has(perm) || p.HasOnAgent(perm, AgentRef{ID: "a"}) || p.AllAgents(perm) {
			t.Errorf("API key holds forbidden %s", perm)
		}
	}
	for _, perm := range p.Permissions() {
		if apiKeyForbidden[perm] {
			t.Errorf("Permissions() lists forbidden %s", perm)
		}
	}
	if !p.Has(AgentsApprove) {
		t.Error("admin API key should approve agents")
	}
}

func TestRequireStepUp(t *testing.T) {
	p := principal(t, store.PrincipalUser, store.RoleBinding{RoleID: RoleOwner, Scope: store.AgentScopeSpec{AllAgents: true}})
	p.Session = &store.Session{StepUpAt: time.Now().Add(-time.Hour)}
	ctx := WithPrincipal(context.Background(), p)
	if _, err := Require(ctx, FleetView); err != nil {
		t.Fatalf("non-step-up permission: %v", err)
	}
	_, err := Require(ctx, TerminalOpen)
	var ce *connect.Error
	if err == nil || !asConnect(err, &ce) || ce.Code() != connect.CodeFailedPrecondition || ce.Meta().Get(ReasonHeader) != ReasonStepUpRequired {
		t.Fatalf("expected step-up error, got %v", err)
	}
	p.Session.StepUpAt = time.Now()
	if _, err := Require(ctx, TerminalOpen); err != nil {
		t.Fatalf("fresh step-up: %v", err)
	}
	// Out-of-scope agents look like missing agents.
	scoped := principal(t, store.PrincipalUser, store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{Tags: []string{"web"}}})
	scoped.Session = &store.Session{StepUpAt: time.Now()}
	if _, err := RequireOnAgent(WithPrincipal(context.Background(), scoped), PackagesManage, AgentRef{ID: "x"}); !asConnect(err, &ce) || ce.Code() != connect.CodeNotFound {
		t.Fatalf("out of scope: %v", err)
	}
	if _, err := Require(context.Background(), FleetView); !asConnect(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("no principal: %v", err)
	}
}

func TestCustomRolesAndUnknownPermissions(t *testing.T) {
	ctx := context.Background()
	s := store.Open(memory.New())
	_ = s.Migrate(ctx)
	h := &store.Holder{}
	h.Set(s)
	_ = s.Roles.Create(ctx, store.Tenant("org"), &store.Role{
		ID: "r1", OrgID: "org", Name: "Patcher",
		Permissions: []string{PackagesManage, "made.up.permission"},
	})
	r := NewResolver(h)
	b, err := r.resolveBindings(ctx, "org", []store.RoleBinding{{RoleID: "r1"}, {RoleID: "deleted-role"}})
	if err != nil {
		t.Fatal(err)
	}
	p := &Principal{Kind: store.PrincipalUser, OrgID: "org", bindings: b}
	if !p.Has(PackagesManage) || p.Has("made.up.permission") || len(p.Permissions()) != 1 {
		t.Fatalf("custom role resolution: %v", p.Permissions())
	}
	// A custom role from another org grants nothing.
	b2, _ := r.resolveBindings(ctx, "other-org", []store.RoleBinding{{RoleID: "r1"}})
	if (&Principal{bindings: b2}).Has(PackagesManage) {
		t.Fatal("role leaked across organizations")
	}
}

func asConnect(err error, target **connect.Error) bool {
	ce, ok := err.(*connect.Error) //nolint:errorlint // test helper
	if ok {
		*target = ce
	}
	return ok
}

func TestFingerprintAndPermissionsOn(t *testing.T) {
	a := principal(t, store.PrincipalUser,
		store.RoleBinding{RoleID: RoleViewer, Scope: store.AgentScopeSpec{AllAgents: true}},
		store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{Tags: []string{"web"}}})
	b := principal(t, store.PrincipalUser,
		store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{Tags: []string{"web"}}},
		store.RoleBinding{RoleID: RoleViewer, Scope: store.AgentScopeSpec{AllAgents: true}})
	c := principal(t, store.PrincipalUser,
		store.RoleBinding{RoleID: RoleViewer, Scope: store.AgentScopeSpec{AllAgents: true}},
		store.RoleBinding{RoleID: RoleOperator, Scope: store.AgentScopeSpec{Tags: []string{"db"}}})
	if a.Fingerprint() != b.Fingerprint() || a.Fingerprint() == c.Fingerprint() {
		t.Fatal("fingerprint must ignore binding order and reflect scopes")
	}
	on := a.PermissionsOn(AgentRef{ID: "x", Tags: []string{"web"}})
	off := a.PermissionsOn(AgentRef{ID: "y"})
	if !on[PackagesManage] || off[PackagesManage] || !off[FleetView] {
		t.Fatalf("PermissionsOn: %v / %v", on, off)
	}
}
