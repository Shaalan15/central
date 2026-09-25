// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/setup"
	"github.com/Shaalan15/central/server/internal/store"
)

type testEnv struct {
	app    *App
	srv    *httptest.Server
	client apiv1connect.SetupServiceClient
	http   *http.Client
	token  string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Load(config.Flags{Dev: true, DataDir: dir}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(context.Background(), &cfg, log, Build{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if st := a.Holder.Get(); st != nil {
			_ = st.Close()
		}
	})
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	tok, err := setup.ReadTokenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{
		app: a, srv: srv, http: hc, token: tok,
		client: apiv1connect.NewSetupServiceClient(hc, srv.URL+"/api"),
	}
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return connect.CodeUnknown
}

func TestSetupWizardFlow(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	st, err := env.client.GetSetupStatus(ctx, connect.NewRequest(&apiv1.GetSetupStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Msg.GetComplete() || !st.Msg.GetDatabasePreconfigured() || st.Msg.GetNextStep() != apiv1.SetupStep_SETUP_STEP_ENDPOINTS {
		t.Fatalf("status = %v", st.Msg)
	}

	// Every wizard step requires the setup session.
	_, err = env.client.SaveEndpoints(ctx, connect.NewRequest(&apiv1.SaveEndpointsRequest{
		PublicUrl: "https://c.example.com", AgentUrl: "https://c.example.com:9443",
	}))
	if code(err) != connect.CodeUnauthenticated {
		t.Fatalf("SaveEndpoints without session: %v", err)
	}
	if _, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: "wrong"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong token: %v", err)
	}
	if _, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: env.token})); err != nil {
		t.Fatalf("BeginSetup: %v", err)
	}

	// Database is preconfigured in dev mode: the wizard must refuse to change it.
	_, err = env.client.SaveDatabase(ctx, connect.NewRequest(&apiv1.SaveDatabaseRequest{Config: &apiv1.DatabaseConfig{
		Driver: &apiv1.DatabaseConfig_Appwrite{Appwrite: &apiv1.AppwriteConfig{Endpoint: "https://x.cloud.appwrite.io/v1"}},
	}}))
	if code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("SaveDatabase with preconfigured storage: %v", err)
	}

	// Agent URL must be https.
	_, err = env.client.SaveEndpoints(ctx, connect.NewRequest(&apiv1.SaveEndpointsRequest{
		PublicUrl: "https://c.example.com", AgentUrl: "http://c.example.com:9443",
	}))
	if code(err) != connect.CodeInvalidArgument {
		t.Fatalf("http agent URL: %v", err)
	}
	if _, err := env.client.SaveEndpoints(ctx, connect.NewRequest(&apiv1.SaveEndpointsRequest{
		PublicUrl: "https://c.example.com/", AgentUrl: "https://c.example.com:9443",
	})); err != nil {
		t.Fatalf("SaveEndpoints: %v", err)
	}

	owner := &apiv1.CreateOwnerRequest{Email: "Owner@Example.com", DisplayName: "Olivia Owner", OrganizationName: "Acme Ops", Password: "short"}
	if _, err := env.client.CreateOwner(ctx, connect.NewRequest(owner)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("weak password: %v", err)
	}
	owner.Password = "tidy-lantern-orbit-42"
	res, err := env.client.CreateOwner(ctx, connect.NewRequest(owner))
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}

	// The owner, org and membership exist; the password is hashed.
	s := env.app.Holder.Get()
	u, err := s.Users.FindOne(ctx, store.System(), store.Eq("email", "owner@example.com"))
	if err != nil || u.ID != res.Msg.GetUserId() || !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Fatalf("user = %+v, %v", u, err)
	}
	if _, err := s.Memberships.Get(ctx, store.Tenant(res.Msg.GetOrganizationId()), store.DeriveID(res.Msg.GetOrganizationId(), u.ID)); err != nil {
		t.Fatalf("membership: %v", err)
	}

	// Setup is closed for good: token file gone, every RPC refuses.
	if _, err := os.Stat(filepath.Join(env.app.Config.DataDir, setup.TokenFileName)); !os.IsNotExist(err) {
		t.Fatalf("token file still exists: %v", err)
	}
	if _, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: env.token})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("BeginSetup after completion: %v", err)
	}
	if _, err := env.client.CreateOwner(ctx, connect.NewRequest(owner)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("second CreateOwner: %v", err)
	}
	st, _ = env.client.GetSetupStatus(ctx, connect.NewRequest(&apiv1.GetSetupStatusRequest{}))
	if !st.Msg.GetComplete() {
		t.Fatal("status not complete")
	}
}

func TestSetupTokenRateLimited(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	limited := false
	for range 30 {
		_, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: "guess"}))
		if code(err) == connect.CodeResourceExhausted {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("setup token guessing is not rate limited")
	}
	// Even the correct token is refused while limited (no oracle for guessers).
	if _, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: env.token})); code(err) != connect.CodeResourceExhausted {
		t.Fatalf("correct token while limited: %v", err)
	}
}

func TestCrossOriginAPIRejected(t *testing.T) {
	env := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/central.api.v1.SetupService/GetSetupStatus", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := env.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d", resp.StatusCode)
	}
	// Same-origin requests pass.
	req2, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/central.api.v1.SetupService/GetSetupStatus", strings.NewReader("{}"))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", env.srv.URL)
	resp2, err := env.http.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("same-origin status = %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Cache-Control") != "no-store" || resp2.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("API security headers missing")
	}
}

func TestHealthEndpoints(t *testing.T) {
	env := newTestEnv(t)
	for path, want := range map[string]string{"/healthz": "ok", "/readyz": "setup pending"} {
		resp, err := env.http.Get(env.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, body)
		}
	}
}
