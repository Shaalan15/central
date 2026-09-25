// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
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
	"github.com/Shaalan15/central/server/internal/store/appwrite/appwritefake"
)

// TestSetupWizardWithAppwrite drives the production (non-dev) wizard over HTTPS against the fake
// Appwrite: test connection, save (migrate + sealed key), endpoints, owner, then restarts the
// server from its state file to prove the configuration persists.
func TestSetupWizardWithAppwrite(t *testing.T) {
	fake, awSrv := appwritefake.New(t)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	noEnv := func(string) string { return "" }

	cfg, err := config.Load(config.Flags{DataDir: dir}, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(ctx, &cfg, log, Build{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(a.Handler())
	defer srv.Close()
	hc := srv.Client()
	hc.Jar, _ = cookiejar.New(nil)
	client := apiv1connect.NewSetupServiceClient(hc, srv.URL+"/api")

	st, err := client.GetSetupStatus(ctx, connect.NewRequest(&apiv1.GetSetupStatusRequest{}))
	if err != nil || st.Msg.GetNextStep() != apiv1.SetupStep_SETUP_STEP_DATABASE || st.Msg.GetDatabasePreconfigured() {
		t.Fatalf("status = %v, %v", st.Msg, err)
	}
	token, err := setup.ReadTokenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: token})); err != nil {
		t.Fatalf("BeginSetup: %v", err)
	}

	dbCfg := &apiv1.DatabaseConfig{Driver: &apiv1.DatabaseConfig_Appwrite{Appwrite: &apiv1.AppwriteConfig{
		Deployment: apiv1.AppwriteDeployment_APPWRITE_DEPLOYMENT_SELF_HOSTED,
		Endpoint:   awSrv.URL + "/v1", ProjectId: fake.Project, ApiKey: fake.Key, CreateDatabase: true,
	}}}

	// A plain-http, non-loopback endpoint is refused (API key would travel in clear text).
	bad := &apiv1.DatabaseConfig{Driver: &apiv1.DatabaseConfig_Appwrite{Appwrite: &apiv1.AppwriteConfig{
		Endpoint: "http://appwrite.example.com/v1", ProjectId: "p", ApiKey: fake.Key,
	}}}
	if _, err := client.TestDatabase(ctx, connect.NewRequest(&apiv1.TestDatabaseRequest{Config: bad})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("plain http endpoint: %v", err)
	}

	tr, err := client.TestDatabase(ctx, connect.NewRequest(&apiv1.TestDatabaseRequest{Config: dbCfg}))
	if err != nil || !tr.Msg.GetOk() || tr.Msg.GetServerVersion() != "2.0.3" {
		t.Fatalf("TestDatabase = %v, %v", tr.Msg, err)
	}
	if _, err := client.SaveDatabase(ctx, connect.NewRequest(&apiv1.SaveDatabaseRequest{Config: dbCfg})); err != nil {
		t.Fatalf("SaveDatabase: %v", err)
	}
	if n := fake.Tables("central"); n != len(store.AllSchemas()) {
		t.Fatalf("migrated %d tables", n)
	}
	state, err := os.ReadFile(filepath.Join(dir, config.StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), fake.Key) || !strings.Contains(string(state), "api_key_sealed = \"cenc1.") {
		t.Fatalf("state file must contain only the sealed key:\n%s", state)
	}

	if _, err := client.SaveEndpoints(ctx, connect.NewRequest(&apiv1.SaveEndpointsRequest{
		PublicUrl: "https://central.example.com", AgentUrl: "https://central.example.com:9443",
	})); err != nil {
		t.Fatalf("SaveEndpoints: %v", err)
	}
	if _, err := client.CreateOwner(ctx, connect.NewRequest(&apiv1.CreateOwnerRequest{
		Email: "owner@example.com", DisplayName: "Owner", OrganizationName: "Acme", Password: "tidy-lantern-orbit-42",
	})); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	users, _ := fake.Table("central", "users")
	if users.Rows != 1 {
		t.Fatalf("users rows = %d", users.Rows)
	}

	// Restart from disk: the state file + master key reopen Appwrite and setup stays complete.
	_ = a.Holder.Get().Close()
	cfg2, err := config.Load(config.Flags{DataDir: dir}, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New(ctx, &cfg2, log, Build{Version: "test"})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !a2.Setup.Complete() || a2.Holder.Get() == nil || a2.Holder.Get().Info().Name != "appwrite" {
		t.Fatal("restarted instance lost its configuration")
	}
	u, err := a2.Holder.Get().Users.FindOne(ctx, store.System(), store.Eq("email", "owner@example.com"))
	if err != nil || u.DisplayName != "Owner" {
		t.Fatalf("owner after restart: %+v %v", u, err)
	}
	_ = a2.Holder.Get().Close()

	// Cookies were issued with the __Host- prefix and Secure over HTTPS.
	resp, err := hc.Post(srv.URL+"/api/central.api.v1.SetupService/BeginSetup", "application/json", strings.NewReader(`{"setupToken":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("setup accepted after completion")
	}
}
