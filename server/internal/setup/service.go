// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package setup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/auth"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/ratelimit"
	"github.com/Shaalan15/central/server/internal/storage"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/validate"
)

const setupCookie = "central-setup"

// Service implements the SetupService RPCs.
type Service struct {
	apiv1connect.UnimplementedSetupServiceHandler

	State   *State
	Config  *config.Config
	Keyring *crypto.Keyring
	Holder  *store.Holder
	Cookies httpx.Cookies
	Log     *slog.Logger
	Version string
	// OnStoreReady is called after the wizard configured storage (so the app can start
	// store-dependent services).
	OnStoreReady func(*store.Store)
	// OnComplete is called after the owner was created.
	OnComplete func(ctx context.Context, st *store.Store, orgID, userID string)

	stepMu      sync.Mutex
	tokenLimit  *ratelimit.Keyed
	globalLimit *ratelimit.Keyed
	testLimit   *ratelimit.Keyed
	initOnce    sync.Once
}

func (s *Service) init() {
	s.initOnce.Do(func() {
		s.tokenLimit = ratelimit.New(10, 10*time.Minute, 10)
		s.globalLimit = ratelimit.New(100, 10*time.Minute, 30)
		s.testLimit = ratelimit.New(20, 10*time.Minute, 10)
	})
}

var errSetupDone = connect.NewError(connect.CodeFailedPrecondition, errors.New("setup is already complete"))

func (s *Service) nextStep(ctx context.Context) apiv1.SetupStep {
	st := s.Holder.Get()
	switch {
	case s.State.Complete():
		return apiv1.SetupStep_SETUP_STEP_COMPLETE
	case st == nil:
		return apiv1.SetupStep_SETUP_STEP_DATABASE
	}
	if _, err := st.GetSetting(ctx, SettingAgentURL); err != nil {
		return apiv1.SetupStep_SETUP_STEP_ENDPOINTS
	}
	return apiv1.SetupStep_SETUP_STEP_OWNER
}

// GetSetupStatus implements SetupService.
func (s *Service) GetSetupStatus(ctx context.Context, _ *connect.Request[apiv1.GetSetupStatusRequest]) (*connect.Response[apiv1.GetSetupStatusResponse], error) {
	return connect.NewResponse(&apiv1.GetSetupStatusResponse{
		Complete:              s.State.Complete(),
		NextStep:              s.nextStep(ctx),
		DatabasePreconfigured: s.Config.StoragePreconfigured(),
		Version:               s.Version,
	}), nil
}

// BeginSetup implements SetupService.
func (s *Service) BeginSetup(ctx context.Context, req *connect.Request[apiv1.BeginSetupRequest]) (*connect.Response[apiv1.BeginSetupResponse], error) {
	s.init()
	if s.State.Complete() {
		return nil, errSetupDone
	}
	ip := httpx.ClientIPFrom(ctx).String()
	if !s.tokenLimit.Allow(ip) || !s.globalLimit.Allow("global") {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts; wait a few minutes"))
	}
	if !s.State.CheckToken(req.Msg.GetSetupToken()) {
		s.Log.Warn("invalid setup token presented", "client_ip", ip)
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid setup token"))
	}
	secret := s.State.NewSession()
	res := connect.NewResponse(&apiv1.BeginSetupResponse{NextStep: s.nextStep(ctx)})
	s.Cookies.Set(ctx, res.Header(), setupCookie, secret, setupSessionTTL)
	s.Log.Info("setup session started", "client_ip", ip)
	return res, nil
}

func (s *Service) authorize(ctx context.Context, reqHeader connect.AnyRequest) error {
	if s.State.Complete() {
		return errSetupDone
	}
	if !s.State.ValidSession(s.Cookies.Read(ctx, reqHeader.Header(), setupCookie)) {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("enter the setup token first"))
	}
	return nil
}

// TestDatabase implements SetupService.
func (s *Service) TestDatabase(ctx context.Context, req *connect.Request[apiv1.TestDatabaseRequest]) (*connect.Response[apiv1.TestDatabaseResponse], error) {
	s.init()
	if err := s.authorize(ctx, req); err != nil {
		return nil, err
	}
	if !s.testLimit.Allow("test") {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many connection tests; wait a minute"))
	}
	cfg, key, err := s.appwriteConfig(req.Msg.GetConfig())
	if err != nil {
		return nil, err
	}
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r := storage.TestAppwrite(tctx, cfg, key)
	return connect.NewResponse(testResponse(r)), nil
}

// SaveDatabase implements SetupService.
func (s *Service) SaveDatabase(ctx context.Context, req *connect.Request[apiv1.SaveDatabaseRequest]) (*connect.Response[apiv1.SaveDatabaseResponse], error) {
	if err := s.authorize(ctx, req); err != nil {
		return nil, err
	}
	if s.Config.StoragePreconfigured() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("storage is configured by the operator and cannot be changed here"))
	}
	s.stepMu.Lock()
	defer s.stepMu.Unlock()
	if s.Holder.Get() != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("storage is already configured"))
	}
	cfg, key, err := s.appwriteConfig(req.Msg.GetConfig())
	if err != nil {
		return nil, err
	}
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	r := storage.TestAppwrite(tctx, cfg, key)
	cancel()
	if !r.OK || !r.VersionSupported || len(r.MissingScopes) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("database check failed: %s", describeFailure(r)))
	}
	sealed, err := s.Keyring.SealString(key.Reveal(), storage.AppwriteKeyPurpose)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not encrypt the API key"))
	}
	cfg.APIKey = ""
	cfg.APIKeySealed = sealed
	sc := config.StorageConfig{Driver: config.DriverAppwrite, Appwrite: cfg}
	st, err := storage.Open(ctx, sc, s.Keyring)
	if err != nil {
		s.Log.Error("setup: opening storage failed", "error", err)
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("could not initialize the database; check the server log"))
	}
	if err := config.WriteState(s.Config.DataDir, config.StateFile{Storage: sc}); err != nil {
		_ = st.Close()
		s.Log.Error("setup: writing state file failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not save the configuration"))
	}
	s.Config.Storage = sc
	s.Holder.Set(st)
	if s.OnStoreReady != nil {
		s.OnStoreReady(st)
	}
	s.Log.Info("setup: storage configured", "driver", "appwrite", "endpoint", cfg.Endpoint, "project", cfg.ProjectID)
	return connect.NewResponse(&apiv1.SaveDatabaseResponse{
		SchemaVersion: store.SchemaVersion, NextStep: s.nextStep(ctx),
	}), nil
}

// SaveEndpoints implements SetupService.
func (s *Service) SaveEndpoints(ctx context.Context, req *connect.Request[apiv1.SaveEndpointsRequest]) (*connect.Response[apiv1.SaveEndpointsResponse], error) {
	if err := s.authorize(ctx, req); err != nil {
		return nil, err
	}
	st := s.Holder.Get()
	if st == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("configure the database first"))
	}
	pub, err := s.checkURL("public URL", req.Msg.GetPublicUrl())
	if err != nil {
		return nil, err
	}
	agentURL, err := s.checkURL("agent URL", req.Msg.GetAgentUrl())
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(agentURL, "https://") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the agent URL must use https (agents always use TLS)"))
	}
	if err := st.PutSetting(ctx, SettingPublicURL, pub); err != nil {
		return nil, internal(s.Log, err)
	}
	if err := st.PutSetting(ctx, SettingAgentURL, agentURL); err != nil {
		return nil, internal(s.Log, err)
	}
	return connect.NewResponse(&apiv1.SaveEndpointsResponse{NextStep: s.nextStep(ctx)}), nil
}

// CreateOwner implements SetupService.
func (s *Service) CreateOwner(ctx context.Context, req *connect.Request[apiv1.CreateOwnerRequest]) (*connect.Response[apiv1.CreateOwnerResponse], error) {
	if err := s.authorize(ctx, req); err != nil {
		return nil, err
	}
	st := s.Holder.Get()
	if st == nil || s.nextStep(ctx) != apiv1.SetupStep_SETUP_STEP_OWNER {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("complete the previous setup steps first"))
	}
	m := req.Msg
	email, err := validate.Email(m.GetEmail())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	name, err := validate.DisplayText("display name", m.GetDisplayName(), 100)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	orgName, err := validate.DisplayText("organization name", m.GetOrganizationName(), 100)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := auth.CheckPasswordPolicy(m.GetPassword(), email, name, orgName); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.stepMu.Lock()
	defer s.stepMu.Unlock()
	if s.State.Complete() {
		return nil, errSetupDone
	}
	if n, err := st.Users.Count(ctx, store.System(), store.Query{}); err != nil {
		return nil, internal(s.Log, err)
	} else if n > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("an account already exists"))
	}
	hash, err := auth.HashPassword(ctx, m.GetPassword())
	if err != nil {
		return nil, internal(s.Log, err)
	}
	now := time.Now().UTC()
	org := &store.Org{ID: store.NewID(), Name: orgName, Settings: store.DefaultOrgSettings(), CreatedAt: now, UpdatedAt: now}
	user := &store.User{
		ID: store.NewID(), Email: email, DisplayName: name, PasswordHash: hash,
		CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now, WebAuthnID: crypto.RandomBytes(32),
	}
	mem := &store.Membership{
		ID: store.DeriveID(org.ID, user.ID), OrgID: org.ID, UserID: user.ID, JoinedAt: now,
		RoleBindings: []store.RoleBinding{{RoleID: authz.RoleOwner, Scope: store.AgentScopeSpec{AllAgents: true}}},
	}
	if err := st.Orgs.Create(ctx, store.System(), org); err != nil {
		return nil, internal(s.Log, err)
	}
	if err := st.Users.Create(ctx, store.System(), user); err != nil {
		return nil, internal(s.Log, err)
	}
	if err := st.Memberships.Create(ctx, store.Tenant(org.ID), mem); err != nil {
		return nil, internal(s.Log, err)
	}
	if err := s.State.MarkComplete(ctx, st); err != nil {
		return nil, internal(s.Log, err)
	}
	if s.OnComplete != nil {
		s.OnComplete(ctx, st, org.ID, user.ID)
	}
	res := connect.NewResponse(&apiv1.CreateOwnerResponse{UserId: user.ID, OrganizationId: org.ID})
	s.Cookies.Clear(ctx, res.Header(), setupCookie)
	s.Log.Info("setup: owner account created", "user_id", user.ID, "org_id", org.ID)
	return res, nil
}

var projectIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,35}$`)

func (s *Service) appwriteConfig(dc *apiv1.DatabaseConfig) (config.AppwriteConfig, crypto.Secret, error) {
	aw := dc.GetAppwrite()
	if aw == nil {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("only Appwrite is supported"))
	}
	endpoint := strings.TrimRight(strings.TrimSpace(aw.GetEndpoint()), "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("endpoint must be a URL like https://fra.cloud.appwrite.io/v1"))
	}
	plainHTTPAllowed := u.Scheme == "http" && (s.Config.Dev || isLoopback(u.Hostname()))
	if u.Scheme != "https" && !plainHTTPAllowed {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("endpoint must use https (the API key would otherwise travel in clear text)"))
	}
	if !strings.HasSuffix(u.Path, "/v1") {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("endpoint must end with /v1"))
	}
	if aw.GetDeployment() == apiv1.AppwriteDeployment_APPWRITE_DEPLOYMENT_CLOUD && !strings.HasSuffix(u.Hostname(), ".appwrite.io") && u.Hostname() != "cloud.appwrite.io" {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("cloud endpoints look like https://<region>.cloud.appwrite.io/v1"))
	}
	if !projectIDRe.MatchString(aw.GetProjectId()) {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid project ID"))
	}
	dbID := aw.GetDatabaseId()
	if dbID == "" {
		dbID = "central"
	}
	if !projectIDRe.MatchString(dbID) {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid database ID"))
	}
	key := strings.TrimSpace(aw.GetApiKey())
	if len(key) < 16 || len(key) > 1024 {
		return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("an Appwrite server API key is required"))
	}
	cfg := config.AppwriteConfig{Endpoint: endpoint, ProjectID: aw.GetProjectId(), DatabaseID: dbID}
	if pem := strings.TrimSpace(aw.GetCaBundlePem()); pem != "" {
		path, err := s.writeCABundle(pem)
		if err != nil {
			return config.AppwriteConfig{}, "", connect.NewError(connect.CodeInvalidArgument, err)
		}
		cfg.CABundleFile = path
	}
	return cfg, crypto.Secret(key), nil
}

func (s *Service) writeCABundle(pem string) (string, error) {
	if len(pem) > 256*1024 || !strings.Contains(pem, "-----BEGIN CERTIFICATE-----") {
		return "", errors.New("the CA bundle must contain PEM certificates")
	}
	path := s.Config.DataDir + "/appwrite-ca.pem"
	if err := crypto.WriteFileAtomic(path, []byte(pem+"\n"), 0o600); err != nil {
		return "", errors.New("could not store the CA bundle")
	}
	return path, nil
}

func (s *Service) checkURL(field, raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if err := config.ValidateBaseURL(raw); err != nil {
		return "", connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s: %w", field, err))
	}
	if !s.Config.Dev && strings.HasPrefix(raw, "http://") {
		u, _ := url.Parse(raw)
		if !isLoopback(u.Hostname()) {
			return "", connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s must use https", field))
		}
	}
	return raw, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func testResponse(r storage.TestResult) *apiv1.TestDatabaseResponse {
	return &apiv1.TestDatabaseResponse{
		Ok: r.OK, ServerVersion: r.ServerVersion, VersionSupported: r.VersionSupported,
		MissingScopes: r.MissingScopes, DatabaseExists: r.DatabaseExists, Error: r.Error,
	}
}

func describeFailure(r storage.TestResult) string {
	switch {
	case r.Error != "":
		return r.Error
	case !r.VersionSupported:
		return "Appwrite " + r.ServerVersion + " is not supported (2.0 or newer required)"
	case len(r.MissingScopes) > 0:
		return "the API key is missing scopes: " + strings.Join(r.MissingScopes, ", ")
	}
	return "unknown error"
}

func internal(log *slog.Logger, err error) error {
	log.Error("setup: internal error", "error", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error; check the server log"))
}
