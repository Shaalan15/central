// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package app wires Central's components together and runs the listeners.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/api"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/auth"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/setup"
	"github.com/Shaalan15/central/server/internal/storage"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/tlsutil"
	"github.com/Shaalan15/central/server/internal/webui"
)

// Build information, set by main.
type Build struct {
	Version string
	Commit  string
}

// App is a running Central instance.
type App struct {
	Config  *config.Config
	Log     *slog.Logger
	Build   Build
	Keyring *crypto.Keyring
	Holder  *store.Holder
	Bus     *bus.Memory
	Setup   *setup.State
	Cookies httpx.Cookies
	Started time.Time

	Deps *api.Deps

	trusted []netip.Prefix
	webui   *webui.Handler

	storeReadyOnce sync.Once
	bgCtx          context.Context
}

// New initializes an App: data directory, master key, storage (if configured) and setup state.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, build Build) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("app: data dir: %w", err)
	}
	kr, err := loadKeyring(cfg, log)
	if err != nil {
		return nil, err
	}
	a := &App{
		Config: cfg, Log: log, Build: build, Keyring: kr, Holder: &store.Holder{},
		Bus: bus.NewMemory(), Cookies: httpx.Cookies{Dev: cfg.Dev}, Started: time.Now().UTC(),
	}
	for _, p := range cfg.HTTP.TrustedProxies {
		pfx, err := config.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		a.trusted = append(a.trusted, pfx)
	}
	if a.webui, err = webui.New(); err != nil {
		return nil, fmt.Errorf("app: web UI: %w", err)
	}
	if cfg.Dev {
		log.Warn("DEVELOPMENT MODE: in-memory storage persisted to disk, relaxed cookie security on plain HTTP. Never use in production.",
			"data_dir", cfg.DataDir)
	}
	if cfg.StorageConfigured() {
		st, err := storage.Open(ctx, cfg.Storage, kr)
		if err != nil {
			return nil, err
		}
		a.Holder.Set(st)
		log.Info("storage ready", "driver", st.Info().Name, "endpoint", st.Info().Endpoint)
	}
	a.Setup = setup.NewState(cfg.DataDir, a.Holder, log)
	if err := a.Setup.Init(ctx); err != nil {
		return nil, err
	}
	var extraOrigins []string
	if cfg.Dev {
		extraOrigins = []string{"http://localhost:4200", "http://localhost:8080"}
	}
	a.Deps = &api.Deps{
		Config: cfg, Log: log, Holder: a.Holder, Keyring: kr, Cookies: a.Cookies, Setup: a.Setup,
		Sessions: auth.NewSessions(a.Holder), Resolver: authz.NewResolver(a.Holder),
		Audit: audit.NewRecorder(a.Holder, log), Version: build.Version, Commit: build.Commit, Started: a.Started,
	}
	a.Deps.Passkeys = auth.NewPasskeys(a.Holder, a.Deps.PublicURL, extraOrigins)
	a.Deps.Init()
	a.bgCtx = ctx
	if st := a.Holder.Get(); st != nil {
		a.onStoreReady(st)
	}
	return a, nil
}

func loadKeyring(cfg *config.Config, log *slog.Logger) (*crypto.Keyring, error) {
	var key []byte
	if cfg.MasterKey != "" {
		k, err := crypto.DecodeMasterKey(cfg.MasterKey.Reveal())
		if err != nil {
			return nil, fmt.Errorf("app: CENTRAL_MASTER_KEY: %w", err)
		}
		key = k
	} else {
		k, created, err := crypto.LoadOrCreateMasterKey(cfg.MasterKeyFile)
		if err != nil {
			return nil, err
		}
		if created {
			log.Warn("generated a new master key: BACK IT UP. Without it, encrypted secrets and the agent CA cannot be recovered.",
				"path", cfg.MasterKeyFile)
		}
		key = k
	}
	return crypto.NewKeyring(key)
}

// onStoreReady starts components that need storage. Called once, either at startup or when the
// setup wizard configures storage.
func (a *App) onStoreReady(st *store.Store) {
	a.storeReadyOnce.Do(func() {
		_ = st
		go a.housekeeping(a.bgCtx)
	})
}

// housekeeping runs periodic maintenance (expired sessions).
func (a *App) housekeeping(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.Deps == nil || !a.Setup.Complete() {
				continue
			}
			if n, err := a.Deps.Sessions.DeleteExpired(ctx); err != nil {
				a.Log.Warn("housekeeping: deleting expired sessions failed", "error", err)
			} else if n > 0 {
				a.Log.Debug("housekeeping: deleted expired sessions", "count", n)
			}
		}
	}
}

// Handler builds the HTTP handler for the UI/API listener.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	opts := []connect.HandlerOption{
		connect.WithReadMaxBytes(4 << 20),
		connect.WithCompressMinBytes(1024),
		connect.WithInterceptors(&api.Guard{D: a.Deps}),
	}
	d := a.Deps

	setupSvc := &setup.Service{
		State: a.Setup, Config: a.Config, Keyring: a.Keyring, Holder: a.Holder,
		Cookies: a.Cookies, Log: a.Log, Version: a.Build.Version,
		OnStoreReady: a.onStoreReady,
		OnComplete: func(ctx context.Context, _ *store.Store, orgID, userID string) {
			_ = d.Audit.Record(ctx, audit.Event{
				OrgID: orgID, Actor: store.PrincipalRef{Kind: store.PrincipalSystem, ID: "setup", Display: "setup wizard"},
				Action: "setup.completed", TargetType: "user", TargetID: userID,
			})
		},
	}
	mux.Handle(apiv1connect.NewSetupServiceHandler(setupSvc, opts...))
	mux.Handle(apiv1connect.NewAuthServiceHandler(&api.AuthService{D: d}, opts...))
	mux.Handle(apiv1connect.NewOrganizationServiceHandler(&api.OrgService{D: d}, opts...))
	mux.Handle(apiv1connect.NewMemberServiceHandler(&api.MemberService{D: d}, opts...))
	mux.Handle(apiv1connect.NewRoleServiceHandler(&api.RoleService{D: d}, opts...))
	mux.Handle(apiv1connect.NewApiKeyServiceHandler(&api.APIKeyService{D: d}, opts...))
	mux.Handle(apiv1connect.NewAuditServiceHandler(&api.AuditService{D: d}, opts...))
	mux.Handle(apiv1connect.NewSystemServiceHandler(&api.SystemService{D: d}, opts...))

	apiHandler := httpx.Chain(mux,
		httpx.NoStore(),
		httpx.SameOrigin(a.allowedOrigins),
		httpx.MaxBytes(8<<20),
	)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	root.HandleFunc("GET /readyz", a.ready)
	root.Handle("/api/", http.StripPrefix("/api", apiHandler))
	root.Handle("/", a.webui)

	return httpx.Chain(root,
		httpx.RequestID(),
		httpx.ClientIP(a.trusted),
		httpx.AccessLog(a.Log),
		httpx.Recover(a.Log),
		httpx.BaseSecurityHeaders(true),
	)
}

func (a *App) allowedOrigins() []string {
	out := []string{}
	if a.Config.PublicURL != "" {
		out = append(out, a.Config.PublicURL)
	}
	if st := a.Holder.Get(); st != nil {
		if v, err := st.GetSetting(context.Background(), setup.SettingPublicURL); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if st := a.Holder.Get(); st != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("storage unavailable\n"))
			return
		}
	}
	if !a.Setup.Complete() {
		_, _ = w.Write([]byte("ready (setup pending)\n"))
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (a *App) Run(ctx context.Context) error {
	tlsCfg, err := tlsutil.ForUI(*a.Config)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              a.Config.HTTP.Addr,
		Handler:           a.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.Config.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("app: listen %s: %w", a.Config.HTTP.Addr, err)
	}
	a.Log.Info("web UI and API listening", "addr", ln.Addr().String(), "tls", a.Config.HTTP.TLS.Mode,
		"version", a.Build.Version)

	errCh := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			errCh <- srv.ServeTLS(ln, "", "")
		} else {
			errCh <- srv.Serve(ln)
		}
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	a.Log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if st := a.Holder.Get(); st != nil {
		if err := st.Close(); err != nil {
			a.Log.Error("closing storage", "error", err)
		}
	}
	return nil
}
