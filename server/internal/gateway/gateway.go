// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway serves the agent listener: TLS 1.3 only, with certificates from Central's
// internal CA. EnrollmentService works without a client certificate; AgentService requires a
// client certificate issued by the CA whose identity (organization, agent, serial) matches an
// active agent. The identity is checked during every TLS handshake and again on every request,
// so a revoked agent cannot open new streams even on an existing connection.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/ratelimit"
	"github.com/Shaalan15/central/server/internal/sessions"
	"github.com/Shaalan15/central/server/internal/store"
)

// Limits and timeouts.
const (
	maxConnections      = 20_000
	enrollReadMaxBytes  = 64 << 10
	agentReadMaxBytes   = 16 << 20
	helloTimeout        = 30 * time.Second
	defaultIdleTimeout  = 120 * time.Second
	writeTimeout        = 30 * time.Second
	outboundQueue       = 256
	hostsRefresh        = time.Minute
	renewalGrace        = 24 * time.Hour
	shutdownGracePeriod = 5 * time.Second
)

// Gateway is the agent listener.
type Gateway struct {
	Holder   *store.Holder
	PKI      *pki.Authority
	Fleet    *fleet.Index
	Enroll   *enrollment.Service
	Dispatch *dispatch.Dispatcher
	Sessions *sessions.Manager
	Bus      bus.Bus
	Audit    *audit.Recorder
	Log      *slog.Logger
	// AgentURL returns the configured agent URL (its host goes into the server certificate).
	AgentURL func(ctx context.Context) string
	// MinAgentVersion is announced in HelloAck.
	MinAgentVersion string
	// IdleTimeout closes streams without traffic (default 120s).
	IdleTimeout time.Duration
	// Relaxed raises the per-IP enrollment limits (development mode only, for load tests from
	// one machine).
	Relaxed bool

	limitsOnce sync.Once
	limits     struct {
		enrollIP, enrollToken, pollIP, connect, renew, events *ratelimit.Keyed
	}

	hostsMu    sync.Mutex
	hosts      []string
	hostsAt    time.Time
	shutdownMu sync.Mutex
	shutdown   bool
}

func (g *Gateway) init() {
	g.limitsOnce.Do(func() {
		g.limits.enrollIP = ratelimit.New(60, 10*time.Minute, 30)
		g.limits.enrollToken = ratelimit.New(600, 10*time.Minute, 100)
		g.limits.pollIP = ratelimit.New(1200, 10*time.Minute, 200)
		if g.Relaxed {
			g.limits.enrollIP = ratelimit.New(20_000, 10*time.Minute, 2000)
			g.limits.enrollToken = ratelimit.New(20_000, 10*time.Minute, 2000)
			g.limits.pollIP = ratelimit.New(100_000, 10*time.Minute, 5000)
		}
		g.limits.connect = ratelimit.New(20, 10*time.Minute, 10)
		g.limits.renew = ratelimit.New(6, time.Hour, 3)
		g.limits.events = ratelimit.New(60, time.Minute, 30)
		if g.IdleTimeout == 0 {
			g.IdleTimeout = defaultIdleTimeout
		}
	})
}

func (g *Gateway) certHosts(ctx context.Context) []string {
	g.hostsMu.Lock()
	defer g.hostsMu.Unlock()
	if g.hosts != nil && time.Since(g.hostsAt) < hostsRefresh {
		return g.hosts
	}
	hosts := []string{}
	if g.AgentURL != nil {
		if u, err := url.Parse(g.AgentURL(ctx)); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	g.hosts, g.hostsAt = hosts, time.Now()
	return hosts
}

// TLSConfig returns the listener's TLS configuration. Handshakes fail until the PKI is loaded
// (i.e. until storage has been configured).
func (g *Gateway) TLSConfig() *tls.Config {
	g.init()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !g.PKI.Loaded() {
				return nil, errors.New("gateway: not ready (setup incomplete)")
			}
			cert, err := g.PKI.ServerCertificate(g.certHosts(hello.Context()))
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:             tls.VersionTLS13,
				NextProtos:             []string{"h2", "http/1.1"},
				Certificates:           []tls.Certificate{*cert},
				ClientAuth:             tls.VerifyClientCertIfGiven,
				ClientCAs:              g.PKI.CAPool(),
				SessionTicketsDisabled: true,
				VerifyConnection:       g.verifyConnection,
			}, nil
		},
	}
}

// verifyConnection runs on every handshake after chain verification: a presented client
// certificate must belong to an active agent and be its current certificate.
func (g *Gateway) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return nil // enrollment
	}
	if len(cs.VerifiedChains) == 0 {
		return errors.New("gateway: client certificate not verified")
	}
	id, err := pki.IdentityFromCert(cs.PeerCertificates[0])
	if err != nil {
		return err
	}
	if err := g.Fleet.CheckIdentity(id.OrgID, id.AgentID, id.Serial); err != nil {
		g.Log.Info("gateway: rejected agent certificate", "agent", id.AgentID, "serial", id.Serial, "reason", err)
		return err
	}
	return nil
}

type identityKey struct{}

type identity struct {
	pki.AgentIdentity
	NotAfter time.Time
	ctl      *streamControl
}

func identityFrom(ctx context.Context) *identity {
	id, _ := ctx.Value(identityKey{}).(*identity)
	return id
}

// streamControl lets a stream handler abort blocked reads and writes of its HTTP/2 stream.
type streamControl struct {
	body interface{ Close() error }
	rc   *http.ResponseController
}

func (c *streamControl) abortRead() {
	if c != nil && c.body != nil {
		_ = c.body.Close()
	}
}

func (c *streamControl) writeDeadline(t time.Time) {
	if c != nil && c.rc != nil {
		_ = c.rc.SetWriteDeadline(t)
	}
}

var errorWriter = connect.NewErrorWriter()

func (g *Gateway) authenticate(next http.Handler) http.Handler {
	agentPrefix := "/" + agentv1connect.AgentServiceName + "/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, agentPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		fail := func(code connect.Code, msg string) {
			_ = errorWriter.Write(w, r, connect.NewError(code, errors.New(msg)))
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			fail(connect.CodeUnauthenticated, "a client certificate is required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id, err := pki.IdentityFromCert(leaf)
		if err != nil {
			fail(connect.CodeUnauthenticated, "the client certificate has no agent identity")
			return
		}
		if err := g.Fleet.CheckIdentity(id.OrgID, id.AgentID, id.Serial); err != nil {
			if errors.Is(err, fleet.ErrRevoked) {
				fail(connect.CodePermissionDenied, "this agent has been revoked")
				return
			}
			fail(connect.CodeUnauthenticated, "the client certificate is no longer valid for this agent")
			return
		}
		ident := &identity{AgentIdentity: id, NotAfter: leaf.NotAfter, ctl: &streamControl{body: r.Body, rc: http.NewResponseController(w)}}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, ident)))
	})
}

// Handler returns the HTTP handler for the agent listener.
func (g *Gateway) Handler() http.Handler {
	g.init()
	mux := http.NewServeMux()
	mux.Handle(agentv1connect.NewEnrollmentServiceHandler(&enrollmentService{g: g},
		connect.WithReadMaxBytes(enrollReadMaxBytes)))
	mux.Handle(agentv1connect.NewAgentServiceHandler(&agentService{g: g},
		connect.WithReadMaxBytes(agentReadMaxBytes), connect.WithCompressMinBytes(4096)))
	return httpx.Chain(g.authenticate(mux),
		httpx.ClientIP(nil), // agents connect directly (TCP passthrough): the peer address is the source
		httpx.Recover(g.Log),
	)
}

// limitListener bounds concurrent connections.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// Serve runs the agent listener on ln until ctx is cancelled.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           g.Handler(),
		TLSConfig:         g.TLSConfig(), //nolint:contextcheck // handshakes use the ClientHello context
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: 16,
			SendPingTimeout:      60 * time.Second,
			PingTimeout:          20 * time.Second,
			WriteByteTimeout:     60 * time.Second,
		},
		ErrorLog:    slog.NewLogLogger(g.Log.Handler(), slog.LevelDebug),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeTLS(&limitListener{Listener: ln, sem: make(chan struct{}, maxConnections)}, "", "")
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	g.shutdownMu.Lock()
	g.shutdown = true
	g.shutdownMu.Unlock()
	g.Fleet.CloseAll(agentv1.Disconnect_REASON_SHUTDOWN, "Central is restarting")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGracePeriod)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}

func (g *Gateway) shuttingDown() bool {
	g.shutdownMu.Lock()
	defer g.shutdownMu.Unlock()
	return g.shutdown
}
