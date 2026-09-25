// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/store"
)

// ProtocolVersion is the agent protocol version Central speaks.
const ProtocolVersion = 1

type agentService struct {
	agentv1connect.UnimplementedAgentServiceHandler
	g *Gateway
}

var errQueueFull = errors.New("gateway: agent send queue full")

// conn is one agent control stream. Messages are queued and written by a single sender.
type conn struct {
	out  chan *agentv1.CentralMessage
	done chan struct{}
	once sync.Once

	mu         sync.Mutex
	disconnect *agentv1.Disconnect
}

func newConn() *conn {
	return &conn{out: make(chan *agentv1.CentralMessage, outboundQueue), done: make(chan struct{})}
}

// Send implements fleet.Conn.
func (c *conn) Send(m *agentv1.CentralMessage) error {
	select {
	case <-c.done:
		return errors.New("gateway: stream closed")
	default:
	}
	select {
	case c.out <- m:
		return nil
	default:
		return errQueueFull
	}
}

// Close implements fleet.Conn.
func (c *conn) Close(reason agentv1.Disconnect_Reason, message string) {
	c.once.Do(func() {
		if reason != agentv1.Disconnect_REASON_UNSPECIFIED {
			d := &agentv1.Disconnect{Reason: reason, Message: message}
			if reason == agentv1.Disconnect_REASON_SHUTDOWN {
				// Spread reconnects after a restart.
				d.RetryAfter = durationpb.New(5*time.Second + rand.N(25*time.Second)) //nolint:gosec // jitter only
			}
			c.mu.Lock()
			c.disconnect = d
			c.mu.Unlock()
		}
		close(c.done)
	})
}

func (c *conn) goodbye() *agentv1.Disconnect {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnect
}

func protocolError(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// Connect implements AgentService.
func (s *agentService) Connect(ctx context.Context, stream *connect.BidiStream[agentv1.AgentMessage, agentv1.CentralMessage]) error {
	g := s.g
	id := identityFrom(ctx)
	if id == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("a client certificate is required"))
	}
	if g.shuttingDown() {
		return connect.NewError(connect.CodeUnavailable, errors.New("central is shutting down"))
	}
	if !g.limits.connect.Allow(id.AgentID) {
		return errRateLimited
	}

	// Reader: forwards agent messages until the stream ends or we abort it.
	msgs := make(chan *agentv1.AgentMessage, 16)
	recvErr := make(chan error, 1)
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			m, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-stop:
				return
			}
		}
	}()
	stopReader := func() {
		close(stop)
		id.ctl.abortRead()
		<-readerDone
	}

	var hello *agentv1.Hello
	timer := time.NewTimer(helloTimeout)
	select {
	case m := <-msgs:
		hello = m.GetHello()
	case <-recvErr:
	case <-timer.C:
	case <-ctx.Done():
	}
	timer.Stop()
	if hello == nil {
		stopReader()
		return protocolError("the first message must be hello")
	}
	c, running, err := s.accept(ctx, id, hello)
	if err != nil {
		stopReader()
		return err
	}

	// Sender: the only goroutine that writes to the stream.
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		send := func(m *agentv1.CentralMessage) error {
			id.ctl.writeDeadline(time.Now().Add(writeTimeout))
			defer id.ctl.writeDeadline(time.Time{})
			return stream.Send(m)
		}
		for {
			select {
			case m := <-c.out:
				if err := send(m); err != nil {
					c.Close(agentv1.Disconnect_REASON_UNSPECIFIED, "")
					return
				}
			case <-c.done:
				if d := c.goodbye(); d != nil {
					_ = send(&agentv1.CentralMessage{Message: &agentv1.CentralMessage_Disconnect{Disconnect: d}})
				}
				return
			}
		}
	}()
	g.Dispatch.OnHello(ctx, id.OrgID, id.AgentID, running)
	g.Log.Debug("gateway: agent connected", "agent", id.AgentID, "ip", httpx.ClientIPFrom(ctx).String())

	idle := time.NewTimer(g.IdleTimeout)
	defer idle.Stop()
	expiry := time.NewTimer(max(time.Until(id.NotAfter), time.Second))
	defer expiry.Stop()
	var result error
loop:
	for {
		select {
		case m := <-msgs:
			idle.Reset(g.IdleTimeout)
			if err := s.handle(ctx, id, c, m); err != nil {
				result = err
				c.Close(agentv1.Disconnect_REASON_UNSPECIFIED, "")
				break loop
			}
		case <-recvErr: // the agent closed the stream or the connection dropped
			c.Close(agentv1.Disconnect_REASON_UNSPECIFIED, "")
			break loop
		case <-c.done:
			break loop
		case <-idle.C:
			result = connect.NewError(connect.CodeDeadlineExceeded, errors.New("no traffic from the agent"))
			c.Close(agentv1.Disconnect_REASON_UNSPECIFIED, "")
			break loop
		case <-expiry.C:
			c.Close(agentv1.Disconnect_REASON_RENEW_CERTIFICATE, "the client certificate expired; renew it and reconnect")
			break loop
		case <-ctx.Done():
			c.Close(agentv1.Disconnect_REASON_UNSPECIFIED, "")
			break loop
		}
	}
	<-senderDone
	stopReader()
	g.Fleet.Disconnect(context.WithoutCancel(ctx), id.AgentID, c)
	g.Log.Debug("gateway: agent disconnected", "agent", id.AgentID)
	return result
}

// accept validates a Hello, registers the stream and queues the HelloAck.
func (s *agentService) accept(ctx context.Context, id *identity, h *agentv1.Hello) (*conn, []string, error) {
	g := s.g
	if h.GetProtocolVersion() != ProtocolVersion {
		return nil, nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("unsupported agent protocol version %d (Central speaks %d)", h.GetProtocolVersion(), ProtocolVersion))
	}
	facts, err := enrollment.SanitizeFacts(h.GetFacts())
	if err != nil {
		return nil, nil, protocolError("invalid host facts: %v", err)
	}
	features := h.GetFeatures()
	if len(features) > 32 {
		features = features[:32]
	}
	features = slices.DeleteFunc(slices.Clone(features), func(f string) bool { return len(f) > 64 || f == "" })
	running := h.GetRunningCommandIds()
	if len(running) > 1000 {
		running = running[:1000]
	}
	version := h.GetAgentVersion()
	if len(version) > 64 {
		return nil, nil, protocolError("invalid agent version")
	}
	var skew time.Duration
	if t := h.GetAgentTime(); t != nil {
		skew = time.Until(t.AsTime())
	}
	st := g.Holder.Get()
	if st == nil {
		return nil, nil, connect.NewError(connect.CodeUnavailable, errors.New("central is not ready"))
	}
	cfg := s.agentConfig(ctx, st, id)

	c := newConn()
	ack := &agentv1.HelloAck{
		AgentId: id.AgentID, ServerTime: timestamppb.Now(), Config: cfg, MinAgentVersion: g.MinAgentVersion,
	}
	if ks, err := s.signedKeySet(id.AgentID); err == nil {
		ack.SigningKeys = ks
	}
	// HelloAck is queued before the stream is registered, so it is always the first message.
	c.out <- &agentv1.CentralMessage{Message: &agentv1.CentralMessage_HelloAck{HelloAck: ack}}
	info := fleet.ConnectInfo{
		Facts: facts, Policy: h.GetPolicy(), Version: version, Features: features,
		RemoteIP: httpx.ClientIPFrom(ctx).String(), ClockSkew: skew,
	}
	if err := g.Fleet.Connect(ctx, id.OrgID, id.AgentID, c, info); err != nil {
		if errors.Is(err, fleet.ErrRevoked) {
			return nil, nil, connect.NewError(connect.CodePermissionDenied, errors.New("this agent has been revoked"))
		}
		return nil, nil, connect.NewError(connect.CodeUnavailable, errors.New("could not register the agent"))
	}
	return c, running, nil
}

func (s *agentService) agentConfig(ctx context.Context, st *store.Store, id *identity) *agentv1.AgentConfig {
	interval := 15
	if org, err := st.Orgs.Get(ctx, store.System(), id.OrgID); err == nil && org.Settings.MetricsIntervalSec > 0 {
		interval = org.Settings.MetricsIntervalSec
	}
	if v, ok := s.g.Fleet.Get(id.AgentID); ok && v.Agent.GroupID != "" {
		if grp, err := st.AgentGroups.Get(ctx, store.Tenant(id.OrgID), v.Agent.GroupID); err == nil && grp.MetricsIntervalSec > 0 {
			interval = grp.MetricsIntervalSec
		}
	}
	interval = min(max(interval, 5), 300)
	return &agentv1.AgentConfig{
		MetricsInterval:       durationpb.New(time.Duration(interval) * time.Second),
		InventoryInterval:     durationpb.New(6 * time.Hour),
		HeartbeatInterval:     durationpb.New(30 * time.Second),
		MaxOutputBytes:        4 << 20,
		MaxConcurrentCommands: 4,
		OfflineBufferSamples:  uint32(min(3600/interval, 720)),
	}
}

// signedKeySet signs the current command-signing key set with the active key (key set version
// 1 until rotation exists).
func (s *agentService) signedKeySet(agentID string) (*agentv1.SignedKeySet, error) {
	key := s.g.PKI.ActiveSigningKey()
	set := &agentv1.CommandSigningKeySet{
		AgentId: agentID, Version: 1, IssuedAt: timestamppb.Now(),
		Keys: []*agentv1.CommandSigningKey{enrollment.SigningKeyProto(key)},
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(set)
	if err != nil {
		return nil, err
	}
	sig, kid := s.g.PKI.Sign(pki.KeySetSignaturePrefix, raw)
	return &agentv1.SignedKeySet{KeySet: raw, Signature: sig, KeyId: kid}, nil
}

const maxSamplesPerReport = 1000

func (s *agentService) handle(ctx context.Context, id *identity, c *conn, m *agentv1.AgentMessage) error {
	g := s.g
	switch msg := m.GetMessage().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		g.Fleet.Touch(id.AgentID)
	case *agentv1.AgentMessage_Metrics:
		samples := msg.Metrics.GetSamples()
		if len(samples) > maxSamplesPerReport {
			samples = samples[len(samples)-maxSamplesPerReport:]
		}
		g.Fleet.RecordMetrics(id.AgentID, samples)
	case *agentv1.AgentMessage_Inventory:
		if _, err := g.Fleet.SetInventory(ctx, id.AgentID, msg.Inventory); err != nil {
			g.Log.Warn("gateway: inventory rejected", "agent", id.AgentID, "kind", msg.Inventory.GetKind().String(), "error", err)
		}
	case *agentv1.AgentMessage_CommandUpdate:
		g.Dispatch.HandleUpdate(ctx, id.OrgID, id.AgentID, msg.CommandUpdate)
	case *agentv1.AgentMessage_Policy:
		s.policyChanged(ctx, id, msg.Policy.GetPolicy())
	case *agentv1.AgentMessage_Event:
		s.event(ctx, id, msg.Event)
	case *agentv1.AgentMessage_Hello:
		return protocolError("hello may only be sent once per stream")
	default:
		// Unknown messages from newer agents are ignored.
	}
	_ = c
	return nil
}

func (s *agentService) policyChanged(ctx context.Context, id *identity, p *agentv1.EffectivePolicy) {
	g := s.g
	if p == nil {
		return
	}
	prev, _ := g.Fleet.Get(id.AgentID)
	if err := g.Fleet.SetPolicy(ctx, id.AgentID, p); err != nil {
		g.Log.Warn("gateway: storing policy failed", "agent", id.AgentID, "error", err)
		return
	}
	if prev.Policy.GetDigest() != p.GetDigest() || prev.Policy.GetProfile() != p.GetProfile() || prev.Policy.GetPaused() != p.GetPaused() {
		_ = g.Audit.Record(ctx, audit.Event{
			OrgID: id.OrgID, Actor: agentActor(id, prev), Action: "agent.policy_changed", TargetType: "agent",
			TargetID: id.AgentID, TargetDisplay: prev.Agent.Name, Details: map[string]string{
				"profile": strings.ToLower(strings.TrimPrefix(p.GetProfile().String(), "POLICY_PROFILE_")),
				"digest":  p.GetDigest(), "paused": strconv.FormatBool(p.GetPaused()),
			},
		})
	}
}

func agentActor(id *identity, v fleet.View) store.PrincipalRef {
	return store.PrincipalRef{Kind: store.PrincipalAgent, ID: id.AgentID, Display: v.Agent.Name}
}

func (s *agentService) event(ctx context.Context, id *identity, e *agentv1.AgentEvent) {
	g := s.g
	if !g.limits.events.Allow(id.AgentID) {
		return
	}
	v, _ := g.Fleet.Get(id.AgentID)
	switch e.GetType() {
	case agentv1.AgentEvent_TYPE_REBOOT_REQUIRED:
		_ = g.Fleet.SetRebootRequired(ctx, id.AgentID, true)
	case agentv1.AgentEvent_TYPE_PAUSED, agentv1.AgentEvent_TYPE_RESUMED:
		_ = g.Audit.Record(ctx, audit.Event{
			OrgID: id.OrgID, Actor: agentActor(id, v), TargetType: "agent", TargetID: id.AgentID, TargetDisplay: v.Agent.Name,
			Action: map[bool]string{true: "agent.paused", false: "agent.resumed"}[e.GetType() == agentv1.AgentEvent_TYPE_PAUSED],
		})
	case agentv1.AgentEvent_TYPE_NETWORK_ROLLED_BACK:
		_ = g.Audit.Record(ctx, audit.Event{
			OrgID: id.OrgID, Actor: agentActor(id, v), Action: "agent.network_rolled_back", TargetType: "agent",
			TargetID: id.AgentID, TargetDisplay: v.Agent.Name, Result: store.AuditFailure,
			Details: map[string]string{"message": truncate(e.GetMessage(), 200)},
		})
	default:
	}
	g.Log.Info("agent event", "agent", id.AgentID, "type", e.GetType().String(), "message", truncate(e.GetMessage(), 200))
}

func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// RenewCertificate implements AgentService.
func (s *agentService) RenewCertificate(ctx context.Context, req *connect.Request[agentv1.RenewCertificateRequest]) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	g := s.g
	id := identityFrom(ctx)
	if id == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("a client certificate is required"))
	}
	if !g.limits.renew.Allow(id.AgentID) {
		return nil, errRateLimited
	}
	csr, spki, err := pki.ParseCSR(req.Msg.GetCsrDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	cert, err := g.PKI.IssueAgentCertificate(csr, id.OrgID, id.AgentID)
	if err != nil {
		g.Log.Error("gateway: issuing renewed certificate failed", "agent", id.AgentID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	now := time.Now().UTC()
	v, err := g.Fleet.Update(ctx, id.OrgID, id.AgentID, func(a *store.Agent) error {
		if a.Lifecycle != store.AgentActive {
			return fleet.ErrRevoked
		}
		if a.CertSerial != id.Serial {
			// Only the current certificate may renew (not one inside the grace period).
			return fleet.ErrIdentity
		}
		a.PrevCertSerial, a.PrevCertValidUntil = a.CertSerial, now.Add(renewalGrace)
		a.CertSerial, a.CertNotAfter, a.PublicKeySHA256 = pki.SerialString(cert), cert.NotAfter, spki
		return nil
	})
	if err != nil {
		if errors.Is(err, fleet.ErrRevoked) || errors.Is(err, fleet.ErrIdentity) {
			return nil, connect.NewError(connect.CodePermissionDenied, err)
		}
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("could not record the new certificate"))
	}
	_ = g.Audit.Record(ctx, audit.Event{
		OrgID: id.OrgID, Actor: agentActor(id, v), Action: "agent.certificate_renewed", TargetType: "agent",
		TargetID: id.AgentID, TargetDisplay: v.Agent.Name,
		Details: map[string]string{"old_serial": id.Serial, "new_serial": v.Agent.CertSerial},
	})
	return connect.NewResponse(&agentv1.RenewCertificateResponse{
		CertificateDer: cert.Raw, CaCertificatesDer: [][]byte{g.PKI.CACertificate().Raw},
	}), nil
}

// AttachSession implements AgentService (interactive sessions arrive with the terminal bridge).
func (s *agentService) AttachSession(context.Context, *connect.BidiStream[agentv1.SessionFrame, agentv1.SessionFrame]) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("interactive sessions are not available yet"))
}
