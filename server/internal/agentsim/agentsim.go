// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package agentsim is a protocol-faithful simulated agent. It enrolls with a real enrollment
// key (verifying the CA pin before sending anything), keeps the mTLS control stream open,
// verifies command signatures the way the agent's privileged helper must, and can attach
// interactive sessions. Tests and the central-sim load generator build on it.
package agentsim

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/pki"
)

// Version is the simulated agent version.
const Version = "0.1.0"

// Errors.
var (
	ErrDenied  = errors.New("agentsim: enrollment denied")
	ErrRevoked = errors.New("agentsim: agent revoked")
)

func httpClient(pin, serverName string, cert *tls.Certificate, roots *x509.CertPool) *http.Client {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// Trust is established by the pin (and, after enrollment, by the received CA): before
		// enrollment there are no roots, and VerifyConnection enforces the pin and the chain.
		InsecureSkipVerify: roots == nil,
		RootCAs:            roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			chain := cs.PeerCertificates
			if len(chain) == 0 {
				return errors.New("agentsim: no server certificate")
			}
			for _, c := range chain {
				if pki.SPKIPin(c) != pin {
					continue
				}
				pool := x509.NewCertPool()
				pool.AddCert(c)
				inter := x509.NewCertPool()
				for _, i := range chain[1:] {
					inter.AddCert(i)
				}
				_, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: serverName})
				return err
			}
			return errors.New("agentsim: server certificate does not match the CA pin")
		},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4}}
}

// Enrollment is a submitted enrollment request.
type Enrollment struct {
	ID          string
	PairingCode string
	pollSecret  string
	key         *ecdsa.PrivateKey
	url, pin    string
	serverName  string
	facts       *agentv1.HostFacts
	client      agentv1connect.EnrollmentServiceClient
}

// EnrollOptions configure Enroll.
type EnrollOptions struct {
	// AgentURL is the agent endpoint, e.g. https://127.0.0.1:9443.
	AgentURL string
	// ServerName is the TLS server name to verify (default "localhost").
	ServerName string
	// Key is the enrollment key "cek1.…".
	Key   string
	Facts *agentv1.HostFacts
}

// Enroll submits an enrollment request and checks that Central's pairing code matches the
// locally derived one.
func Enroll(ctx context.Context, o EnrollOptions) (*Enrollment, error) {
	tokenID, secret, pin, err := enrollment.ParseKey(o.Key)
	if err != nil {
		return nil, err
	}
	if o.ServerName == "" {
		o.ServerName = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	c := agentv1connect.NewEnrollmentServiceClient(httpClient(pin, o.ServerName, nil, nil), o.AgentURL, connect.WithGRPC())
	res, err := c.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		TokenId: tokenID, TokenSecret: secret, CsrDer: csr, Facts: o.Facts, AgentVersion: Version, ProtocolVersion: 1,
	}))
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	local := enrollment.PairingCode(spki, res.Msg.GetEnrollmentId(), res.Msg.GetServerNonce())
	if local != res.Msg.GetPairingCode() {
		return nil, fmt.Errorf("agentsim: pairing code mismatch (local %s, Central %s): possible interception", local, res.Msg.GetPairingCode())
	}
	return &Enrollment{
		ID: res.Msg.GetEnrollmentId(), PairingCode: local, pollSecret: res.Msg.GetPollSecret(), key: key,
		url: o.AgentURL, pin: pin, serverName: o.ServerName, facts: o.Facts, client: c,
	}, nil
}

// Wait long-polls until the request is decided and returns the enrolled agent.
func (e *Enrollment) Wait(ctx context.Context) (*Agent, error) {
	for {
		res, err := e.client.GetEnrollmentStatus(ctx, connect.NewRequest(&agentv1.GetEnrollmentStatusRequest{
			EnrollmentId: e.ID, PollSecret: e.pollSecret, Wait: durationpb.New(30 * time.Second),
		}))
		if err != nil {
			return nil, err
		}
		switch res.Msg.GetStatus() {
		case agentv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED:
			return e.agent(res.Msg.GetCredentials())
		case agentv1.EnrollmentStatus_ENROLLMENT_STATUS_DENIED, agentv1.EnrollmentStatus_ENROLLMENT_STATUS_EXPIRED:
			return nil, fmt.Errorf("%w: %s", ErrDenied, res.Msg.GetReason())
		default:
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

func (e *Enrollment) agent(c *agentv1.AgentCredentials) (*Agent, error) {
	roots := x509.NewCertPool()
	for _, der := range c.GetCaCertificatesDer() {
		ca, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if pki.SPKIPin(ca) != e.pin {
			return nil, errors.New("agentsim: received CA does not match the pin")
		}
		roots.AddCert(ca)
	}
	a := &Agent{
		ID: c.GetAgentId(), OrgID: c.GetOrgId(), URL: e.url, pin: e.pin, serverName: e.serverName, roots: roots,
		cas:  c.GetCaCertificatesDer(),
		cert: tls.Certificate{Certificate: [][]byte{c.GetCertificateDer()}, PrivateKey: e.key}, Facts: e.facts,
		keys: map[string]ed25519.PublicKey{}, seen: map[string]time.Time{},
	}
	for _, k := range c.GetCommandSigningKeys() {
		a.keys[k.GetKeyId()] = k.GetPublicKey()
	}
	a.client = agentv1connect.NewAgentServiceClient(httpClient(e.pin, e.serverName, &a.cert, roots), e.url, connect.WithGRPC())
	return a, nil
}

// Agent is an enrolled simulated agent.
type Agent struct {
	ID, OrgID  string
	URL        string
	Facts      *agentv1.HostFacts
	Policy     *agentv1.EffectivePolicy
	pin        string
	serverName string
	roots      *x509.CertPool
	cas        [][]byte
	cert       tls.Certificate
	client     agentv1connect.AgentServiceClient

	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
	seen map[string]time.Time // replay cache: command ID → expiry
}

// Handler executes a verified command and returns its final update. Use conn to send
// progress updates, metrics or to attach a session.
type Handler func(ctx context.Context, conn *Conn, cmd *agentv1.Command) *agentv1.CommandUpdate

// Conn is a live control stream.
type Conn struct {
	agent  *Agent
	stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.CentralMessage]
	ctx    context.Context
	mu     sync.Mutex
	Ack    *agentv1.HelloAck
}

// Context is cancelled when the stream ends.
func (c *Conn) Context() context.Context { return c.ctx }

// Send writes one message (safe for concurrent use).
func (c *Conn) Send(m *agentv1.AgentMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream.Send(m)
}

// Update sends a CommandUpdate.
func (c *Conn) Update(u *agentv1.CommandUpdate) error {
	return c.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandUpdate{CommandUpdate: u}})
}

// Verify checks a signed command exactly as the privileged helper must: known key, signature
// over the exact bytes, target, time window and replay.
func (a *Agent) Verify(sc *agentv1.SignedCommand) (*agentv1.Command, agentv1.ErrorCode, error) {
	a.mu.Lock()
	pub := a.keys[sc.GetKeyId()]
	a.mu.Unlock()
	if pub == nil || !pki.VerifyCommand(pub, sc.GetCommand(), sc.GetSignature()) {
		return nil, agentv1.ErrorCode_ERROR_CODE_BAD_SIGNATURE, errors.New("bad signature")
	}
	cmd := &agentv1.Command{}
	if err := proto.Unmarshal(sc.GetCommand(), cmd); err != nil {
		return nil, agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, err
	}
	if cmd.GetAgentId() != a.ID || cmd.GetOrgId() != a.OrgID {
		return cmd, agentv1.ErrorCode_ERROR_CODE_WRONG_TARGET, errors.New("wrong target")
	}
	now := time.Now()
	issued, expires := cmd.GetIssuedAt().AsTime(), cmd.GetExpiresAt().AsTime()
	if issued.After(now.Add(5*time.Minute)) || now.After(expires) || expires.Sub(issued) > 24*time.Hour {
		return cmd, agentv1.ErrorCode_ERROR_CODE_EXPIRED, errors.New("outside the validity window")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, exp := range a.seen {
		if now.After(exp) {
			delete(a.seen, id)
		}
	}
	if _, dup := a.seen[cmd.GetCommandId()]; dup {
		return cmd, agentv1.ErrorCode_ERROR_CODE_REPLAYED, errors.New("replayed")
	}
	a.seen[cmd.GetCommandId()] = expires
	return cmd, 0, nil
}

func (a *Agent) hello() *agentv1.AgentMessage {
	pol := a.Policy
	if pol == nil {
		pol = FullPolicy()
	}
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentVersion: Version, ProtocolVersion: 1, Features: []string{"sessions.v1"}, Facts: a.Facts,
		Policy: pol, AgentTime: timestamppb.Now(),
	}}}
}

// FullPolicy allows every capability (the "full" profile).
func FullPolicy() *agentv1.EffectivePolicy {
	p := &agentv1.EffectivePolicy{Version: 1, Profile: agentv1.PolicyProfile_POLICY_PROFILE_FULL}
	for v := range agentv1.Capability_name {
		if v != 0 {
			p.Allowed = append(p.Allowed, agentv1.Capability(v))
		}
	}
	return p
}

// Run keeps one control stream open until ctx ends or Central disconnects the agent. It calls
// onConnect (if set) once the stream is accepted and handler for every verified command.
func (a *Agent) Run(ctx context.Context, handler Handler, onConnect func(*Conn)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := a.client.Connect(ctx)
	// Cancelling the context alone does not unblock a pending Receive on an open HTTP/2
	// stream: close both directions explicitly.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.CloseRequest()
			_ = stream.CloseResponse()
		case <-stopped:
		}
	}()
	conn := &Conn{agent: a, stream: stream, ctx: ctx}
	if err := conn.Send(a.hello()); err != nil {
		return err
	}
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	if first.GetHelloAck() == nil {
		return errors.New("agentsim: expected hello_ack")
	}
	conn.Ack = first.GetHelloAck()
	if onConnect != nil {
		onConnect(conn)
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	var runningMu sync.Mutex
	running := map[string]context.CancelFunc{}
	for {
		m, err := stream.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch msg := m.GetMessage().(type) {
		case *agentv1.CentralMessage_Command:
			cmd, code, verr := a.Verify(msg.Command)
			if verr != nil {
				id := ""
				if cmd != nil {
					id = cmd.GetCommandId()
				}
				_ = conn.Update(&agentv1.CommandUpdate{
					CommandId: id, State: agentv1.CommandState_COMMAND_STATE_REJECTED,
					Error: &agentv1.CommandError{Code: code, Message: verr.Error()},
				})
				continue
			}
			_ = conn.Update(&agentv1.CommandUpdate{CommandId: cmd.GetCommandId(), State: agentv1.CommandState_COMMAND_STATE_ACCEPTED})
			cmdCtx, cmdCancel := context.WithCancel(ctx)
			runningMu.Lock()
			running[cmd.GetCommandId()] = cmdCancel
			runningMu.Unlock()
			wg.Go(func() {
				defer func() {
					runningMu.Lock()
					delete(running, cmd.GetCommandId())
					runningMu.Unlock()
					cmdCancel()
				}()
				final := handler(cmdCtx, conn, cmd)
				if final != nil {
					final.CommandId = cmd.GetCommandId()
					_ = conn.Update(final)
				}
			})
		case *agentv1.CentralMessage_Cancel:
			runningMu.Lock()
			if c := running[msg.Cancel.GetCommandId()]; c != nil {
				c()
			}
			runningMu.Unlock()
		case *agentv1.CentralMessage_Disconnect:
			if msg.Disconnect.GetReason() == agentv1.Disconnect_REASON_REVOKED {
				return ErrRevoked
			}
			return fmt.Errorf("agentsim: disconnected: %s", msg.Disconnect.GetReason())
		default:
		}
	}
}

// Session is an attached interactive session.
type Session struct {
	stream *connect.BidiStreamForClient[agentv1.SessionFrame, agentv1.SessionFrame]
	mu     sync.Mutex
}

// Attach opens the session a command authorized.
func (a *Agent) Attach(ctx context.Context, cmd *agentv1.Command) (*Session, error) {
	b := cmd.GetSession()
	if b == nil {
		return nil, errors.New("agentsim: command has no session binding")
	}
	s := &Session{stream: a.client.AttachSession(ctx)}
	go func() {
		<-ctx.Done()
		_ = s.stream.CloseRequest()
		_ = s.stream.CloseResponse()
	}()
	if err := s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Attach{Attach: &agentv1.SessionAttach{
		SessionId: b.GetSessionId(), AttachToken: b.GetAttachToken(), CommandId: cmd.GetCommandId(),
	}}}); err != nil {
		return nil, err
	}
	return s, nil
}

// Send writes a frame.
func (s *Session) Send(f *agentv1.SessionFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(f)
}

// Receive reads the next frame.
func (s *Session) Receive() (*agentv1.SessionFrame, error) { return s.stream.Receive() }

// Close ends the session gracefully: send SessionClose, half-close the request stream and let
// Central end the response (resetting the stream could discard the close frame in transit).
func (s *Session) Close(exitCode int32) {
	_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Close{Close: &agentv1.SessionClose{ExitCode: exitCode}}})
	_ = s.stream.CloseRequest()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := s.stream.Receive(); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	_ = s.stream.CloseResponse()
}

// Attach opens the session a command authorized (convenience for handlers).
func (c *Conn) Attach(ctx context.Context, cmd *agentv1.Command) (*Session, error) {
	return c.agent.Attach(ctx, cmd)
}
