// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/bus"
	ccrypto "github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/metrics"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

type testEnv struct {
	g    *Gateway
	url  string
	pin  string
	pool *x509.CertPool
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st := store.Open(memory.New())
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(st)
	_ = st.Orgs.Create(ctx, store.System(), &store.Org{ID: "org", Name: "Org", Settings: store.DefaultOrgSettings()})
	kr, _ := ccrypto.NewKeyring(bytes.Repeat([]byte{7}, 32))
	authority := pki.New(h, kr)
	if err := authority.Load(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := bus.NewMemory()
	fl := fleet.New(h, b, metrics.NewStore(h, log), log)
	rec := audit.NewRecorder(h, log)
	g := &Gateway{
		Holder: h, PKI: authority, Fleet: fl, Bus: b, Audit: rec, Log: log, MinAgentVersion: "0.1.0",
		Dispatch: dispatch.New(h, authority, fl, b, log),
		Enroll:   &enrollment.Service{Holder: h, PKI: authority, Fleet: fl, Bus: b, Audit: rec, Log: log},
		AgentURL: func(context.Context) string { return "https://agents.example.com:9443" },
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Serve(ctx, ln)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return &testEnv{g: g, url: "https://" + ln.Addr().String(), pin: authority.Pin(), pool: authority.CAPool()}
}

// client builds an HTTP/2 client that trusts only Central's CA (pinned), optionally presenting
// a client certificate.
func (e *testEnv) client(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: e.pool, ServerName: "agents.example.com",
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if pki.SPKIPin(c) == e.pin {
					return nil
				}
			}
			return errors.New("CA pin mismatch")
		},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
}

type enrolled struct {
	cert    tls.Certificate
	agentID string
}

func (e *testEnv) enroll(t *testing.T, host, machine string) enrolled {
	t.Helper()
	ctx := context.Background()
	_, keyStr, err := e.g.Enroll.CreateToken(ctx, "org", store.PrincipalRef{Kind: "user", ID: "u1"}, enrollment.TokenSpec{Name: "t", MaxUses: 5})
	if err != nil {
		t.Fatal(err)
	}
	tokenID, secret, pin, _ := enrollment.ParseKey(keyStr)
	if pin != e.pin {
		t.Fatal("pin mismatch")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	ec := agentv1connect.NewEnrollmentServiceClient(e.client(nil), e.url, connect.WithGRPC())
	res, err := ec.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		TokenId: tokenID, TokenSecret: secret, CsrDer: csr, AgentVersion: "0.1.0", ProtocolVersion: 1,
		Facts: &agentv1.HostFacts{
			Hostname: host, MachineId: machine, Os: &agentv1.OSInfo{Id: "debian", VersionId: "12"},
			Addresses: []*agentv1.InterfaceAddress{{Cidr: "127.0.0.1/8"}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if enrollment.PairingCode(spki, res.Msg.GetEnrollmentId(), res.Msg.GetServerNonce()) != res.Msg.GetPairingCode() {
		t.Fatal("pairing code mismatch")
	}
	if _, err := e.g.Enroll.Approve(ctx, "org", res.Msg.GetEnrollmentId(), store.PrincipalRef{Kind: "user", ID: "u1"},
		enrollment.ApproveInput{PairingCode: res.Msg.GetPairingCode()}); err != nil {
		t.Fatal(err)
	}
	status, err := ec.GetEnrollmentStatus(ctx, connect.NewRequest(&agentv1.GetEnrollmentStatusRequest{
		EnrollmentId: res.Msg.GetEnrollmentId(), PollSecret: res.Msg.GetPollSecret(),
	}))
	if err != nil || status.Msg.GetStatus() != agentv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Fatalf("status: %v %v", status, err)
	}
	creds := status.Msg.GetCredentials()
	return enrolled{
		cert:    tls.Certificate{Certificate: [][]byte{creds.GetCertificateDer()}, PrivateKey: key},
		agentID: creds.GetAgentId(),
	}
}

func hello() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentVersion: "0.1.0", ProtocolVersion: 1, AgentTime: timestamppb.Now(),
		Facts: &agentv1.HostFacts{Hostname: "web-1", MachineId: strings.Repeat("a", 32), Os: &agentv1.OSInfo{Id: "debian", VersionId: "12"}},
		Policy: &agentv1.EffectivePolicy{Profile: agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER, Allowed: []agentv1.Capability{
			agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE, agentv1.Capability_CAPABILITY_TELEMETRY,
		}},
	}}}
}

type stream = connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.CentralMessage]

func openStream(t *testing.T, e *testEnv, cert tls.Certificate) (*stream, *agentv1.HelloAck) {
	t.Helper()
	ac := agentv1connect.NewAgentServiceClient(e.client(&cert), e.url, connect.WithGRPC())
	s := ac.Connect(context.Background())
	if err := s.Send(hello()); err != nil {
		t.Fatal(err)
	}
	m, err := s.Receive()
	if err != nil {
		t.Fatalf("receive hello ack: %v", err)
	}
	if m.GetHelloAck() == nil {
		t.Fatalf("first message is %T", m.GetMessage())
	}
	return s, m.GetHelloAck()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnrollConnectCommandRevoke(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	a := e.enroll(t, "web-1", strings.Repeat("a", 32))

	s, ack := openStream(t, e, a.cert)
	if ack.GetAgentId() != a.agentID || ack.GetConfig().GetMetricsInterval().AsDuration() != 15*time.Second {
		t.Fatalf("hello ack: %v", ack)
	}
	// The key set is signed with the key the agent trusts, under the key-set prefix.
	ks := ack.GetSigningKeys()
	signer := e.g.PKI.ActiveSigningKey()
	if !pkiVerify(signer.PublicKey, pki.KeySetSignaturePrefix, ks.GetKeySet(), ks.GetSignature()) {
		t.Fatal("key set signature")
	}
	var set agentv1.CommandSigningKeySet
	_ = proto.Unmarshal(ks.GetKeySet(), &set)
	if set.GetAgentId() != a.agentID || set.GetVersion() != 1 {
		t.Fatalf("key set: %v", &set)
	}
	waitFor(t, "online", func() bool { v, _ := e.g.Fleet.Get(a.agentID); return v.Online })

	// Metrics flow into the fleet index.
	_ = s.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricsReport{Samples: []*agentv1.MetricsSample{
		{Time: timestamppb.Now(), CpuPercent: 42, MemoryTotalBytes: 100, MemoryUsedBytes: 50},
	}}}})
	waitFor(t, "metrics", func() bool { v, _ := e.g.Fleet.Get(a.agentID); return v.HasPoint && v.Point.CPU == 42 })

	// A command is signed, delivered and completed.
	rec, err := e.g.Dispatch.Submit(ctx, dispatch.Request{OrgID: "org", AgentID: a.agentID, Operation: &agentv1.Operation{
		Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Receive()
	if err != nil || m.GetCommand() == nil {
		t.Fatalf("command: %v %v", m, err)
	}
	if !pki.VerifyCommand(signer.PublicKey, m.GetCommand().GetCommand(), m.GetCommand().GetSignature()) {
		t.Fatal("command signature")
	}
	_ = s.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandUpdate{CommandUpdate: &agentv1.CommandUpdate{
		CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED,
	}}})
	final, _ := e.g.Dispatch.Wait(ctx, "org", rec.ID, 5*time.Second)
	if final.State != store.CommandSucceeded {
		t.Fatalf("command state %s", final.State)
	}
	// Owner policy denies what it does not allow.
	if _, err := e.g.Dispatch.Submit(ctx, dispatch.Request{OrgID: "org", AgentID: a.agentID, Operation: &agentv1.Operation{
		Kind: &agentv1.Operation_PackagesInstall{PackagesInstall: &agentv1.PackagesInstall{Names: []string{"nginx"}}},
	}}); !errors.Is(err, dispatch.ErrPolicyDenied) {
		t.Fatalf("policy: %v", err)
	}

	// Certificate renewal: the new certificate works, the old one stays valid during the grace period.
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr2, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key2)
	ac := agentv1connect.NewAgentServiceClient(e.client(&a.cert), e.url, connect.WithGRPC())
	renewed, err := ac.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr2}))
	if err != nil {
		t.Fatal(err)
	}
	newCert := tls.Certificate{Certificate: [][]byte{renewed.Msg.GetCertificateDer()}, PrivateKey: key2}
	// A second stream replaces the first, which is told why.
	s2, _ := openStream(t, e, newCert)
	m, err = s.Receive()
	if err != nil || m.GetDisconnect().GetReason() != agentv1.Disconnect_REASON_REPLACED {
		t.Fatalf("replaced: %v %v", m, err)
	}
	if _, err := ac.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr2})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("renewal with the superseded certificate: %v", err)
	}

	// Revocation disconnects immediately and blocks new handshakes.
	if _, err := e.g.Fleet.Revoke(ctx, "org", a.agentID, "test"); err != nil {
		t.Fatal(err)
	}
	m, err = s2.Receive()
	if err != nil || m.GetDisconnect().GetReason() != agentv1.Disconnect_REASON_REVOKED {
		t.Fatalf("revoked: %v %v", m, err)
	}
	_, err = agentv1connect.NewAgentServiceClient(e.client(&newCert), e.url, connect.WithGRPC()).
		RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr2}))
	if err == nil {
		t.Fatal("revoked agent completed a request")
	}
	waitFor(t, "offline", func() bool { v, _ := e.g.Fleet.Get(a.agentID); return !v.Online })
}

func TestRejectsUntrustedClients(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	csr := func() []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		b, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		return b
	}()
	// No client certificate.
	ac := agentv1connect.NewAgentServiceClient(e.client(nil), e.url, connect.WithGRPC())
	if _, err := ac.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no cert: %v", err)
	}
	// A certificate from another CA with a well-formed agent identity.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "evil"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{pki.SpiffeID("org", "agent1")},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	evil := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	ac = agentv1connect.NewAgentServiceClient(e.client(&evil), e.url, connect.WithGRPC())
	if _, err := ac.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr})); err == nil {
		t.Fatal("certificate from a foreign CA accepted")
	}
	// Streams must start with hello.
	a := e.enroll(t, "db-1", strings.Repeat("b", 32))
	s := agentv1connect.NewAgentServiceClient(e.client(&a.cert), e.url, connect.WithGRPC()).Connect(ctx)
	_ = s.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}})
	if _, err := s.Receive(); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no hello: %v", err)
	}
	// Bad enrollment keys.
	ec := agentv1connect.NewEnrollmentServiceClient(e.client(nil), e.url, connect.WithGRPC())
	if _, err := ec.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		TokenId: "AAAAAAAAAAAAAAAA", TokenSecret: strings.Repeat("A", 43),
		CsrDer: csr, ProtocolVersion: 1, AgentVersion: "0.1.0", Facts: hello().GetHello().GetFacts(),
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("bad key: %v", err)
	}
}

func pkiVerify(pub ed25519.PublicKey, prefix string, data, sig []byte) bool {
	return ed25519.Verify(pub, append([]byte(prefix), data...), sig)
}
