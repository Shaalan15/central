// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/bus"
	ccrypto "github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

var owner = store.PrincipalRef{Kind: store.PrincipalUser, ID: "u1", Display: "owner@example.com"}

type env struct {
	svc *Service
	st  *store.Store
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := store.Open(memory.New())
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(st)
	kr, _ := ccrypto.NewKeyring(bytes.Repeat([]byte{5}, 32))
	a := pki.New(h, kr)
	if err := a.Load(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := bus.NewMemory()
	e := &env{st: st, now: time.Now()}
	e.svc = &Service{
		Holder: h, PKI: a, Fleet: fleet.New(h, b, nil, log), Bus: b, Audit: audit.NewRecorder(h, log), Log: log,
		MinAgentVersion: "0.2.0",
	}
	e.svc.now = func() time.Time { return e.now }
	return e
}

type agentKey struct {
	key *ecdsa.PrivateKey
	csr []byte
}

func newAgentKey(t *testing.T) agentKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return agentKey{k, csr}
}

func facts(host, machine string) *agentv1.HostFacts {
	return &agentv1.HostFacts{
		Hostname: host, MachineId: machine, Arch: "amd64",
		Os:        &agentv1.OSInfo{Id: "ubuntu", VersionId: "24.04", PrettyName: "Ubuntu 24.04.1 LTS"},
		Addresses: []*agentv1.InterfaceAddress{{Interface: "eth0", Cidr: "10.0.0.5/24"}},
	}
}

func (e *env) token(t *testing.T, spec TokenSpec) (id, secret string) {
	t.Helper()
	if spec.Name == "" {
		spec.Name = "test"
	}
	tok, key, err := e.svc.CreateToken(context.Background(), "org", owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	id, secret, pin, err := ParseKey(key)
	if err != nil || id != tok.ID || pin != e.svc.PKI.Pin() {
		t.Fatalf("key %q: %v", key, err)
	}
	return id, secret
}

func (e *env) submit(id, secret string, k agentKey, f *agentv1.HostFacts, ip string) (*SubmitResult, error) {
	return e.svc.Submit(context.Background(), SubmitInput{
		TokenID: id, TokenSecret: secret, CSRDER: k.csr, Facts: f, AgentVersion: "0.3.0", ProtocolVersion: 1,
		SourceIP: netip.MustParseAddr(ip),
	})
}

func code(err error) connect.Code { return connect.CodeOf(err) }

func hasFlag(r *store.EnrollmentRequest, c string) bool {
	return slices.ContainsFunc(r.RiskFlags, func(f store.RiskFlag) bool { return f.Code == c })
}

func TestTokenValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bad := []TokenSpec{
		{Name: ""},
		{Name: "x", ApprovalMode: store.ApprovalAuto},                                            // auto needs max uses
		{Name: "x", ApprovalMode: store.ApprovalAuto, MaxUses: 5, ExpiresIn: 8 * 24 * time.Hour}, // auto max 7d
		{Name: "x", ExpiresIn: 31 * 24 * time.Hour},
		{Name: "x", MaxUses: 10_001},
		{Name: "x", AllowedCIDRs: []string{"not-a-cidr"}},
		{Name: "x", HostnamePattern: "web-["},
		{Name: "x", DefaultGroupID: "missing"},
		{Name: "x", DefaultTags: []string{"Bad Tag"}},
	}
	for i, spec := range bad {
		if _, _, err := e.svc.CreateToken(ctx, "org", owner, spec); code(err) != connect.CodeInvalidArgument {
			t.Errorf("spec %d: %v", i, err)
		}
	}
	for _, k := range []string{"", "cek1.", "cek1.a.b.c", "cek2.AAAAAAAAAAAAAAAA." + strings.Repeat("a", 43) + "." + strings.Repeat("a", 43)} {
		if _, _, _, err := ParseKey(k); err == nil {
			t.Errorf("parsed %q", k)
		}
	}
}

func TestEnrollApproveFlow(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, secret := e.token(t, TokenSpec{MaxUses: 3, DefaultTags: []string{"web"}})
	k := newAgentKey(t)

	// Wrong or unknown secrets look identical.
	for _, s := range []string{strings.Repeat("A", 43)} {
		if _, err := e.submit(id, s, k, facts("web-1", strings.Repeat("a", 32)), "10.0.0.5"); code(err) != connect.CodePermissionDenied ||
			!strings.Contains(err.Error(), "invalid enrollment key") {
			t.Fatalf("wrong secret: %v", err)
		}
	}
	if _, err := e.submit("BBBBBBBBBBBBBBBB", secret, k, facts("web-1", strings.Repeat("a", 32)), "10.0.0.5"); !strings.Contains(err.Error(), "invalid enrollment key") {
		t.Fatalf("unknown token: %v", err)
	}
	// Invalid facts are rejected.
	if _, err := e.submit(id, secret, k, facts("web_1!", strings.Repeat("a", 32)), "10.0.0.5"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad hostname: %v", err)
	}
	if _, err := e.submit(id, secret, k, facts("web-1", "not-a-machine-id"), "10.0.0.5"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad machine id: %v", err)
	}

	res, err := e.submit(id, secret, k, facts("web-1", strings.Repeat("a", 32)), "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Request
	if r.Status != store.EnrollmentPending || len(r.RiskFlags) != 0 {
		t.Fatalf("request: %+v", r)
	}
	// The agent derives the same pairing code from its own key.
	spki, _ := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	if got := PairingCode(spki, r.ID, r.ServerNonce); got != r.PairingCode || len(got) != 9 {
		t.Fatalf("pairing code %q vs %q", got, r.PairingCode)
	}
	if e.svc.Fleet.Pending("org") != 1 {
		t.Fatal("pending count")
	}

	// The agent long-polls while an admin approves.
	type pollResult struct {
		res *StatusResult
		err error
	}
	done := make(chan pollResult, 1)
	go func() {
		s, err := e.svc.Status(ctx, r.ID, res.PollSecret, 10*time.Second)
		done <- pollResult{s, err}
	}()
	time.Sleep(50 * time.Millisecond)

	if _, err := e.svc.Approve(ctx, "other-org", r.ID, owner, ApproveInput{PairingCode: r.PairingCode}); code(err) != connect.CodeNotFound {
		t.Fatalf("cross-org approve: %v", err)
	}
	if _, err := e.svc.Approve(ctx, "org", r.ID, owner, ApproveInput{PairingCode: "0000-0000"}); code(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong code: %v", err)
	}
	typed := strings.ToLower(strings.ReplaceAll(r.PairingCode, "-", " "))
	approved, err := e.svc.Approve(ctx, "org", r.ID, owner, ApproveInput{PairingCode: typed, Name: "Web 1"})
	if err != nil {
		t.Fatal(err)
	}
	pr := <-done
	if pr.err != nil || pr.res.Request.Status != store.EnrollmentApproved || pr.res.Credentials == nil {
		t.Fatalf("poll: %+v %v", pr.res, pr.err)
	}
	creds := pr.res.Credentials
	cert, err := x509.ParseCertificate(creds.GetCertificateDer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: e.svc.PKI.CAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	ident, _ := pki.IdentityFromCert(cert)
	if ident.AgentID != approved.AgentID || ident.OrgID != "org" || creds.GetAgentId() != approved.AgentID ||
		len(creds.GetCommandSigningKeys()) != 1 || !bytes.Equal(creds.GetCaCertificatesDer()[0], e.svc.PKI.CACertificate().Raw) {
		t.Fatalf("credentials: %+v", ident)
	}
	v, ok := e.svc.Fleet.GetInOrg("org", approved.AgentID)
	if !ok || v.Agent.Name != "Web 1" || !slices.Equal(v.Agent.Tags, []string{"web"}) || v.Agent.CertSerial != ident.Serial {
		t.Fatalf("agent: %+v", v.Agent)
	}
	if e.svc.Fleet.Pending("org") != 0 {
		t.Fatal("pending count after approval")
	}
	if _, err := e.svc.Approve(ctx, "org", r.ID, owner, ApproveInput{PairingCode: r.PairingCode}); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("double approve: %v", err)
	}
	if _, err := e.svc.Status(ctx, r.ID, strings.Repeat("x", 43), 0); code(err) != connect.CodeNotFound {
		t.Fatalf("wrong poll secret: %v", err)
	}

	// Re-enrolling the same machine flags it and replaces the old agent on approval.
	k2 := newAgentKey(t)
	res2, err := e.submit(id, secret, k2, facts("web-1", strings.Repeat("a", 32)), "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlag(res2.Request, "duplicate_machine_id") || res2.Request.ReplacesAgentID != approved.AgentID {
		t.Fatalf("flags: %+v", res2.Request.RiskFlags)
	}
	if _, err := e.svc.Approve(ctx, "org", res2.Request.ID, owner, ApproveInput{PairingCode: res2.Request.PairingCode}); err != nil {
		t.Fatal(err)
	}
	if old, _ := e.svc.Fleet.Get(approved.AgentID); old.Active() {
		t.Fatal("replaced agent still active")
	}

	// The third use exhausts the token (max_uses 3), the fourth is refused.
	if _, err := e.submit(id, secret, newAgentKey(t), facts("web-2", strings.Repeat("b", 32)), "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.submit(id, secret, newAgentKey(t), facts("web-3", strings.Repeat("c", 32)), "10.0.0.5"); code(err) != connect.CodePermissionDenied ||
		!strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted: %v", err)
	}
}

func TestTokenRestrictionsDenyAndBlock(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id, secret := e.token(t, TokenSpec{MaxUses: 100, AllowedCIDRs: []string{"10.0.0.0/8"}, HostnamePattern: "web-*"})
	if _, err := e.submit(id, secret, newAgentKey(t), facts("web-1", strings.Repeat("a", 32)), "192.0.2.1"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("cidr: %v", err)
	}
	if _, err := e.submit(id, secret, newAgentKey(t), facts("db-1", strings.Repeat("a", 32)), "10.1.1.1"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("hostname pattern: %v", err)
	}
	k := newAgentKey(t)
	f := facts("web-9", strings.Repeat("d", 32))
	f.Os = &agentv1.OSInfo{Id: "fedora", VersionId: "40"}
	res, err := e.submit(id, secret, k, f, "10.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlag(res.Request, "unsupported_os") || !hasFlag(res.Request, "source_ip_not_on_host") {
		t.Fatalf("flags: %+v", res.Request.RiskFlags)
	}
	// Retrying with the same key supersedes the older request.
	res2, err := e.submit(id, secret, k, f, "10.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if old, _ := e.st.EnrollmentRequests.Get(ctx, store.Tenant("org"), res.Request.ID); old.Status != store.EnrollmentExpired {
		t.Fatalf("superseded: %s", old.Status)
	}
	if _, err := e.svc.Deny(ctx, "org", res2.Request.ID, owner, DenyInput{Reason: "unknown host", BlockKey: true}); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Status(ctx, res2.Request.ID, res2.PollSecret, 0)
	if st.Request.Status != store.EnrollmentDenied || st.Credentials != nil {
		t.Fatalf("denied status: %+v", st.Request)
	}
	if _, err := e.submit(id, secret, k, f, "10.9.9.9"); code(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("blocked key: %v", err)
	}

	// Pending requests expire.
	res3, _ := e.submit(id, secret, newAgentKey(t), facts("web-5", strings.Repeat("e", 32)), "10.0.0.5")
	e.now = e.now.Add(RequestTTL + time.Minute)
	st3, err := e.svc.Status(ctx, res3.Request.ID, res3.PollSecret, time.Second)
	if err != nil || st3.Request.Status != store.EnrollmentExpired {
		t.Fatalf("expiry: %+v %v", st3, err)
	}

	// Wrong pairing codes eventually deny the request.
	e.now = time.Now()
	res4, _ := e.submit(id, secret, newAgentKey(t), facts("web-6", strings.Repeat("f", 32)), "10.0.0.5")
	for range MaxPairingFailures {
		_, _ = e.svc.Approve(ctx, "org", res4.Request.ID, owner, ApproveInput{PairingCode: "ZZZZ-ZZZZ"})
	}
	if r, _ := e.st.EnrollmentRequests.Get(ctx, store.Tenant("org"), res4.Request.ID); r.Status != store.EnrollmentDenied {
		t.Fatalf("after pairing failures: %s", r.Status)
	}
	// Revoked tokens stop working.
	if _, err := e.svc.RevokeToken(ctx, "org", id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.submit(id, secret, newAgentKey(t), facts("web-7", strings.Repeat("0", 32)), "10.0.0.5"); !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked token: %v", err)
	}
}

func TestAutoApproval(t *testing.T) {
	e := newEnv(t)
	id, secret := e.token(t, TokenSpec{ApprovalMode: store.ApprovalAuto, MaxUses: 10, ExpiresIn: time.Hour})
	res, err := e.submit(id, secret, newAgentKey(t), facts("ci-1", strings.Repeat("1", 32)), "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if res.Request.Status != store.EnrollmentApproved || res.Request.DecidedBy != "auto-approval" {
		t.Fatalf("auto: %+v", res.Request)
	}
	// Warning-level flags still require a human.
	f := facts("ci-2", strings.Repeat("2", 32))
	f.Os.VersionId = "20.04"
	res2, err := e.submit(id, secret, newAgentKey(t), f, "10.0.0.5")
	if err != nil || res2.Request.Status != store.EnrollmentPending {
		t.Fatalf("flagged auto request: %+v %v", res2.Request, err)
	}
}

func TestVersionsAndCodes(t *testing.T) {
	if compareVersions("0.10.0", "0.9.9") != 1 || compareVersions("1.0.0-rc1", "1.0.0") != 0 || compareVersions("0.1", "0.1.1") != -1 {
		t.Fatal("compareVersions")
	}
	if NormalizePairingCode("k7qp-3mzx") != "K7QP-3MZX" || NormalizePairingCode("abc") != "" || NormalizePairingCode("O1IL 0000") != "0111-0000" {
		t.Fatal("NormalizePairingCode")
	}
}
