// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	ccrypto "github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

func newAuthority(t *testing.T) (*Authority, *store.Holder, *ccrypto.Keyring) {
	t.Helper()
	s := store.Open(memory.New())
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(s)
	kr, _ := ccrypto.NewKeyring(bytes.Repeat([]byte{3}, 32))
	a := New(h, kr)
	if err := a.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, h, kr
}

func csrFor(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCAPersistsAcrossLoads(t *testing.T) {
	a, h, kr := newAuthority(t)
	pin := a.Pin()
	signer := a.ActiveSigningKey()
	b := New(h, kr)
	if err := b.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.Pin() != pin || b.ActiveSigningKey().ID != signer.ID || !bytes.Equal(b.ActiveSigningKey().PublicKey, signer.PublicKey) {
		t.Fatal("CA or signing key changed across loads")
	}
	// The wrong master key cannot unseal the CA.
	wrong, _ := ccrypto.NewKeyring(bytes.Repeat([]byte{4}, 32))
	if err := New(h, wrong).Load(context.Background()); err == nil {
		t.Fatal("CA unsealed with the wrong master key")
	}
	if len(pin) != 43 {
		t.Fatalf("pin length %d", len(pin))
	}
}

func TestAgentCertificateIssuance(t *testing.T) {
	a, _, _ := newAuthority(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, spki, err := ParseCSR(csrFor(t, key))
	if err != nil || len(spki) != 64 {
		t.Fatalf("ParseCSR: %v", err)
	}
	cert, err := a.IssueAgentCertificate(csr, "org1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.CAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("agent cert does not verify: %v", err)
	}
	id, err := IdentityFromCert(cert)
	if err != nil || id.OrgID != "org1" || id.AgentID != "agent1" || id.Serial == "" {
		t.Fatalf("identity = %+v, %v", id, err)
	}
	if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime > AgentCertValidity+10*time.Minute {
		t.Fatalf("lifetime %s", lifetime)
	}
	// Bad CSRs: RSA key, P-384 key, corrupted bytes.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	bad := csrFor(t, key)
	bad[len(bad)-5] ^= 0xff
	for name, der := range map[string][]byte{"rsa": csrFor(t, rsaKey), "p384": csrFor(t, p384), "corrupt": bad, "empty": nil} {
		if _, _, err := ParseCSR(der); err == nil {
			t.Errorf("%s CSR accepted", name)
		}
	}
}

func TestIdentityRejectsForeignURIs(t *testing.T) {
	for _, raw := range []string{
		"spiffe://evil/org/o/agent/a", "https://central/org/o/agent/a", "spiffe://central/org/o/agent",
		"spiffe://central/org/../agent/a", "spiffe://central/org/o/agent/a/extra",
	} {
		u, _ := url.Parse(raw)
		if _, err := IdentityFromCert(&x509.Certificate{URIs: []*url.URL{u}}); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := IdentityFromCert(&x509.Certificate{}); err == nil {
		t.Error("accepted certificate without URI SAN")
	}
}

func TestServerCertificateChainsToCA(t *testing.T) {
	a, _, _ := newAuthority(t)
	cert, err := a.ServerCertificate([]string{"central.example.com", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: a.CAPool(), DNSName: "central.example.com"}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Fatalf("server cert: %v", err)
	}
	again, _ := a.ServerCertificate([]string{"central.example.com", "10.0.0.5"})
	if again != cert {
		t.Fatal("server certificate not cached")
	}
	// A client pinning the CA accepts the chain.
	if SPKIPin(a.CACertificate()) != a.Pin() {
		t.Fatal("pin mismatch")
	}
	_ = tls.Certificate{}
}

func TestCommandSignatures(t *testing.T) {
	a, _, _ := newAuthority(t)
	cmd := []byte("serialized command")
	sig, kid := a.SignCommand(cmd)
	pub := a.ActiveSigningKey()
	if kid != pub.ID || !VerifyCommand(pub.PublicKey, cmd, sig) {
		t.Fatal("signature does not verify")
	}
	if VerifyCommand(pub.PublicKey, []byte("serialized commanD"), sig) {
		t.Fatal("tampered command verifies")
	}
	// A key-set signature is not a valid command signature (domain separation).
	ks, _ := a.Sign(KeySetSignaturePrefix, cmd)
	if VerifyCommand(pub.PublicKey, cmd, ks) {
		t.Fatal("key-set signature accepted as command signature")
	}
}
