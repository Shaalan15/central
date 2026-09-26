// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package pki manages Central's agent-facing public key infrastructure:
//
//   - an internal ECDSA P-256 certificate authority (key sealed with the master key),
//   - short-lived server certificates for the agent listener,
//   - 30-day agent client certificates issued from CSRs, identified by a SPIFFE-style URI SAN
//     (spiffe://central/org/<org>/agent/<agent>),
//   - Ed25519 command-signing keys whose public halves agents pin at enrollment.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ccrypto "github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Lifetimes.
const (
	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 90 * 24 * time.Hour
	// AgentCertValidity is the lifetime of agent client certificates.
	AgentCertValidity = 30 * 24 * time.Hour
	clockSkew         = 5 * time.Minute
)

// Domain-separation prefixes for signatures (must match docs/protocol.md).
const (
	CommandSignaturePrefix = "central-command-v1\x00"
	KeySetSignaturePrefix  = "central-keyset-v1\x00"
)

// SPIFFE trust domain and path layout for agent identities.
const spiffeTrustDomain = "central"

// Errors.
var (
	ErrBadCSR      = errors.New("pki: invalid certificate signing request")
	ErrBadIdentity = errors.New("pki: certificate does not carry a valid agent identity")
)

// Authority is the loaded CA and signing keys.
type Authority struct {
	holder  *store.Holder
	keyring *ccrypto.Keyring

	mu        sync.RWMutex
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPool    *x509.CertPool
	signer    ed25519.PrivateKey
	signerID  string
	signerPub ed25519.PublicKey

	serverMu    sync.Mutex
	serverCert  *tls.Certificate
	serverHosts []string
}

// New returns an Authority. Call Load before use.
func New(holder *store.Holder, kr *ccrypto.Keyring) *Authority {
	return &Authority{holder: holder, keyring: kr}
}

func caPurpose(id string) string     { return "pki.agent_ca:" + id }
func signerPurpose(id string) string { return "pki.command_signer:" + id }

// Load reads the CA and command-signing key from storage, creating them on first use.
func (a *Authority) Load(ctx context.Context) error {
	st := a.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	if err := a.loadCA(ctx, st); err != nil {
		return err
	}
	return a.loadSigner(ctx, st)
}

func (a *Authority) loadCA(ctx context.Context, st *store.Store) error {
	item, err := st.PKI.FindOne(ctx, store.System(), store.Eq("kind", store.PKIAgentCA).And("active", store.OpEq, true))
	if errors.Is(err, store.ErrNotFound) {
		item, err = a.createCA(ctx, st)
	}
	if err != nil {
		return fmt.Errorf("pki: load CA: %w", err)
	}
	block, _ := pem.Decode([]byte(item.CertPEM))
	if block == nil {
		return errors.New("pki: stored CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	der, err := a.keyring.Open(item.KeySealed, caPurpose(item.ID))
	if err != nil {
		return fmt.Errorf("pki: unseal CA key (wrong master key?): %w", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return fmt.Errorf("pki: parse CA key: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	a.mu.Lock()
	a.caCert, a.caKey, a.caPool = cert, key, pool
	a.mu.Unlock()
	return nil
}

func (a *Authority) createCA(ctx context.Context, st *store.Store) (*store.PKIItem, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Central Agent CA", Organization: []string{"Central"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	id := store.NewID()
	sealed, err := a.keyring.Seal(keyDER, caPurpose(id))
	if err != nil {
		return nil, err
	}
	item := &store.PKIItem{
		ID: id, Kind: store.PKIAgentCA, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeySealed: sealed, Active: true, Version: 1, NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter, CreatedAt: now,
	}
	return item, st.PKI.Create(ctx, store.System(), item)
}

func (a *Authority) loadSigner(ctx context.Context, st *store.Store) error {
	item, err := st.PKI.FindOne(ctx, store.System(), store.Eq("kind", store.PKICommandSigner).And("active", store.OpEq, true))
	if errors.Is(err, store.ErrNotFound) {
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return gerr
		}
		id := store.NewID()[:16]
		sealed, serr := a.keyring.Seal(priv.Seed(), signerPurpose(id))
		if serr != nil {
			return serr
		}
		now := time.Now().UTC()
		item = &store.PKIItem{
			ID: id, Kind: store.PKICommandSigner, PublicKey: pub, KeySealed: sealed, Active: true,
			Version: 1, NotBefore: now, NotAfter: now.Add(caValidity), CreatedAt: now,
		}
		err = st.PKI.Create(ctx, store.System(), item)
	}
	if err != nil {
		return fmt.Errorf("pki: load signing key: %w", err)
	}
	seed, err := a.keyring.Open(item.KeySealed, signerPurpose(item.ID))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("pki: unseal signing key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	a.mu.Lock()
	a.signer, a.signerID, a.signerPub = priv, item.ID, priv.Public().(ed25519.PublicKey) //nolint:forcetypeassert // ed25519 keys
	a.mu.Unlock()
	return nil
}

// Loaded reports whether Load has succeeded.
func (a *Authority) Loaded() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.caCert != nil && a.signer != nil
}

// CACertificate returns the CA certificate.
func (a *Authority) CACertificate() *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.caCert
}

// CAPool returns a pool containing only the CA (for verifying agent certificates).
func (a *Authority) CAPool() *x509.CertPool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.caPool
}

// Pin returns base64url(SHA-256(CA SubjectPublicKeyInfo)), the value embedded in enrollment keys.
func (a *Authority) Pin() string { return SPKIPin(a.CACertificate()) }

// SPKIPin computes the pin of a certificate.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ServerCertificate returns (and renews when needed) the agent listener certificate for hosts.
func (a *Authority) ServerCertificate(hosts []string) (*tls.Certificate, error) {
	a.serverMu.Lock()
	defer a.serverMu.Unlock()
	if a.serverCert != nil && sameHosts(a.serverHosts, hosts) && time.Until(a.serverCert.Leaf.NotAfter) > 30*24*time.Hour {
		return a.serverCert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "Central agent endpoint"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range append([]string{"localhost"}, hosts...) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	a.mu.RLock()
	ca, caKey := a.caCert, a.caKey
	a.mu.RUnlock()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}
	a.serverCert, a.serverHosts = cert, append([]string(nil), hosts...)
	return cert, nil
}

func sameHosts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseCSR validates a DER CSR: signature valid, key ECDSA P-256. It returns the CSR and the
// lowercase hex SHA-256 of the public key's SubjectPublicKeyInfo.
func ParseCSR(der []byte) (*x509.CertificateRequest, string, error) {
	if len(der) == 0 || len(der) > 8192 {
		return nil, "", ErrBadCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, "", ErrBadCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", ErrBadCSR
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", fmt.Errorf("%w: the key must be ECDSA P-256", ErrBadCSR)
	}
	return csr, ccrypto.SHA256Hex(csr.RawSubjectPublicKeyInfo), nil
}

// AgentIdentity identifies an agent certificate.
type AgentIdentity struct {
	OrgID   string
	AgentID string
	Serial  string
}

// SpiffeID returns the URI SAN for an agent.
func SpiffeID(orgID, agentID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: spiffeTrustDomain, Path: "/org/" + orgID + "/agent/" + agentID}
}

// IssueAgentCertificate signs a client certificate for a validated CSR.
func (a *Authority) IssueAgentCertificate(csr *x509.CertificateRequest, orgID, agentID string) (*x509.Certificate, error) {
	if !store.ValidID(orgID) || !store.ValidID(agentID) {
		return nil, errors.New("pki: invalid identity")
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{orgID}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(AgentCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{SpiffeID(orgID, agentID)},
	}
	a.mu.RLock()
	ca, caKey := a.caCert, a.caKey
	a.mu.RUnlock()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// IdentityFromCert extracts the agent identity from a verified client certificate.
func IdentityFromCert(cert *x509.Certificate) (AgentIdentity, error) {
	if len(cert.URIs) != 1 {
		return AgentIdentity{}, ErrBadIdentity
	}
	u := cert.URIs[0]
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "spiffe" || u.Host != spiffeTrustDomain || len(parts) != 4 || parts[0] != "org" || parts[2] != "agent" ||
		!store.ValidID(parts[1]) || !store.ValidID(parts[3]) {
		return AgentIdentity{}, ErrBadIdentity
	}
	return AgentIdentity{OrgID: parts[1], AgentID: parts[3], Serial: SerialString(cert)}, nil
}

// SerialString formats a certificate serial number.
func SerialString(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic("pki: randomness unavailable")
	}
	return n.Add(n, big.NewInt(1))
}

// SigningKey describes the active command-signing public key.
type SigningKey struct {
	ID        string
	PublicKey ed25519.PublicKey
	NotAfter  time.Time
}

// ActiveSigningKey returns the current command-signing public key.
func (a *Authority) ActiveSigningKey() SigningKey {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return SigningKey{ID: a.signerID, PublicKey: a.signerPub, NotAfter: time.Now().Add(caValidity)}
}

// SignCommand signs serialized command bytes and returns the signature and key ID.
func (a *Authority) SignCommand(command []byte) ([]byte, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	msg := append([]byte(CommandSignaturePrefix), command...)
	return ed25519.Sign(a.signer, msg), a.signerID
}

// Sign signs arbitrary bytes with the active key (with a caller-provided prefix).
func (a *Authority) Sign(prefix string, data []byte) ([]byte, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return ed25519.Sign(a.signer, append([]byte(prefix), data...)), a.signerID
}

// VerifyCommand checks a command signature (used by tests and the simulator; agents implement
// the same check).
func VerifyCommand(pub ed25519.PublicKey, command, sig []byte) bool {
	return ed25519.Verify(pub, append([]byte(CommandSignaturePrefix), command...), sig)
}

// ExportItems returns the stored PKI items (keys remain sealed) for key backups.
func (a *Authority) ExportItems(ctx context.Context) ([]*store.PKIItem, error) {
	st := a.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	return st.PKI.All(ctx, store.System(), store.Query{})
}
