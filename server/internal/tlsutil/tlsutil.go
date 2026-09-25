// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package tlsutil builds TLS configurations for Central's listeners.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/Shaalan15/central/server/internal/config"
)

// BrowserConfig returns a TLS config suitable for the UI/API listener: TLS 1.2+ with modern
// AEAD cipher suites only (TLS 1.3 suites are always enabled by Go).
func BrowserConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// ForUI returns the TLS config for the UI listener, or nil for TLSOff.
func ForUI(cfg config.Config) (*tls.Config, error) {
	switch cfg.HTTP.TLS.Mode {
	case config.TLSOff:
		return nil, nil
	case config.TLSFiles:
		r := &fileReloader{certFile: cfg.HTTP.TLS.CertFile, keyFile: cfg.HTTP.TLS.KeyFile}
		if _, err := r.get(nil); err != nil {
			return nil, err
		}
		c := BrowserConfig()
		c.GetCertificate = r.get
		return c, nil
	case config.TLSACME:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.HTTP.TLS.ACMEDomains...),
			Cache:      autocert.DirCache(cfg.DataDir + "/acme"),
			Email:      cfg.HTTP.TLS.ACMEEmail,
		}
		if cfg.HTTP.TLS.ACMEDirectory != "" {
			m.Client = &acme.Client{DirectoryURL: cfg.HTTP.TLS.ACMEDirectory}
		}
		c := BrowserConfig()
		c.GetCertificate = m.GetCertificate
		c.NextProtos = append(c.NextProtos, acme.ALPNProto)
		return c, nil
	case config.TLSSelfSigned:
		cert, err := SelfSigned([]string{"localhost"}, 90*24*time.Hour)
		if err != nil {
			return nil, err
		}
		c := BrowserConfig()
		c.Certificates = []tls.Certificate{cert}
		return c, nil
	}
	return nil, fmt.Errorf("tlsutil: unknown mode %q", cfg.HTTP.TLS.Mode)
}

// fileReloader serves a certificate from disk and reloads it when the files change, so
// certificates renewed by an external tool (certbot, cert-manager) are picked up.
type fileReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	modTime           time.Time
	checked           time.Time
}

func (r *fileReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checked) < 30*time.Second {
		return r.cert, nil
	}
	r.checked = time.Now()
	st, err := os.Stat(r.certFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, fmt.Errorf("tlsutil: %w", err)
	}
	if r.cert != nil && st.ModTime().Equal(r.modTime) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil // keep serving the old certificate
		}
		return nil, fmt.Errorf("tlsutil: load certificate: %w", err)
	}
	r.cert, r.modTime = &cert, st.ModTime()
	return r.cert, nil
}

// SelfSigned creates a throwaway self-signed ECDSA certificate (testing and LAN use only).
func SelfSigned(hosts []string, validity time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Central (self-signed)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
