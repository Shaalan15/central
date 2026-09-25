// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package agentsim

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/pki"
)

type savedAgent struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"org_id"`
	URL         string            `json:"url"`
	Pin         string            `json:"pin"`
	ServerName  string            `json:"server_name"`
	Key         []byte            `json:"key_pkcs8"`
	Certificate []byte            `json:"certificate"`
	CAs         [][]byte          `json:"cas"`
	SigningKeys map[string][]byte `json:"signing_keys"`
	Facts       json.RawMessage   `json:"facts"`
}

// Save writes the agent's credentials to path (mode 0600).
func (a *Agent) Save(path string) error {
	key, err := x509.MarshalPKCS8PrivateKey(a.cert.PrivateKey)
	if err != nil {
		return err
	}
	facts, err := protojson.Marshal(a.Facts)
	if err != nil {
		return err
	}
	s := savedAgent{
		ID: a.ID, OrgID: a.OrgID, URL: a.URL, Pin: a.pin, ServerName: a.serverName, Key: key,
		Certificate: a.cert.Certificate[0], CAs: a.cas, SigningKeys: map[string][]byte{}, Facts: facts,
	}
	a.mu.Lock()
	for id, k := range a.keys {
		s.SigningKeys[id] = k
	}
	a.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return crypto.WriteFileAtomic(path, data, 0o600)
}

// Load reads credentials written by Save.
func Load(path string) (*Agent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s savedAgent
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(s.Key)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("agentsim: stored key is not ECDSA")
	}
	roots := x509.NewCertPool()
	for _, der := range s.CAs {
		ca, err := x509.ParseCertificate(der)
		if err != nil || pki.SPKIPin(ca) != s.Pin {
			return nil, errors.New("agentsim: stored CA does not match the pin")
		}
		roots.AddCert(ca)
	}
	facts := &agentv1.HostFacts{}
	if err := protojson.Unmarshal(s.Facts, facts); err != nil {
		return nil, err
	}
	a := &Agent{
		ID: s.ID, OrgID: s.OrgID, URL: s.URL, pin: s.Pin, serverName: s.ServerName, roots: roots, cas: s.CAs,
		cert: tls.Certificate{Certificate: [][]byte{s.Certificate}, PrivateKey: key}, Facts: facts,
		keys: map[string]ed25519.PublicKey{}, seen: map[string]time.Time{},
	}
	for id, pub := range s.SigningKeys {
		a.keys[id] = pub
	}
	a.client = agentv1connect.NewAgentServiceClient(httpClient(s.Pin, s.ServerName, &a.cert, roots), s.URL, connect.WithGRPC())
	return a, nil
}
