// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package agentsim

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/pki"
)

func TestVerifyLikeTheHelper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	a := &Agent{ID: "a1", OrgID: "org", keys: map[string]ed25519.PublicKey{"k1": pub}, seen: map[string]time.Time{}}
	sign := func(c *agentv1.Command, key ed25519.PrivateKey, prefix string) *agentv1.SignedCommand {
		raw, _ := proto.Marshal(c)
		return &agentv1.SignedCommand{Command: raw, Signature: ed25519.Sign(key, append([]byte(prefix), raw...)), KeyId: "k1"}
	}
	now := time.Now()
	cmd := func(id, agent string, issued, expires time.Time) *agentv1.Command {
		return &agentv1.Command{CommandId: id, AgentId: agent, OrgId: "org", IssuedAt: timestamppb.New(issued), ExpiresAt: timestamppb.New(expires)}
	}
	ok := cmd("c1", "a1", now, now.Add(time.Minute))
	if _, code, err := a.Verify(sign(ok, priv, pki.CommandSignaturePrefix)); err != nil {
		t.Fatalf("valid command rejected: %v (%v)", err, code)
	}
	cases := map[string]struct {
		sc   *agentv1.SignedCommand
		want agentv1.ErrorCode
	}{
		"replay":        {sign(ok, priv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_REPLAYED},
		"other key":     {sign(cmd("c2", "a1", now, now.Add(time.Minute)), otherPriv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_BAD_SIGNATURE},
		"keyset prefix": {sign(cmd("c3", "a1", now, now.Add(time.Minute)), priv, pki.KeySetSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_BAD_SIGNATURE},
		"wrong agent":   {sign(cmd("c4", "a2", now, now.Add(time.Minute)), priv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_WRONG_TARGET},
		"expired":       {sign(cmd("c5", "a1", now.Add(-time.Hour), now.Add(-time.Minute)), priv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_EXPIRED},
		"future":        {sign(cmd("c6", "a1", now.Add(time.Hour), now.Add(2*time.Hour)), priv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_EXPIRED},
		"too long":      {sign(cmd("c7", "a1", now, now.Add(25*time.Hour)), priv, pki.CommandSignaturePrefix), agentv1.ErrorCode_ERROR_CODE_EXPIRED},
	}
	for name, c := range cases {
		if _, code, err := a.Verify(c.sc); err == nil || code != c.want {
			t.Errorf("%s: code %v err %v", name, code, err)
		}
	}
	// Tampering with the signed bytes breaks the signature.
	sc := sign(cmd("c8", "a1", now, now.Add(time.Minute)), priv, pki.CommandSignaturePrefix)
	sc.Command[len(sc.Command)-1] ^= 1
	if _, code, _ := a.Verify(sc); code != agentv1.ErrorCode_ERROR_CODE_BAD_SIGNATURE {
		t.Errorf("tampered: %v", code)
	}
}

func TestHostPolicyProfiles(t *testing.T) {
	observe := PolicyFor(agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE)
	administer := PolicyFor(agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER)
	full := PolicyFor(agentv1.PolicyProfile_POLICY_PROFILE_FULL)
	has := func(p *agentv1.EffectivePolicy, c agentv1.Capability) bool {
		for _, x := range p.GetAllowed() {
			if x == c {
				return true
			}
		}
		return false
	}
	if has(observe, agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE) || !has(administer, agentv1.Capability_CAPABILITY_PACKAGES_INSTALL) ||
		has(administer, agentv1.Capability_CAPABILITY_TERMINAL) || has(administer, agentv1.Capability_CAPABILITY_EXEC) ||
		!has(full, agentv1.Capability_CAPABILITY_TERMINAL) || has(full, agentv1.Capability_CAPABILITY_AGENT_UNINSTALL) {
		t.Fatal("profiles do not match docs/agent/local-policy.md")
	}
	h := NewHost("x", 1, agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE)
	u := h.Handle(t.Context(), &Conn{}, &agentv1.Command{Operation: &agentv1.Operation{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{}}}})
	if u.GetState() != agentv1.CommandState_COMMAND_STATE_REJECTED || u.GetError().GetCode() != agentv1.ErrorCode_ERROR_CODE_POLICY_DENIED {
		t.Fatalf("observe host upgraded: %v", u)
	}
	if f := h.Facts(); f.GetAddresses()[0].GetCidr() != h.Facts().GetAddresses()[0].GetCidr() || len(f.GetMachineId()) != 32 {
		t.Fatal("facts must be stable")
	}
}
