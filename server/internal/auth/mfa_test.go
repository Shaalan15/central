// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTOTP(t *testing.T) {
	kr, _ := crypto.NewKeyring(bytes.Repeat([]byte{7}, 32))
	secret, uri := NewTOTPSecret("Central", "alice@example.com")
	u, err := url.Parse(uri)
	if err != nil || u.Query().Get("secret") != secret || !strings.Contains(uri, "totp/Central:alice@example.com?") {
		t.Fatalf("uri = %s", uri)
	}
	cred := &store.MFACredential{ID: "c1"}
	cred.TOTPSecretSealed, _ = SealTOTP(kr, cred.ID, secret)
	now := time.Unix(1_800_000_000, 0)

	step, err := VerifyTOTP(kr, cred, code(t, secret, now), now)
	if err != nil {
		t.Fatal(err)
	}
	cred.TOTPLastStep = step
	if _, err := VerifyTOTP(kr, cred, code(t, secret, now), now); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("replay within the same step accepted")
	}
	if _, err := VerifyTOTP(kr, cred, code(t, secret, now.Add(-30*time.Second)), now); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("older step accepted after a newer one")
	}
	if _, err := VerifyTOTP(kr, cred, code(t, secret, now.Add(30*time.Second)), now); err != nil {
		t.Fatalf("one step of skew rejected: %v", err)
	}
	cred.TOTPLastStep = 0
	if _, err := VerifyTOTP(kr, cred, code(t, secret, now.Add(90*time.Second)), now); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("three steps of skew accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, err := VerifyTOTP(kr, cred, bad, now); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// A secret sealed for one credential cannot be used as another's.
	other := &store.MFACredential{ID: "c2", TOTPSecretSealed: cred.TOTPSecretSealed}
	if _, err := VerifyTOTP(kr, other, code(t, secret, now), now); err == nil {
		t.Fatal("sealed secret swapped between credentials")
	}
}

func TestRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := store.Open(memory.New())
	_ = s.Migrate(ctx)
	codes, err := ReplaceRecoveryCodes(ctx, s, "u1")
	if err != nil || len(codes) != 10 {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
	}
	left, err := UseRecoveryCode(ctx, s, "u1", " "+strings.ToLower(strings.ReplaceAll(codes[3], "-", ""))+" ")
	if err != nil || left != 9 {
		t.Fatalf("use: %d %v", left, err)
	}
	if _, err := UseRecoveryCode(ctx, s, "u1", codes[3]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("code reused")
	}
	if _, err := UseRecoveryCode(ctx, s, "u2", codes[4]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("code used by another user")
	}
	// Regeneration invalidates the old set.
	if _, err := ReplaceRecoveryCodes(ctx, s, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := UseRecoveryCode(ctx, s, "u1", codes[5]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("old code valid after regeneration")
	}
	if n, _ := CountRecoveryCodes(ctx, s, "u1"); n != 10 {
		t.Fatalf("count = %d", n)
	}
}

func TestSessionsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := store.Open(memory.New())
	_ = s.Migrate(ctx)
	h := &store.Holder{}
	h.Set(s)
	m := NewSessions(h)
	now := time.Now()
	m.now = func() time.Time { return now }
	to := SessionTimeouts{Idle: 30 * time.Minute, Max: 12 * time.Hour}

	token, sess, err := m.Create(ctx, "u1", "org", store.SessionStageFull, "1.2.3.4", "ua", to)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sess.TokenHash, token) || sess.ID != sess.TokenHash[:32] {
		t.Fatal("token stored in clear or bad id")
	}
	got, err := m.Lookup(ctx, token)
	if err != nil || got.UserID != "u1" {
		t.Fatalf("lookup: %v", err)
	}
	if _, err := m.Lookup(ctx, token[:len(token)-1]+"x"); !errors.Is(err, ErrNoSession) {
		t.Fatal("tampered token accepted")
	}
	// Idle timeout.
	now = now.Add(31 * time.Minute)
	m.cache = map[string]cachedSession{}
	if _, err := m.Lookup(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatal("idle session still valid")
	}
	// Partial sessions expire after 10 minutes regardless of org settings.
	ptoken, _, _ := m.Create(ctx, "u1", "org", store.SessionStageMFARequired, "", "", to)
	now = now.Add(11 * time.Minute)
	m.cache = map[string]cachedSession{}
	if _, err := m.Lookup(ctx, ptoken); !errors.Is(err, ErrNoSession) {
		t.Fatal("partial session outlived its TTL")
	}
	// Revoke all sessions of a user except one.
	a, sa, _ := m.Create(ctx, "u2", "org", store.SessionStageFull, "", "", to)
	b, _, _ := m.Create(ctx, "u2", "org", store.SessionStageFull, "", "", to)
	if err := m.RevokeUser(ctx, "u2", sa.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Lookup(ctx, a); err != nil {
		t.Fatal("kept session revoked")
	}
	if _, err := m.Lookup(ctx, b); !errors.Is(err, ErrNoSession) {
		t.Fatal("other session survived RevokeUser")
	}
}
