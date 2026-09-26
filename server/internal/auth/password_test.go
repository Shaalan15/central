// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h, err := HashPassword(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=2,p=2$") {
		t.Fatalf("unexpected hash format %s", h)
	}
	rehash, err := VerifyPassword(ctx, h, "correct horse battery")
	if err != nil || rehash {
		t.Fatalf("verify: rehash=%v err=%v", rehash, err)
	}
	if _, err := VerifyPassword(ctx, h, "wrong horse battery"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	h2, _ := HashPassword(ctx, "correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	ctx := context.Background()
	for _, h := range []string{
		"", "plain", "$argon2i$v=19$m=65536,t=2,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",        // params too weak
		"$argon2id$v=19$m=99999999,t=2,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // DoS params
		"$argon2id$v=19$m=65536,t=2,p=2$!!!$aGFzaGhhc2hoYXNoaGFzaA",
	} {
		if _, err := VerifyPassword(ctx, h, "x"); err == nil {
			t.Fatalf("accepted malformed hash %q", h)
		}
	}
}

func TestVerifyLegacyParamsNeedRehash(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte("some long password"), salt, 1, argonMemory, argonThreads, argonKeyLen)
	legacy := fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=%d$%s$%s", argonMemory, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	rehash, err := VerifyPassword(context.Background(), legacy, "some long password")
	if err != nil || !rehash {
		t.Fatalf("legacy hash: rehash=%v err=%v", rehash, err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	ok := []string{"tidy-lantern-orbit-42", "Völlig sicheres Passwort", "correct horse battery"}
	for _, p := range ok {
		if err := CheckPasswordPolicy(p, "alice@example.com", "Acme Corp"); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	bad := map[string]string{
		"short":          "short1",
		"common":         "Password1234",
		"repeated":       "aaaaaaaaaaaaaaaa",
		"few distinct":   "abababababab",
		"sequence":       "abcdefghijklmn",
		"digits":         "123456789012",
		"keyboard":       "qwertyuiopasd",
		"contains email": "alicealice-horse",
		"contains org":   "i-love-acme-corp-servers",
		"control char":   "tidy-lantern\x00orbit",
		"too long":       strings.Repeat("x9", 200),
	}
	for name, p := range bad {
		if err := CheckPasswordPolicy(p, "alice@example.com", "acme corp"); err == nil {
			t.Errorf("%s: %q accepted", name, p)
		}
	}
}

func TestLongPasswordRejectedBeforeHashing(t *testing.T) {
	if _, err := HashPassword(context.Background(), strings.Repeat("x", MaxPasswordLength+1)); err == nil {
		t.Fatal("expected error")
	}
	if _, err := VerifyPassword(context.Background(), dummyHash, strings.Repeat("x", 10000)); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}
}
