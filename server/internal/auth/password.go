// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package auth implements Central-native authentication: password hashing, password policy,
// sessions, MFA (TOTP, passkeys, recovery codes), step-up and API keys.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/Shaalan15/central/server/internal/crypto"
)

// Argon2id parameters (OWASP recommends >= 19 MiB, t=2; we use more memory). Each hash takes
// 64 MiB, so concurrency is bounded by hashSlots to keep login floods from exhausting memory.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
	hashSlots    = 4
)

// Password length limits (bytes). The upper bound caps hashing cost for hostile input.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

var slots = make(chan struct{}, hashSlots)

// ErrPasswordMismatch is returned by VerifyPassword for a wrong password.
var ErrPasswordMismatch = errors.New("auth: password mismatch")

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(ctx context.Context, password string) (string, error) {
	if len(password) > MaxPasswordLength {
		return "", errors.New("auth: password too long")
	}
	if err := acquire(ctx); err != nil {
		return "", err
	}
	defer release()
	salt := crypto.RandomBytes(argonSaltLen)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC argon2id hash in constant time. needsRehash
// reports whether the hash uses outdated parameters and should be replaced after login.
func VerifyPassword(ctx context.Context, encoded, password string) (needsRehash bool, err error) {
	if len(password) > MaxPasswordLength {
		return false, ErrPasswordMismatch
	}
	p, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	if err := acquire(ctx); err != nil {
		return false, err
	}
	defer release()
	got := argon2.IDKey([]byte(password), salt, p.t, p.m, p.p, uint32(len(want))) //nolint:gosec // len(want) is 32
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, ErrPasswordMismatch
	}
	return p.m != argonMemory || p.t != argonTime || p.p != argonThreads, nil
}

// dummyHash is verified against when a user does not exist, so login timing does not reveal
// whether an account exists.
var dummyHash = func() string {
	h, _ := HashPassword(context.Background(), "central-dummy-password-for-timing")
	return h
}()

// VerifyDummy spends the same work as VerifyPassword for unknown users.
func VerifyDummy(ctx context.Context, password string) {
	_, _ = VerifyPassword(ctx, dummyHash, password)
}

type argonParams struct {
	m, t uint32
	p    uint8
}

func parsePHC(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, errors.New("auth: unsupported password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, errors.New("auth: unsupported argon2 version")
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.m, &p.t, &p.p); err != nil {
		return argonParams{}, nil, nil, errors.New("auth: malformed argon2 parameters")
	}
	if p.m < 8*1024 || p.m > 1024*1024 || p.t < 1 || p.t > 10 || p.p < 1 || p.p > 16 {
		return argonParams{}, nil, nil, errors.New("auth: argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return argonParams{}, nil, nil, errors.New("auth: malformed salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return argonParams{}, nil, nil, errors.New("auth: malformed hash")
	}
	return p, salt, key, nil
}

func acquire(ctx context.Context) error {
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release() { <-slots }

// ErrWeakPassword describes why a password was rejected.
type ErrWeakPassword struct{ Reason string }

func (e *ErrWeakPassword) Error() string { return "password " + e.Reason }

// CheckPasswordPolicy enforces NIST SP 800-63B-style rules: a minimum length, no composition
// rules, and rejection of common, trivially patterned or context-derived passwords.
// context values (email, names) must not appear in the password.
func CheckPasswordPolicy(password string, contextWords ...string) error {
	if !utf8.ValidString(password) {
		return &ErrWeakPassword{"must be valid UTF-8"}
	}
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLength {
		return &ErrWeakPassword{fmt.Sprintf("must be at least %d characters", MinPasswordLength)}
	}
	if len(password) > MaxPasswordLength {
		return &ErrWeakPassword{fmt.Sprintf("must be at most %d bytes", MaxPasswordLength)}
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return &ErrWeakPassword{"must not contain control characters"}
		}
	}
	lower := strings.ToLower(password)
	if _, ok := commonPasswords[lower]; ok || distinctRunes(lower) < 5 || isSequential(lower) {
		return &ErrWeakPassword{"is too common or predictable"}
	}
	for _, w := range contextWords {
		w = strings.ToLower(strings.TrimSpace(w))
		if at := strings.IndexByte(w, '@'); at > 0 {
			w = w[:at]
		}
		tokens := strings.FieldsFunc(w, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		for _, tok := range append(tokens, w) {
			if utf8.RuneCountInString(tok) >= 4 && strings.Contains(lower, tok) {
				return &ErrWeakPassword{"must not contain your name, email or organization"}
			}
		}
	}
	return nil
}

func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// isSequential detects runs like "abcdefghijkl", "123456789012" or "qwertyuiopas".
func isSequential(s string) bool {
	for _, seq := range []string{
		"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
		"01234567890123456789012345678901234567890",
		"qwertyuiopasdfghjklzxcvbnmqwertyuiop",
		"zyxwvutsrqponmlkjihgfedcbazyxwvutsrqponmlkjihgfedcba",
		"98765432109876543210987654321098765432109",
	} {
		if strings.Contains(seq, s) {
			return true
		}
	}
	return false
}

// commonPasswords rejects the most frequently breached passwords that meet the length rule.
var commonPasswords = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, p := range strings.Fields(`
password1234 password12345 password123456 passwordpassword qwertyuiop123 1q2w3e4r5t6y
1qaz2wsx3edc qazwsxedcrfv iloveyou1234 administrator changeme1234 welcome12345
letmein12345 monkey123456 football1234 baseball1234 superman1234 princess1234
trustno1trustno1 sunshine1234 starwars1234 dragon123456 master123456 shadow123456
abcd12345678 aaaaaaaaaaaa 111111111111 123123123123 121212121212 000000000000
passw0rd1234 p@ssw0rd1234 p@ssword1234 password!234 qwerty123456 asdfghjkl123
zxcvbnm12345 correcthorsebatterystaple centralcentral admin1234567 rootpassword
`) {
		m[p] = struct{}{}
	}
	return m
}()
