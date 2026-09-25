// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// TOTP parameters: RFC 6238 defaults (SHA-1, 6 digits, 30 s) for compatibility with every
// authenticator app; security comes from the secret's 160 bits, rate limiting and replay
// protection, not from the hash function.
const (
	totpPeriod      = 30
	totpDigits      = otp.DigitsSix
	totpSecretBytes = 20
	totpPurpose     = "mfa.totp.secret"
)

// ErrInvalidCode is returned for a wrong or replayed MFA code.
var ErrInvalidCode = errors.New("auth: invalid code")

// NewTOTPSecret returns a new base32 secret and the otpauth:// URI for QR enrollment.
func NewTOTPSecret(issuer, account string) (secret, uri string) {
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(crypto.RandomBytes(totpSecretBytes))
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return secret, "otpauth://totp/" + label + "?" + v.Encode()
}

// SealTOTP encrypts a TOTP secret for storage, bound to its credential ID.
func SealTOTP(kr *crypto.Keyring, credentialID, secret string) (string, error) {
	return kr.SealString(secret, totpPurpose+":"+credentialID)
}

// VerifyTOTP checks a code against a sealed secret, allowing one step of clock skew and
// rejecting reuse of the last accepted step. It returns the step to record on success.
func VerifyTOTP(kr *crypto.Keyring, cred *store.MFACredential, code string, now time.Time) (int64, error) {
	secret, err := kr.OpenString(cred.TOTPSecretSealed, totpPurpose+":"+cred.ID)
	if err != nil {
		return 0, err
	}
	return verifyTOTPSecret(secret, code, cred.TOTPLastStep, now)
}

// VerifyTOTPSecret validates a code against a plaintext secret (enrollment confirmation).
func VerifyTOTPSecret(secret, code string, now time.Time) (int64, error) {
	return verifyTOTPSecret(secret, code, 0, now)
}

func verifyTOTPSecret(secret, code string, lastStep int64, now time.Time) (int64, error) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, ErrInvalidCode
	}
	step := now.Unix() / totpPeriod
	for _, s := range []int64{step, step - 1, step + 1} {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(s*totpPeriod, 0), totp.ValidateOpts{
			Period: totpPeriod, Digits: totpDigits, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, fmt.Errorf("auth: totp: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if s <= lastStep {
				return 0, ErrInvalidCode // replay of an already used code
			}
			return s, nil
		}
	}
	return 0, ErrInvalidCode
}

// Recovery codes: 10 single-use codes of 10 base32 characters (50 bits), shown once.
const recoveryCodeCount = 10

const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewRecoveryCodes generates codes formatted XXXXX-XXXXX.
func NewRecoveryCodes() []string {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		raw := crypto.RandomBytes(10)
		var b strings.Builder
		for j, c := range raw {
			if j == 5 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		codes[i] = b.String()
	}
	return codes
}

// NormalizeRecoveryCode uppercases and strips separators.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}

// HashRecoveryCode hashes a normalized code for storage.
func HashRecoveryCode(userID, code string) string {
	return crypto.HashToken("recovery:"+userID, NormalizeRecoveryCode(code))
}

// ReplaceRecoveryCodes deletes a user's codes and stores new ones, returning the plaintext.
func ReplaceRecoveryCodes(ctx context.Context, st *store.Store, userID string) ([]string, error) {
	if _, err := st.RecoveryCodes.DeleteWhere(ctx, store.System(), store.Eq("user_id", userID)); err != nil {
		return nil, err
	}
	codes := NewRecoveryCodes()
	now := time.Now().UTC()
	for _, c := range codes {
		rc := &store.RecoveryCode{ID: store.NewID(), UserID: userID, CodeHash: HashRecoveryCode(userID, c), CreatedAt: now}
		if err := st.RecoveryCodes.Create(ctx, store.System(), rc); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// UseRecoveryCode consumes a code; it reports the number of unused codes left.
func UseRecoveryCode(ctx context.Context, st *store.Store, userID, code string) (int, error) {
	codes, err := st.RecoveryCodes.All(ctx, store.System(), store.Eq("user_id", userID))
	if err != nil {
		return 0, err
	}
	want := HashRecoveryCode(userID, code)
	var match *store.RecoveryCode
	remaining := 0
	for _, c := range codes {
		if !c.UsedAt.IsZero() {
			continue
		}
		if crypto.EqualHashes(c.CodeHash, want) && match == nil {
			match = c
			continue
		}
		remaining++
	}
	if match == nil {
		return remaining, ErrInvalidCode
	}
	match.UsedAt = time.Now().UTC()
	if err := st.RecoveryCodes.Update(ctx, store.System(), match); err != nil {
		return 0, err
	}
	return remaining, nil
}

// CountRecoveryCodes returns the number of unused codes.
func CountRecoveryCodes(ctx context.Context, st *store.Store, userID string) (int, error) {
	codes, err := st.RecoveryCodes.All(ctx, store.System(), store.Eq("user_id", userID))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range codes {
		if c.UsedAt.IsZero() {
			n++
		}
	}
	return n, nil
}
