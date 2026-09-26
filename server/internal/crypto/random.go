// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
)

// RandomBytes returns n cryptographically random bytes. It panics if the system randomness
// source fails, which is unrecoverable (Go's crypto/rand never returns short reads on Linux).
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto: system randomness unavailable: " + err.Error())
	}
	return b
}

// RandomToken returns n random bytes encoded as unpadded base64url.
func RandomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

// RandomHex returns n random bytes encoded as lowercase hex (2n characters).
func RandomHex(n int) string {
	return hex.EncodeToString(RandomBytes(n))
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashToken hashes a high-entropy secret token for storage. Tokens are random with >= 128 bits
// of entropy, so a fast hash is appropriate (no password-hashing KDF needed). The purpose
// string domain-separates hashes of different token types.
func HashToken(purpose, token string) string {
	h := sha256.New()
	h.Write([]byte("central-token-v1\x00"))
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// EqualHashes compares two hex hashes in constant time.
func EqualHashes(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Secret wraps a sensitive string so it is never printed by fmt or slog.
type Secret string

// String implements fmt.Stringer and redacts the value.
func (Secret) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer and redacts the value.
func (Secret) GoString() string { return "[REDACTED]" }

// LogValue implements slog.LogValuer and redacts the value.
func (Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalText redacts the value in text encodings (JSON, TOML) to prevent accidental leaks.
// Code that must persist a secret seals it with the Keyring and stores the sealed string.
func (Secret) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

// Reveal returns the underlying value. Call sites are easy to audit with grep.
func (s Secret) Reveal() string { return string(s) }
