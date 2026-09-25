// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package crypto holds Central's cryptographic primitives: master-key envelope encryption for
// secrets at rest, random token generation, and hashing helpers.
//
// Everything here uses the Go standard library (AES-256-GCM, SHA-256, crypto/rand). Keep this
// package small and boring: it is security-critical and heavily tested.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MasterKeySize is the size of the master key in bytes (AES-256).
const MasterKeySize = 32

// sealedPrefix identifies the envelope format version.
const sealedPrefix = "cenc1"

var (
	// ErrDecrypt is returned when a sealed value cannot be decrypted (wrong key, tampered data).
	ErrDecrypt = errors.New("crypto: decryption failed")
	// ErrUnknownKey is returned when a sealed value references a key ID the keyring lacks.
	ErrUnknownKey = errors.New("crypto: unknown key id")
)

// Keyring encrypts and decrypts secrets with the master key. It supports several keys (for
// rotation): new values are sealed with the primary key, and values sealed with any known key
// can be opened.
type Keyring struct {
	mu      sync.RWMutex
	primary string
	aeads   map[string]cipher.AEAD
}

// NewKeyring builds a keyring from one master key; the key ID is derived from the key.
func NewKeyring(masterKey []byte) (*Keyring, error) {
	kr := &Keyring{aeads: map[string]cipher.AEAD{}}
	if err := kr.Add(masterKey, true); err != nil {
		return nil, err
	}
	return kr, nil
}

// Add registers an additional key. If primary is set, new values are sealed with it.
func (k *Keyring) Add(masterKey []byte, primary bool) error {
	if len(masterKey) != MasterKeySize {
		return fmt.Errorf("crypto: master key must be %d bytes, got %d", MasterKeySize, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}
	id := KeyID(masterKey)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.aeads[id] = aead
	if primary || k.primary == "" {
		k.primary = id
	}
	return nil
}

// PrimaryKeyID returns the ID of the key used for sealing.
func (k *Keyring) PrimaryKeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.primary
}

// KeyID derives a short, non-secret identifier for a master key.
func KeyID(masterKey []byte) string {
	sum := sha256.Sum256(append([]byte("central-key-id-v1\x00"), masterKey...))
	return hex.EncodeToString(sum[:4])
}

// Seal encrypts plaintext. The associated data (for example "appwrite.api_key" or a row ID)
// binds the ciphertext to its purpose: a value sealed for one purpose cannot be opened as
// another. The result is a printable string: "cenc1.<key id>.<base64url(nonce||ciphertext)>".
func (k *Keyring) Seal(plaintext []byte, associatedData string) (string, error) {
	k.mu.RLock()
	id := k.primary
	aead := k.aeads[id]
	k.mu.RUnlock()
	if aead == nil {
		return "", ErrUnknownKey
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("crypto: %w", err)
	}
	out := aead.Seal(nonce, nonce, plaintext, []byte(associatedData))
	return sealedPrefix + "." + id + "." + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal with the same associated data.
func (k *Keyring) Open(sealed, associatedData string) ([]byte, error) {
	parts := strings.Split(sealed, ".")
	if len(parts) != 3 || parts[0] != sealedPrefix {
		return nil, ErrDecrypt
	}
	k.mu.RLock()
	aead := k.aeads[parts[1]]
	k.mu.RUnlock()
	if aead == nil {
		return nil, ErrUnknownKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(associatedData))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// SealString is Seal for string plaintexts.
func (k *Keyring) SealString(plaintext, associatedData string) (string, error) {
	return k.Seal([]byte(plaintext), associatedData)
}

// OpenString is Open returning a string.
func (k *Keyring) OpenString(sealed, associatedData string) (string, error) {
	b, err := k.Open(sealed, associatedData)
	return string(b), err
}

// LoadOrCreateMasterKey reads a base64url-encoded master key from path, or generates a new one
// (written with mode 0600) if the file does not exist. created reports whether a new key was
// generated, so the caller can warn the operator to back it up.
func LoadOrCreateMasterKey(path string) (key []byte, created bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from trusted configuration
	switch {
	case err == nil:
		key, err = decodeMasterKey(data)
		return key, false, err
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("crypto: read master key: %w", err)
	}
	key = make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("crypto: generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("crypto: create key dir: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key) + "\n"
	if err := WriteFileAtomic(path, []byte(encoded), 0o600); err != nil {
		return nil, false, fmt.Errorf("crypto: write master key: %w", err)
	}
	return key, true, nil
}

// DecodeMasterKey parses a master key given inline (e.g. from an environment variable).
func DecodeMasterKey(s string) ([]byte, error) { return decodeMasterKey([]byte(s)) }

func decodeMasterKey(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if key, err := enc.DecodeString(s); err == nil && len(key) == MasterKeySize {
			return key, nil
		}
	}
	return nil, fmt.Errorf("crypto: master key must be %d bytes, base64 encoded", MasterKeySize)
}

// WriteFileAtomic writes data to path via a temporary file and rename, so readers never see a
// partially written file. The file is fsynced before the rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
