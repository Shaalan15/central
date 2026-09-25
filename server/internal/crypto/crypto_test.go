// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, MasterKeySize) }

func TestSealOpenRoundTrip(t *testing.T) {
	kr, err := NewKeyring(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := kr.SealString("s3cr3t", "appwrite.api_key")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "s3cr3t") {
		t.Fatal("sealed value contains plaintext")
	}
	got, err := kr.OpenString(sealed, "appwrite.api_key")
	if err != nil || got != "s3cr3t" {
		t.Fatalf("OpenString = %q, %v", got, err)
	}
}

func TestSealIsRandomized(t *testing.T) {
	kr, _ := NewKeyring(testKey(1))
	a, _ := kr.SealString("x", "p")
	b, _ := kr.SealString("x", "p")
	if a == b {
		t.Fatal("two seals of the same plaintext are identical (nonce reuse?)")
	}
}

func TestOpenRejectsWrongAssociatedData(t *testing.T) {
	kr, _ := NewKeyring(testKey(1))
	sealed, _ := kr.SealString("x", "purpose-a")
	if _, err := kr.OpenString(sealed, "purpose-b"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	kr, _ := NewKeyring(testKey(1))
	sealed, _ := kr.SealString("hello world", "p")
	parts := strings.Split(sealed, ".")
	payload := []byte(parts[2])
	// Flip one character in the ciphertext.
	if payload[10] == 'A' {
		payload[10] = 'B'
	} else {
		payload[10] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(payload)
	if _, err := kr.Open(tampered, "p"); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	for _, bad := range []string{"", "cenc1", "cenc1.x", "nope.a.b", sealed + ".extra", "cenc1." + parts[1] + ".!!!"} {
		if _, err := kr.Open(bad, "p"); err == nil {
			t.Fatalf("malformed value %q decrypted", bad)
		}
	}
}

func TestOpenRejectsUnknownKey(t *testing.T) {
	a, _ := NewKeyring(testKey(1))
	b, _ := NewKeyring(testKey(2))
	sealed, _ := a.SealString("x", "p")
	if _, err := b.OpenString(sealed, "p"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	kr, _ := NewKeyring(testKey(1))
	old, _ := kr.SealString("old", "p")
	if err := kr.Add(testKey(2), true); err != nil {
		t.Fatal(err)
	}
	if kr.PrimaryKeyID() != KeyID(testKey(2)) {
		t.Fatal("new key is not primary")
	}
	fresh, _ := kr.SealString("new", "p")
	if !strings.Contains(fresh, KeyID(testKey(2))) {
		t.Fatal("new value not sealed with the new primary key")
	}
	if got, err := kr.OpenString(old, "p"); err != nil || got != "old" {
		t.Fatalf("old value no longer opens: %q %v", got, err)
	}
}

func TestNewKeyringRejectsBadKeySize(t *testing.T) {
	if _, err := NewKeyring([]byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestLoadOrCreateMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "master.key")
	key, created, err := LoadOrCreateMasterKey(path)
	if err != nil || !created || len(key) != MasterKeySize {
		t.Fatalf("create: key=%d created=%v err=%v", len(key), created, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master key file mode = %o, want 600", perm)
	}
	again, created, err := LoadOrCreateMasterKey(path)
	if err != nil || created || !bytes.Equal(again, key) {
		t.Fatalf("reload: created=%v err=%v equal=%v", created, err, bytes.Equal(again, key))
	}
}

func TestLoadMasterKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateMasterKey(path); err == nil {
		t.Fatal("expected error for invalid key file")
	}
}

func TestHashTokenDomainSeparation(t *testing.T) {
	if HashToken("session", "abc") == HashToken("api_key", "abc") {
		t.Fatal("hashes for different purposes collide")
	}
	if !EqualHashes(HashToken("session", "abc"), HashToken("session", "abc")) {
		t.Fatal("same input hashes differ")
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("hunter2")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "secret", s)
	j, _ := json.Marshal(struct{ S Secret }{s})
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), buf.String(), string(j)} {
		if strings.Contains(out, "hunter2") {
			t.Fatalf("secret leaked: %s", out)
		}
	}
	if s.Reveal() != "hunter2" {
		t.Fatal("Reveal broken")
	}
}

func TestRandomToken(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		tok := RandomToken(32)
		if len(tok) != 43 || seen[tok] {
			t.Fatalf("bad or duplicate token %q", tok)
		}
		seen[tok] = true
	}
	if len(RandomHex(16)) != 32 {
		t.Fatal("RandomHex length")
	}
}
