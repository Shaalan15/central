// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(Flags{DataDir: dir}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":8080" || cfg.Agent.Addr != ":9443" || cfg.HTTP.TLS.Mode != TLSOff {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.StorageConfigured() {
		t.Fatal("storage must be unconfigured by default")
	}
	if cfg.MasterKeyFile != filepath.Join(dir, "master.key") {
		t.Fatalf("master key file = %s", cfg.MasterKeyFile)
	}
}

func TestDevModeUsesPersistentMemoryStore(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(Flags{Dev: true, DataDir: dir}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Driver != DriverMemory || cfg.Storage.MemoryPath != filepath.Join(dir, "dev-store.json") {
		t.Fatalf("dev storage = %+v", cfg.Storage)
	}
	if !cfg.StoragePreconfigured() {
		t.Fatal("dev storage should count as preconfigured")
	}
}

func TestMemoryDriverRefusedOutsideDev(t *testing.T) {
	_, err := Load(Flags{DataDir: t.TempDir()}, envMap(map[string]string{"CENTRAL_STORAGE_DRIVER": "memory"}))
	if err == nil || !strings.Contains(err.Error(), "only allowed in --dev") {
		t.Fatalf("err = %v", err)
	}
}

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, StateFileName), `
[storage]
driver = "appwrite"
[storage.appwrite]
endpoint = "https://state.example.com/v1"
project_id = "state"
api_key_sealed = "cenc1.x.y"
`)
	write(t, filepath.Join(dir, "central.toml"), `
public_url = "https://file.example.com"
[http]
addr = ":7000"
[storage.appwrite]
project_id = "file"
`)
	cfg, err := Load(Flags{DataDir: dir, AgentAddr: ":7443"}, envMap(map[string]string{
		"CENTRAL_HTTP_ADDR": ":7001",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":7001" {
		t.Errorf("env should override file: %s", cfg.HTTP.Addr)
	}
	if cfg.Agent.Addr != ":7443" {
		t.Errorf("flag should override: %s", cfg.Agent.Addr)
	}
	if cfg.PublicURL != "https://file.example.com" {
		t.Errorf("file value lost: %s", cfg.PublicURL)
	}
	if cfg.Storage.Appwrite.Endpoint != "https://state.example.com/v1" || cfg.Storage.Appwrite.ProjectID != "file" {
		t.Errorf("state/file merge: %+v", cfg.Storage.Appwrite)
	}
	if cfg.StoragePreconfigured() {
		t.Error("storage from the state file is wizard-managed, not preconfigured")
	}
}

func TestEnvAppwriteImpliesDriverAndSecretFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	write(t, keyFile, "  sk_secret \n")
	cfg, err := Load(Flags{DataDir: dir}, envMap(map[string]string{
		"CENTRAL_APPWRITE_ENDPOINT":     "https://fra.cloud.appwrite.io/v1",
		"CENTRAL_APPWRITE_PROJECT":      "p1",
		"CENTRAL_APPWRITE_API_KEY_FILE": keyFile,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Driver != DriverAppwrite || cfg.Storage.Appwrite.APIKey.Reveal() != "sk_secret" {
		t.Fatalf("storage = %+v", cfg.Storage)
	}
	if !cfg.StoragePreconfigured() {
		t.Fatal("env storage should be preconfigured")
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "central.toml"), "htp_addr = \":1\"\n")
	if _, err := Load(Flags{DataDir: dir}, envMap(nil)); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]map[string]string{
		"bad tls mode":      {"CENTRAL_TLS_MODE": "weird"},
		"files without key": {"CENTRAL_TLS_MODE": "files", "CENTRAL_TLS_CERT_FILE": "/c.pem"},
		"acme no domains":   {"CENTRAL_TLS_MODE": "acme"},
		"bad proxy":         {"CENTRAL_TRUSTED_PROXIES": "10.0.0.0/8,nope"},
		"bad public url":    {"CENTRAL_PUBLIC_URL": "ftp://x"},
		"url with creds":    {"CENTRAL_PUBLIC_URL": "https://u:p@x.example.com"},
		"appwrite no key":   {"CENTRAL_APPWRITE_ENDPOINT": "https://x/v1", "CENTRAL_APPWRITE_PROJECT": "p"},
		"bad log level":     {"CENTRAL_LOG_LEVEL": "loud"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(Flags{DataDir: t.TempDir()}, envMap(env)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestWriteStateNeverContainsPlainKey(t *testing.T) {
	dir := t.TempDir()
	st := StateFile{Storage: StorageConfig{Driver: DriverAppwrite, Appwrite: AppwriteConfig{
		Endpoint: "https://x/v1", ProjectID: "p", APIKey: "plain-secret", APIKeySealed: "cenc1.a.b",
	}}}
	if err := WriteState(dir, st); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "plain-secret") {
		t.Fatal("state file contains the plaintext API key")
	}
	info, _ := os.Stat(filepath.Join(dir, StateFileName))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %o", info.Mode().Perm())
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": "10.0.0.1/32", "10.0.0.0/8": "10.0.0.0/8", "::1": "::1/128"} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Fatalf("ParsePrefix(%q) = %v, %v", in, p, err)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
