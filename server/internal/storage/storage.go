// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package storage opens the configured storage driver. It is the only place that knows about
// concrete drivers; everything else talks to store.Store.
package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/appwrite"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

// AppwriteKeyPurpose is the associated data used when sealing the Appwrite API key.
const AppwriteKeyPurpose = "storage.appwrite.api_key"

// ErrNotConfigured is returned when no driver is configured.
var ErrNotConfigured = errors.New("storage: no driver configured")

// TestResult reports a connectivity test.
type TestResult struct {
	OK               bool
	ServerVersion    string
	VersionSupported bool
	MissingScopes    []string
	DatabaseExists   bool
	Error            string
}

// Open opens and migrates the configured store.
func Open(ctx context.Context, cfg config.StorageConfig, kr *crypto.Keyring) (*store.Store, error) {
	var d store.Driver
	switch cfg.Driver {
	case "":
		return nil, ErrNotConfigured
	case config.DriverMemory:
		if cfg.MemoryPath == "" {
			d = memory.New()
		} else {
			md, err := memory.Open(cfg.MemoryPath)
			if err != nil {
				return nil, err
			}
			d = md
		}
	case config.DriverAppwrite:
		key, err := AppwriteKey(cfg.Appwrite, kr)
		if err != nil {
			return nil, err
		}
		ad, err := appwrite.Open(cfg.Appwrite, key)
		if err != nil {
			return nil, err
		}
		d = ad
	default:
		return nil, fmt.Errorf("storage: unknown driver %q", cfg.Driver)
	}
	s := store.Open(d)
	mctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.Migrate(mctx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("storage: migrate: %w", err)
	}
	return s, nil
}

// AppwriteKey returns the plaintext API key from config (inline or sealed).
func AppwriteKey(cfg config.AppwriteConfig, kr *crypto.Keyring) (crypto.Secret, error) {
	if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	if cfg.APIKeySealed == "" {
		return "", errors.New("storage: no Appwrite API key configured")
	}
	key, err := kr.OpenString(cfg.APIKeySealed, AppwriteKeyPurpose)
	if err != nil {
		return "", fmt.Errorf("storage: cannot decrypt the Appwrite API key (wrong master key?): %w", err)
	}
	return crypto.Secret(key), nil
}

// TestAppwrite checks an Appwrite configuration without persisting or creating anything.
func TestAppwrite(ctx context.Context, cfg config.AppwriteConfig, apiKey crypto.Secret) TestResult {
	r := appwrite.Check(ctx, cfg, apiKey)
	return TestResult{
		OK: r.OK, ServerVersion: r.ServerVersion, VersionSupported: r.VersionSupported,
		MissingScopes: r.MissingScopes, DatabaseExists: r.DatabaseExists, Error: r.Error,
	}
}
