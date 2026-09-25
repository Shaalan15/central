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
	"github.com/Shaalan15/central/server/internal/store/memory"
)

// AppwriteKeyPurpose is the associated data used when sealing the Appwrite API key.
const AppwriteKeyPurpose = "storage.appwrite.api_key"

// ErrNotConfigured is returned when no driver is configured.
var ErrNotConfigured = errors.New("storage: no driver configured")

// AppwriteOpener opens the Appwrite driver. It is registered by the appwrite package's init
// (via RegisterAppwrite) to keep this package free of the SDK dependency in tests.
type AppwriteOpener func(ctx context.Context, cfg config.AppwriteConfig, apiKey crypto.Secret) (store.Driver, error)

// AppwriteTester checks an Appwrite configuration without persisting it.
type AppwriteTester func(ctx context.Context, cfg config.AppwriteConfig, apiKey crypto.Secret) TestResult

var (
	openAppwrite AppwriteOpener
	testAppwrite AppwriteTester
)

// RegisterAppwrite installs the Appwrite driver implementation.
func RegisterAppwrite(open AppwriteOpener, test AppwriteTester) {
	openAppwrite, testAppwrite = open, test
}

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
		if openAppwrite == nil {
			return nil, errors.New("storage: the Appwrite driver is not compiled into this build")
		}
		key, err := AppwriteKey(cfg.Appwrite, kr)
		if err != nil {
			return nil, err
		}
		ad, err := openAppwrite(ctx, cfg.Appwrite, key)
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

// TestAppwrite runs the registered Appwrite connectivity test.
func TestAppwrite(ctx context.Context, cfg config.AppwriteConfig, apiKey crypto.Secret) TestResult {
	if testAppwrite == nil {
		return TestResult{Error: "the Appwrite driver is not compiled into this build"}
	}
	return testAppwrite(ctx, cfg, apiKey)
}
