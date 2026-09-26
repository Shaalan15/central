// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package setup implements the first-run wizard.
//
// Until setup completes, Central prints a one-time setup token to its log and writes it to
// <data dir>/setup-token (0600). Every wizard step except the status probe requires a setup
// session obtained by presenting that token, so the first visitor on the network cannot take
// over a fresh install. Once the owner account exists the token file is deleted, the wizard
// closes permanently, and all SetupService RPCs fail with FAILED_PRECONDITION.
package setup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Setting keys written by the wizard.
const (
	SettingSetupComplete = "setup_complete"
	SettingPublicURL     = "public_url"
	SettingAgentURL      = "agent_url"
)

// TokenFileName is the setup token file inside the data directory.
const TokenFileName = "setup-token"

// setupSessionTTL bounds how long a wizard session stays valid.
const setupSessionTTL = time.Hour

// State tracks whether setup is complete and manages the setup token and sessions.
type State struct {
	dataDir string
	holder  *store.Holder
	log     *slog.Logger

	complete atomic.Bool

	mu        sync.Mutex
	tokenHash string
	sessions  map[string]time.Time
	now       func() time.Time
}

// NewState creates the setup state.
func NewState(dataDir string, holder *store.Holder, log *slog.Logger) *State {
	return &State{dataDir: dataDir, holder: holder, log: log, sessions: map[string]time.Time{}, now: time.Now}
}

// Init determines whether setup is complete and, if not, issues a setup token.
func (s *State) Init(ctx context.Context) error {
	if st := s.holder.Get(); st != nil {
		v, err := st.GetSetting(ctx, SettingSetupComplete)
		switch {
		case err == nil && v == "true":
			s.complete.Store(true)
			s.removeTokenFile()
			return nil
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("setup: read state: %w", err)
		}
	}
	return s.issueToken()
}

// Complete reports whether setup has finished.
func (s *State) Complete() bool { return s.complete.Load() }

func (s *State) tokenPath() string { return filepath.Join(s.dataDir, TokenFileName) }

func (s *State) issueToken() error {
	// Reuse an existing token file so restarting the server does not invalidate the token an
	// operator already copied; otherwise generate a new one.
	token := ""
	if b, err := os.ReadFile(s.tokenPath()); err == nil {
		token = strings.TrimSpace(string(b))
	}
	if len(token) < 32 {
		token = crypto.RandomToken(24)
		if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
			return fmt.Errorf("setup: %w", err)
		}
		if err := crypto.WriteFileAtomic(s.tokenPath(), []byte(token+"\n"), 0o600); err != nil {
			return fmt.Errorf("setup: write token: %w", err)
		}
	}
	s.mu.Lock()
	s.tokenHash = crypto.HashToken("setup", token)
	s.mu.Unlock()
	// The banner goes to the log on purpose: in containers that is where operators look.
	s.log.Warn("Central is not set up yet. Open the web UI and enter this one-time setup token",
		"setup_token", token, "token_file", s.tokenPath())
	return nil
}

// CheckToken verifies a setup token in constant time.
func (s *State) CheckToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenHash == "" || s.complete.Load() {
		return false
	}
	return crypto.EqualHashes(s.tokenHash, crypto.HashToken("setup", strings.TrimSpace(token)))
}

// NewSession creates a setup session and returns its secret.
func (s *State) NewSession() string {
	secret := crypto.RandomToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[crypto.HashToken("setup-session", secret)] = now.Add(setupSessionTTL)
	return secret
}

// ValidSession reports whether secret is a live setup session.
func (s *State) ValidSession(secret string) bool {
	if secret == "" || s.complete.Load() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[crypto.HashToken("setup-session", secret)]
	return ok && s.now().Before(exp)
}

// MarkComplete finalizes setup: persists the flag, deletes the token and all setup sessions.
func (s *State) MarkComplete(ctx context.Context, st *store.Store) error {
	if err := st.PutSetting(ctx, SettingSetupComplete, "true"); err != nil {
		return err
	}
	s.mu.Lock()
	s.tokenHash = ""
	s.sessions = map[string]time.Time{}
	s.mu.Unlock()
	s.complete.Store(true)
	s.removeTokenFile()
	s.log.Info("setup complete; the setup token has been invalidated")
	return nil
}

func (s *State) removeTokenFile() {
	if err := os.Remove(s.tokenPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("could not remove setup token file", "path", s.tokenPath(), "error", err)
	}
}

// ReadTokenFile returns the current setup token from the data directory (for the
// `central setup-token` command).
func ReadTokenFile(dataDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, TokenFileName)) //nolint:gosec // trusted path
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
