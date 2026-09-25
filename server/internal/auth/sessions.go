// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Session token properties. The raw token only exists in the browser cookie; the store keeps a
// SHA-256 hash (first 32 hex chars as row ID, full hash compared in constant time).
const (
	sessionTokenBytes = 32
	sessionPurpose    = "session"
	// partialSessionTTL bounds sessions that have not completed MFA.
	partialSessionTTL = 10 * time.Minute
	// touchInterval limits how often last-seen/idle-expiry updates are written.
	touchInterval = time.Minute
	cacheTTL      = 30 * time.Second
)

// ErrNoSession is returned when a token does not map to a live session.
var ErrNoSession = errors.New("auth: no valid session")

// Sessions manages browser sessions.
type Sessions struct {
	holder *store.Holder
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]cachedSession
}

type cachedSession struct {
	s       *store.Session
	fetched time.Time
}

// NewSessions returns a session manager.
func NewSessions(holder *store.Holder) *Sessions {
	return &Sessions{holder: holder, now: time.Now, cache: map[string]cachedSession{}}
}

// SessionTimeouts are the lifetimes applied to a new session.
type SessionTimeouts struct {
	Idle, Max time.Duration
}

// TimeoutsFor derives timeouts from org settings (with safe bounds).
func TimeoutsFor(s store.OrgSettings) SessionTimeouts {
	idle := clampDur(time.Duration(s.SessionIdleTimeoutSec)*time.Second, 5*time.Minute, 8*time.Hour, 30*time.Minute)
	maxLife := clampDur(time.Duration(s.SessionMaxLifetimeSec)*time.Second, time.Hour, 7*24*time.Hour, 12*time.Hour)
	return SessionTimeouts{Idle: idle, Max: maxLife}
}

func clampDur(v, lo, hi, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return min(max(v, lo), hi)
}

func sessionID(hash string) string { return hash[:32] }

// Create starts a session and returns the raw token for the cookie.
func (m *Sessions) Create(ctx context.Context, userID, orgID, stage, ip, userAgent string, t SessionTimeouts) (string, *store.Session, error) {
	st := m.holder.Get()
	if st == nil {
		return "", nil, store.ErrUnavailable
	}
	token := crypto.RandomToken(sessionTokenBytes)
	hash := crypto.HashToken(sessionPurpose, token)
	now := m.now().UTC()
	s := &store.Session{
		ID: sessionID(hash), TokenHash: hash, UserID: userID, ActiveOrgID: orgID, Stage: stage,
		CSRFToken: crypto.RandomToken(32), CreatedAt: now, LastSeenAt: now,
		IP: ip, UserAgent: truncate(userAgent, 256),
	}
	if stage == store.SessionStageFull {
		s.ExpiresAt = now.Add(t.Max)
		s.IdleExpiresAt = now.Add(t.Idle)
	} else {
		s.ExpiresAt = now.Add(partialSessionTTL)
		s.IdleExpiresAt = s.ExpiresAt
	}
	if err := st.Sessions.Create(ctx, store.System(), s); err != nil {
		return "", nil, err
	}
	return token, s, nil
}

// Lookup resolves a raw token to a live session, extending its idle expiry.
func (m *Sessions) Lookup(ctx context.Context, token string) (*store.Session, error) {
	if len(token) < 40 || len(token) > 64 {
		return nil, ErrNoSession
	}
	st := m.holder.Get()
	if st == nil {
		return nil, ErrNoSession
	}
	hash := crypto.HashToken(sessionPurpose, token)
	now := m.now().UTC()

	m.mu.Lock()
	c, ok := m.cache[hash]
	m.mu.Unlock()
	var s *store.Session
	if ok && now.Sub(c.fetched) < cacheTTL {
		s = c.s
	} else {
		fetched, err := st.Sessions.Get(ctx, store.System(), sessionID(hash))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrNoSession
			}
			return nil, err
		}
		s = fetched
	}
	if !crypto.EqualHashes(s.TokenHash, hash) {
		return nil, ErrNoSession
	}
	if now.After(s.ExpiresAt) || now.After(s.IdleExpiresAt) {
		m.forget(hash)
		_ = st.Sessions.Delete(ctx, store.System(), s.ID)
		return nil, ErrNoSession
	}
	if s.Stage == store.SessionStageFull && now.Sub(s.LastSeenAt) > touchInterval {
		idle := s.IdleExpiresAt.Sub(s.LastSeenAt)
		cp := *s
		cp.LastSeenAt = now
		cp.IdleExpiresAt = minTime(now.Add(idle), cp.ExpiresAt)
		if err := st.Sessions.Update(ctx, store.System(), &cp); err == nil {
			s = &cp
		}
	}
	m.mu.Lock()
	m.cache[hash] = cachedSession{s: s, fetched: now}
	if len(m.cache) > 50_000 {
		m.cache = map[string]cachedSession{}
	}
	m.mu.Unlock()
	cp := *s
	return &cp, nil
}

// Update persists changes to a session (stage, step-up, pending ceremonies).
func (m *Sessions) Update(ctx context.Context, s *store.Session) error {
	st := m.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	if err := st.Sessions.Update(ctx, store.System(), s); err != nil {
		return err
	}
	m.forget(s.TokenHash)
	return nil
}

// Rotate replaces a session with a fresh token (after a privilege change such as completing
// MFA), preventing session fixation. The old token stops working immediately.
func (m *Sessions) Rotate(ctx context.Context, old *store.Session, stage string, t SessionTimeouts) (string, *store.Session, error) {
	token, s, err := m.Create(ctx, old.UserID, old.ActiveOrgID, stage, old.IP, old.UserAgent, t)
	if err != nil {
		return "", nil, err
	}
	if stage == store.SessionStageFull {
		s.StepUpAt = m.now().UTC() // completing MFA counts as a fresh re-authentication
		if err := m.Update(ctx, s); err != nil {
			return "", nil, err
		}
	}
	_ = m.Revoke(ctx, old)
	return token, s, nil
}

// Revoke ends a session.
func (m *Sessions) Revoke(ctx context.Context, s *store.Session) error {
	m.forget(s.TokenHash)
	st := m.holder.Get()
	if st == nil {
		return nil
	}
	err := st.Sessions.Delete(ctx, store.System(), s.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// RevokeUser ends every session of a user except exceptID (use "" for all).
func (m *Sessions) RevokeUser(ctx context.Context, userID, exceptID string) error {
	st := m.holder.Get()
	if st == nil {
		return nil
	}
	sessions, err := st.Sessions.All(ctx, store.System(), store.Eq("user_id", userID))
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.ID == exceptID {
			continue
		}
		if err := m.Revoke(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// List returns a user's live sessions.
func (m *Sessions) List(ctx context.Context, userID string) ([]*store.Session, error) {
	st := m.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	all, err := st.Sessions.All(ctx, store.System(), store.Eq("user_id", userID))
	if err != nil {
		return nil, err
	}
	now := m.now()
	out := all[:0]
	for _, s := range all {
		if now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt) {
			out = append(out, s)
		}
	}
	return out, nil
}

// DeleteExpired removes expired sessions (run periodically).
func (m *Sessions) DeleteExpired(ctx context.Context) (int, error) {
	st := m.holder.Get()
	if st == nil {
		return 0, nil
	}
	return st.Sessions.DeleteWhere(ctx, store.System(), store.Where("expires_at", store.OpLt, store.Millis(m.now())))
}

func (m *Sessions) forget(hash string) {
	m.mu.Lock()
	delete(m.cache, hash)
	m.mu.Unlock()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
