// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit records security-relevant actions in a per-organization, hash-chained log.
//
// Every event stores the SHA-256 of the previous event's hash plus its own canonical encoding,
// so deleting or editing an event (even directly in the database) breaks the chain, which
// VerifyChain detects. Events never contain secrets.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/store"
)

// Event is what callers provide; the recorder fills in the chain fields.
type Event struct {
	OrgID         string
	Actor         store.PrincipalRef
	Action        string
	TargetType    string
	TargetID      string
	TargetDisplay string
	Result        string
	SourceIP      string
	UserAgent     string
	Details       map[string]string
}

// Recorder appends events.
type Recorder struct {
	holder *store.Holder
	log    *slog.Logger

	mu   sync.Mutex
	last map[string]chainHead
}

type chainHead struct {
	seq  int64
	hash string
}

// NewRecorder returns a recorder.
func NewRecorder(holder *store.Holder, log *slog.Logger) *Recorder {
	return &Recorder{holder: holder, log: log, last: map[string]chainHead{}}
}

// FromContext fills actor, IP and user agent from the request context.
func FromContext(ctx context.Context, e Event) Event {
	if p := authz.From(ctx); p != nil {
		if e.Actor.ID == "" {
			e.Actor = p.Ref()
		}
		if e.OrgID == "" {
			e.OrgID = p.OrgID
		}
	}
	if e.SourceIP == "" {
		if ip := httpx.ClientIPFrom(ctx); ip.IsValid() {
			e.SourceIP = ip.String()
		}
	}
	if e.UserAgent == "" {
		e.UserAgent = UserAgentFrom(ctx)
	}
	if e.Result == "" {
		e.Result = store.AuditSuccess
	}
	return e
}

type uaKey struct{}

// WithUserAgent stores the request's user agent for audit events.
func WithUserAgent(ctx context.Context, ua string) context.Context {
	if len(ua) > 256 {
		ua = ua[:256]
	}
	return context.WithValue(ctx, uaKey{}, ua)
}

// UserAgentFrom returns the stored user agent.
func UserAgentFrom(ctx context.Context) string {
	s, _ := ctx.Value(uaKey{}).(string)
	return s
}

// Record appends an event built from ctx. Failures are logged and returned: security events
// must not disappear silently.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	e = FromContext(ctx, e)
	if e.OrgID == "" {
		// Events without an organization (e.g. failed logins for unknown users) go to the log only.
		r.log.Info("audit", "action", e.Action, "result", e.Result, "actor", e.Actor.Display, "ip", e.SourceIP)
		return nil
	}
	st := r.holder.Get()
	if st == nil {
		return store.ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	head, err := r.head(ctx, st, e.OrgID)
	if err != nil {
		r.log.Error("audit: cannot read chain head", "org_id", e.OrgID, "error", err)
		return err
	}
	ev := &store.AuditEvent{
		ID: store.NewID(), OrgID: e.OrgID, Seq: head.seq + 1, Time: time.Now().UTC().Truncate(time.Millisecond),
		Actor: e.Actor, Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID,
		TargetDisplay: e.TargetDisplay, Result: e.Result, SourceIP: e.SourceIP, UserAgent: e.UserAgent,
		Details: e.Details, PrevHash: head.hash,
	}
	ev.Hash = Hash(ev)
	if err := st.Audit.Create(ctx, store.Tenant(e.OrgID), ev); err != nil {
		delete(r.last, e.OrgID) // re-read the head next time
		r.log.Error("audit: write failed", "org_id", e.OrgID, "action", e.Action, "error", err)
		return err
	}
	r.last[e.OrgID] = chainHead{seq: ev.Seq, hash: ev.Hash}
	return nil
}

func (r *Recorder) head(ctx context.Context, st *store.Store, orgID string) (chainHead, error) {
	if h, ok := r.last[orgID]; ok {
		return h, nil
	}
	last, err := st.Audit.FindOne(ctx, store.Tenant(orgID), store.Query{}.Order("seq", true))
	if errors.Is(err, store.ErrNotFound) {
		return chainHead{}, nil
	}
	if err != nil {
		return chainHead{}, err
	}
	return chainHead{seq: last.Seq, hash: last.Hash}, nil
}

// canonical is the hashed representation (field order fixed by the struct; maps are sorted
// by encoding/json).
type canonical struct {
	OrgID         string             `json:"org_id"`
	Seq           int64              `json:"seq"`
	Time          string             `json:"time"`
	Actor         store.PrincipalRef `json:"actor"`
	Action        string             `json:"action"`
	TargetType    string             `json:"target_type"`
	TargetID      string             `json:"target_id"`
	TargetDisplay string             `json:"target_display"`
	Result        string             `json:"result"`
	SourceIP      string             `json:"source_ip"`
	UserAgent     string             `json:"user_agent"`
	Details       map[string]string  `json:"details"`
	PrevHash      string             `json:"prev_hash"`
}

// Hash computes an event's chain hash.
func Hash(e *store.AuditEvent) string {
	c := canonical{
		OrgID: e.OrgID, Seq: e.Seq, Time: e.Time.UTC().Format(time.RFC3339Nano), Actor: e.Actor,
		Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID, TargetDisplay: e.TargetDisplay,
		Result: e.Result, SourceIP: e.SourceIP, UserAgent: e.UserAgent, Details: e.Details, PrevHash: e.PrevHash,
	}
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write([]byte("central-audit-v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyResult reports chain integrity.
type VerifyResult struct {
	Intact         bool
	Checked        int
	FirstBrokenSeq int64
}

// VerifyChain recomputes hashes for seq in [from, to] (0 = unbounded).
func VerifyChain(ctx context.Context, st *store.Store, orgID string, from, to int64) (VerifyResult, error) {
	q := store.Query{}.Order("seq", false)
	if from > 0 {
		q = q.And("seq", store.OpGte, from)
	}
	if to > 0 {
		q = q.And("seq", store.OpLte, to)
	}
	q.Limit = store.MaxLimit
	res := VerifyResult{Intact: true}
	var prev *store.AuditEvent
	if from > 1 {
		p, err := st.Audit.FindOne(ctx, store.Tenant(orgID), store.Eq("seq", from-1))
		if err == nil {
			prev = p
		}
	}
	for {
		page, next, err := st.Audit.Find(ctx, store.Tenant(orgID), q)
		if err != nil {
			return res, err
		}
		for _, ev := range page {
			res.Checked++
			ok := Hash(ev) == ev.Hash
			if prev != nil {
				ok = ok && ev.PrevHash == prev.Hash && ev.Seq == prev.Seq+1
			} else if from <= 1 {
				ok = ok && ev.Seq == 1 && ev.PrevHash == ""
			}
			if !ok {
				return VerifyResult{Intact: false, Checked: res.Checked, FirstBrokenSeq: ev.Seq}, nil
			}
			prev = ev
		}
		if next == "" {
			return res, nil
		}
		q.After = next
	}
}

// Describe formats a principal for logs.
func Describe(p store.PrincipalRef) string { return fmt.Sprintf("%s:%s", p.Kind, p.ID) }
