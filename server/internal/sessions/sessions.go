// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package sessions brokers interactive sessions (terminals, journal follow) between a consumer
// in Central (a browser WebSocket, a streaming RPC) and the agent stream that serves it.
//
// A session is created before the authorizing command is signed: the command carries the
// session ID and a random attach token. The agent then opens AgentService.AttachSession and
// presents both plus the command ID. Central accepts the attach only from the agent the session
// was created for, only once, and only before the session expires.
package sessions

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Kind of session.
type Kind int

// Kinds.
const (
	Terminal Kind = iota + 1
	Journal
)

// Errors.
var (
	ErrUnknown = errors.New("sessions: unknown, expired or already attached session")
	ErrClosed  = errors.New("sessions: session closed")
)

// AttachWindow is how long an agent has to attach after a session is created.
const AttachWindow = 60 * time.Second

// Pending is a session waiting for its agent.
type Pending struct {
	ID        string
	OrgID     string
	AgentID   string
	Kind      Kind
	Token     []byte
	CommandID string
	Expires   time.Time

	attached chan *Pipe
}

// Binding returns the SessionBinding to embed in the signed command.
func (p *Pending) Binding() *agentv1.SessionBinding {
	return &agentv1.SessionBinding{SessionId: p.ID, AttachToken: p.Token}
}

// Attached delivers the agent pipe once the agent attaches.
func (p *Pending) Attached() <-chan *Pipe { return p.attached }

// Manager tracks pending sessions.
type Manager struct {
	mu      sync.Mutex
	pending map[string]*Pending
	now     func() time.Time
}

// NewManager returns a manager.
func NewManager() *Manager { return &Manager{pending: map[string]*Pending{}, now: time.Now} }

// Create registers a new pending session for an agent.
func (m *Manager) Create(orgID, agentID string, kind Kind) *Pending {
	p := &Pending{
		ID: store.NewID(), OrgID: orgID, AgentID: agentID, Kind: kind, Token: crypto.RandomBytes(32),
		Expires: m.now().Add(AttachWindow), attached: make(chan *Pipe, 1),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, old := range m.pending {
		if m.now().After(old.Expires) {
			delete(m.pending, id)
		}
	}
	m.pending[p.ID] = p
	return p
}

// SetCommand records the command that authorizes the session.
func (m *Manager) SetCommand(p *Pending, commandID string) {
	m.mu.Lock()
	p.CommandID = commandID
	m.mu.Unlock()
}

// Cancel forgets a pending session (the consumer gave up).
func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

// Attach validates an agent's attach frame and hands a new pipe to the consumer. Every check
// failure returns ErrUnknown so an agent learns nothing about other sessions.
func (m *Manager) Attach(orgID, agentID string, a *agentv1.SessionAttach) (*Pipe, error) {
	m.mu.Lock()
	p := m.pending[a.GetSessionId()]
	ok := p != nil && p.OrgID == orgID && p.AgentID == agentID && p.CommandID != "" &&
		p.CommandID == a.GetCommandId() && m.now().Before(p.Expires) &&
		subtle.ConstantTimeCompare(p.Token, a.GetAttachToken()) == 1
	if ok {
		delete(m.pending, p.ID) // single use
	}
	m.mu.Unlock()
	if !ok {
		return nil, ErrUnknown
	}
	pipe := newPipe(p.Kind)
	select {
	case p.attached <- pipe:
		return pipe, nil
	default:
		return nil, ErrUnknown
	}
}

// Pipe is the Central side of an attached session. The agent transport feeds FromAgent and
// drains ToAgent; either side may Close.
type Pipe struct {
	Kind      Kind
	fromAgent chan *agentv1.SessionFrame
	toAgent   chan *agentv1.SessionFrame
	done      chan struct{}
	once      sync.Once
}

func newPipe(k Kind) *Pipe {
	return &Pipe{
		Kind: k, fromAgent: make(chan *agentv1.SessionFrame, 64), toAgent: make(chan *agentv1.SessionFrame, 64),
		done: make(chan struct{}),
	}
}

// Done is closed when the session ends.
func (p *Pipe) Done() <-chan struct{} { return p.done }

// Close ends the session (idempotent).
func (p *Pipe) Close() { p.once.Do(func() { close(p.done) }) }

// FromAgent returns frames sent by the agent. Prefer Next, which does not lose frames that
// were delivered just before the session closed.
func (p *Pipe) FromAgent() <-chan *agentv1.SessionFrame { return p.fromAgent }

// Next returns the next frame from the agent, or nil once the session has closed and every
// delivered frame has been consumed (or ctx ended).
func (p *Pipe) Next(ctx context.Context) *agentv1.SessionFrame {
	select {
	case f := <-p.fromAgent:
		return f
	default:
	}
	select {
	case f := <-p.fromAgent:
		return f
	case <-p.done:
		select { // frames delivered before the close still count
		case f := <-p.fromAgent:
			return f
		default:
			return nil
		}
	case <-ctx.Done():
		return nil
	}
}

// Send queues a frame for the agent, waiting at most timeout.
func (p *Pipe) Send(f *agentv1.SessionFrame, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case p.toAgent <- f:
		return nil
	case <-p.done:
		return ErrClosed
	case <-t.C:
		return errors.New("sessions: agent is not reading")
	}
}

// Transport-side accessors (used by the gateway).

// Deliver passes a frame from the agent to the consumer, waiting at most timeout.
func (p *Pipe) Deliver(f *agentv1.SessionFrame, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case p.fromAgent <- f:
		return nil
	case <-p.done:
		return ErrClosed
	case <-t.C:
		return errors.New("sessions: consumer is not reading")
	}
}

// Outgoing returns frames queued for the agent.
func (p *Pipe) Outgoing() <-chan *agentv1.SessionFrame { return p.toAgent }
