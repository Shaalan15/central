// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package terminal bridges browser terminals (xterm.js over a WebSocket) to agent PTY sessions.
//
// Opening a terminal is a two-step handshake:
//  1. HostService.OpenTerminal (permission terminal.open, fresh step-up, owner policy allows
//     terminals) signs a terminal_open command bound to a new session and returns a
//     single-use ticket, valid for 30 seconds and tied to the caller's browser session.
//  2. The browser connects /ws/terminal?ticket=… from an allowed origin with its session
//     cookie. Central waits for the agent to attach the session, then relays bytes both ways
//     and records the output (asciicast v2) when the organization enables recording.
package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/auth"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/sessions"
	"github.com/Shaalan15/central/server/internal/store"
)

// Limits.
const (
	TicketTTL       = 30 * time.Second
	MaxDuration     = 12 * time.Hour
	IdleTimeout     = 30 * time.Minute
	termType        = "xterm-256color"
	ackEvery        = 64 << 10
	maxInputMessage = 64 << 10
	sendTimeout     = 10 * time.Second
	ticketPurpose   = "terminal_ticket"
)

// ErrNotBrowser is returned when a terminal is requested without a browser session.
var ErrNotBrowser = errors.New("terminal: terminals are only available from a signed-in browser")

// Service opens and bridges terminals.
type Service struct {
	Holder   *store.Holder
	Fleet    *fleet.Index
	Dispatch *dispatch.Dispatcher
	Sessions *sessions.Manager
	Auth     *auth.Sessions
	Cookies  httpx.Cookies
	// CookieName is the session cookie's base name.
	CookieName string
	Audit      *audit.Recorder
	Log        *slog.Logger
	// AllowedOrigins lists the origins (scheme://host[:port]) browsers may connect from.
	AllowedOrigins func() []string

	mu      sync.Mutex
	tickets map[string]*ticket
}

type ticket struct {
	pending        *sessions.Pending
	commandID      string
	browserSession string
	userID         string
	userDisplay    string
	orgID          string
	agentID        string
	agentName      string
	runAs          string
	cols, rows     uint32
	record         bool
	expires        time.Time
}

// OpenRequest describes a terminal to open.
type OpenRequest struct {
	Principal *authz.Principal
	Agent     fleet.View
	RunAs     string
	Cols      uint32
	Rows      uint32
	SourceIP  string
}

// OpenResult is returned to the browser.
type OpenResult struct {
	SessionID string
	Ticket    string
	Recorded  bool
}

func clampSize(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return min(v, 1000)
}

// Open authorizes a terminal: it signs the terminal_open command and issues a ticket. The
// caller must already have checked terminal.open (with step-up) on the agent.
func (s *Service) Open(ctx context.Context, req OpenRequest) (OpenResult, error) {
	p := req.Principal
	if p == nil || p.Session == nil || p.Kind != store.PrincipalUser {
		return OpenResult{}, ErrNotBrowser
	}
	st := s.Holder.Get()
	if st == nil {
		return OpenResult{}, store.ErrUnavailable
	}
	record := true
	if org, err := st.Orgs.Get(ctx, store.System(), p.OrgID); err == nil {
		record = org.Settings.RecordTerminalSessions
	}
	cols, rows := clampSize(req.Cols, 80), clampSize(req.Rows, 24)
	pending := s.Sessions.Create(p.OrgID, req.Agent.Agent.ID, sessions.Terminal)
	commandID := store.NewID()
	s.Sessions.SetCommand(pending, commandID)
	op := &agentv1.Operation{Kind: &agentv1.Operation_TerminalOpen{TerminalOpen: &agentv1.TerminalOpen{
		RunAs: req.RunAs, Cols: cols, Rows: rows, Term: termType, IdleTimeout: durationpb.New(IdleTimeout),
	}}}
	if _, err := s.Dispatch.Submit(ctx, dispatch.Request{
		OrgID: p.OrgID, AgentID: req.Agent.Agent.ID, Operation: op, TTL: sessions.AttachWindow, Issuer: p.Ref(),
		SourceIP: req.SourceIP, Session: pending.Binding(), CommandID: commandID,
	}); err != nil {
		s.Sessions.Cancel(pending.ID)
		return OpenResult{}, err
	}
	raw := crypto.RandomToken(32)
	s.mu.Lock()
	if s.tickets == nil {
		s.tickets = map[string]*ticket{}
	}
	now := time.Now()
	for k, t := range s.tickets {
		if now.After(t.expires) {
			delete(s.tickets, k)
		}
	}
	s.tickets[crypto.HashToken(ticketPurpose, raw)] = &ticket{
		pending: pending, commandID: commandID, browserSession: p.Session.ID, userID: p.ID, userDisplay: p.Display,
		orgID: p.OrgID, agentID: req.Agent.Agent.ID, agentName: req.Agent.Agent.Name, runAs: req.RunAs,
		cols: cols, rows: rows, record: record, expires: now.Add(TicketTTL),
	}
	s.mu.Unlock()
	return OpenResult{SessionID: pending.ID, Ticket: raw, Recorded: record}, nil
}

// take consumes a ticket (single use).
func (s *Service) take(raw string) *ticket {
	if len(raw) != 43 {
		return nil
	}
	key := crypto.HashToken(ticketPurpose, raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tickets[key]
	delete(s.tickets, key)
	if t == nil || time.Now().After(t.expires) {
		return nil
	}
	return t
}

func (s *Service) originPatterns() []string {
	var out []string
	if s.AllowedOrigins == nil {
		return nil
	}
	for _, o := range s.AllowedOrigins() {
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			out = append(out, u.Host)
		}
	}
	return out
}

type statusMessage struct {
	Type     string `json:"type"`
	State    string `json:"state"`
	Message  string `json:"message,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Recorded bool   `json:"recorded,omitempty"`
}

type controlMessage struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

func sendStatus(ctx context.Context, c *websocket.Conn, m statusMessage) {
	m.Type = "status"
	data, _ := json.Marshal(m)
	wctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_ = c.Write(wctx, websocket.MessageText, data)
}

// ServeWS handles /ws/terminal.
func (s *Service) ServeWS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := s.take(r.URL.Query().Get("ticket"))
	if t == nil {
		http.Error(w, "invalid or expired terminal ticket", http.StatusUnauthorized)
		return
	}
	// The ticket only works together with the browser session it was issued to.
	sess, err := s.Auth.Lookup(ctx, s.Cookies.Read(ctx, r.Header, s.CookieName))
	if err != nil || sess.ID != t.browserSession || sess.Stage != store.SessionStageFull {
		s.Sessions.Cancel(t.pending.ID)
		http.Error(w, "session mismatch", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.originPatterns()})
	if err != nil {
		s.Sessions.Cancel(t.pending.ID)
		return // Accept already wrote the error response
	}
	defer func() { _ = conn.CloseNow() }()
	s.Log.Debug("terminal: websocket accepted", "ctx_err", ctx.Err())
	conn.SetReadLimit(maxInputMessage)
	sendStatus(ctx, conn, statusMessage{State: "connecting", Recorded: t.record})

	pipe, errMsg := s.waitForAgent(ctx, t)
	s.Log.Debug("terminal: agent wait finished", "session", t.pending.ID, "attached", pipe != nil, "error", errMsg)
	if pipe == nil {
		sendStatus(ctx, conn, statusMessage{State: "error", Message: errMsg})
		_ = conn.Close(websocket.StatusPolicyViolation, "terminal unavailable")
		return
	}
	defer pipe.Close()

	started := time.Now().UTC()
	var rec *Recorder
	if t.record {
		rec, err = StartRecording(ctx, s.Holder, store.Recording{
			ID: t.pending.ID, OrgID: t.orgID, AgentID: t.agentID, AgentName: t.agentName, UserID: t.userID,
			UserDisplay: t.userDisplay, CommandID: t.commandID, RunAs: t.runAs, Cols: int(t.cols), Rows: int(t.rows),
			StartedAt: started,
		}, termType)
		if err != nil {
			// Recording is mandatory when enabled: do not run an unrecorded session.
			s.Log.Error("terminal: cannot start recording", "session", t.pending.ID, "error", err)
			_ = pipe.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Close{Close: &agentv1.SessionClose{}}}, sendTimeout)
			sendStatus(ctx, conn, statusMessage{State: "error", Message: "the session could not be recorded"})
			return
		}
	}
	sendStatus(ctx, conn, statusMessage{State: "connected", Recorded: t.record})
	exitCode, outBytes := s.bridge(ctx, conn, pipe, rec)
	s.Log.Debug("terminal: session ended", "session", t.pending.ID, "exit_code", exitCode, "output_bytes", outBytes)
	if rec != nil {
		if err := rec.Finish(ctx, exitCode); err != nil {
			s.Log.Error("terminal: finishing recording failed", "session", t.pending.ID, "error", err)
		}
	}
	_ = s.Audit.Record(context.WithoutCancel(ctx), audit.Event{
		OrgID: t.orgID, Actor: store.PrincipalRef{Kind: store.PrincipalUser, ID: t.userID, Display: t.userDisplay},
		Action: "terminal.closed", TargetType: "agent", TargetID: t.agentID, TargetDisplay: t.agentName,
		Details: map[string]string{
			"session_id": t.pending.ID, "run_as": t.runAs, "exit_code": strconv.Itoa(exitCode),
			"duration_sec": strconv.Itoa(int(time.Since(started).Seconds())), "output_bytes": strconv.FormatInt(outBytes, 10),
		},
	})
	_ = conn.Close(websocket.StatusNormalClosure, "terminal closed")
}

// waitForAgent waits until the agent attaches the session or the command fails.
func (s *Service) waitForAgent(ctx context.Context, t *ticket) (*sessions.Pipe, string) {
	_, _, sub, err := s.Dispatch.Watch(ctx, t.orgID, t.commandID, 0)
	if err != nil {
		s.Sessions.Cancel(t.pending.ID)
		return nil, "the terminal command was not found"
	}
	defer sub.Close()
	timer := time.NewTimer(time.Until(t.pending.Expires))
	defer timer.Stop()
	for {
		select {
		case pipe := <-t.pending.Attached():
			return pipe, ""
		case msg, ok := <-sub.C:
			if !ok {
				continue
			}
			if ev, ok := msg.(dispatch.Event); ok && ev.Record.Terminal() {
				s.Sessions.Cancel(t.pending.ID)
				reason := ev.Record.ErrorMessage
				if reason == "" {
					reason = "the agent refused to open the terminal (" + ev.Record.State + ")"
				}
				return nil, reason
			}
		case <-timer.C:
			s.Sessions.Cancel(t.pending.ID)
			return nil, "the agent did not open the terminal in time (is it online?)"
		case <-ctx.Done():
			s.Sessions.Cancel(t.pending.ID)
			return nil, "cancelled"
		}
	}
}

// bridge relays bytes until either side closes. It returns the exit code and output size.
func (s *Service) bridge(ctx context.Context, conn *websocket.Conn, pipe *sessions.Pipe, rec *Recorder) (int, int64) {
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	exitCode := -1
	var total int64
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		defer cancel()
		unacked := 0
		for {
			f := pipe.Next(ctx)
			if f == nil {
				s.Log.Debug("terminal: agent side closed")
				return
			}
			switch {
			case f.GetClose() != nil:
				exitCode = int(f.GetClose().GetExitCode())
				msg := f.GetClose().GetError().GetMessage()
				sendStatus(ctx, conn, statusMessage{State: "closed", ExitCode: &exitCode, Message: msg})
				return
			case len(f.GetData()) > 0:
				data := f.GetData()
				if rec != nil {
					rec.Output(ctx, data)
				}
				total += int64(len(data))
				wctx, wcancel := context.WithTimeout(ctx, sendTimeout)
				err := conn.Write(wctx, websocket.MessageBinary, data)
				wcancel()
				if err != nil {
					s.Log.Debug("terminal: browser write failed", "error", err)
					return
				}
				if unacked += len(data); unacked >= ackEvery {
					_ = pipe.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_AckBytes{AckBytes: uint64(unacked)}}, sendTimeout)
					unacked = 0
				}
			}
		}
	}()

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			s.Log.Debug("terminal: browser read ended", "error", err)
			break
		}
		if typ == websocket.MessageBinary {
			for len(data) > 0 {
				n := min(len(data), 32<<10)
				if pipe.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Data{Data: data[:n]}}, sendTimeout) != nil {
					break
				}
				data = data[n:]
			}
			continue
		}
		var m controlMessage
		if json.Unmarshal(data, &m) == nil && m.Type == "resize" && m.Cols > 0 && m.Rows > 0 && m.Cols <= 1000 && m.Rows <= 1000 {
			_ = pipe.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Resize{Resize: &agentv1.SessionResize{Cols: m.Cols, Rows: m.Rows}}}, sendTimeout)
			if rec != nil {
				rec.Resize(ctx, m.Cols, m.Rows)
			}
		}
	}
	// The browser went away (or the agent ended the session): tell the agent to close.
	_ = pipe.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Close{Close: &agentv1.SessionClose{}}}, time.Second)
	pipe.Close()
	<-agentDone
	return exitCode, total
}
