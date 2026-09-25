// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package dispatch sends signed commands to agents and tracks them to completion.
//
// Every command is serialized once, signed with Central's Ed25519 command key and sent as the
// exact signed bytes; the agent's privileged helper verifies the signature, target, expiry and
// replay cache before executing anything. Commands for offline agents wait in a per-agent queue
// until their TTL expires. Delivery is at most once: a command whose outcome is unknown after a
// reconnect is reported as lost rather than executed twice.
//
// Operations are stored redacted (no passwords, file contents or stdin), and the signed bytes
// of queued commands live only in memory.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/ops"
	"github.com/Shaalan15/central/server/internal/store"
)

// Errors returned by Submit and Cancel.
var (
	ErrNotFound     = errors.New("dispatch: agent or command not found")
	ErrRevoked      = errors.New("dispatch: the agent is revoked")
	ErrPolicyDenied = errors.New("dispatch: the host's owner policy does not allow this operation")
	ErrPaused       = errors.New("dispatch: the host's owner has paused remote operations")
	ErrQuota        = errors.New("dispatch: too many pending commands")
	ErrFinished     = errors.New("dispatch: the command has already finished")
)

// Limits.
const (
	DefaultTTL       = 10 * time.Minute
	MinTTL           = 10 * time.Second
	MaxTTL           = 24 * time.Hour
	maxQueuedAgent   = 100
	maxTrackedOrg    = 10_000
	maxChunkBytes    = 64 << 10
	maxOutputMemory  = 256 << 10
	maxOutputTail    = 32 << 10
	maxResultBytes   = 4 << 20
	maxStatusRunes   = 256
	maxErrorRunes    = 1024
	persistEvery     = 5 * time.Second
	lostGrace        = time.Minute
	keepFinished     = 10 * time.Minute
	unacknowledgedBy = time.Minute
	offlineGiveUp    = time.Hour
)

// Signer signs serialized commands.
type Signer interface {
	SignCommand(command []byte) (signature []byte, keyID string)
}

// Request is a command to send.
type Request struct {
	OrgID, AgentID, JobID string
	Operation             *agentv1.Operation
	TTL                   time.Duration
	Issuer                store.PrincipalRef
	SourceIP              string
	Session               *agentv1.SessionBinding
	// CommandID pre-assigns the command ID (sessions need it before the command is sent).
	CommandID string
}

// Event is published on bus.CommandTopic(id) whenever a command changes.
type Event struct {
	Record store.Command
	Output []*agentv1.OutputChunk
}

type tracked struct {
	rec        store.Command
	signed     *agentv1.SignedCommand // kept until the agent acknowledges it
	resent     bool
	cancel     bool
	output     []*agentv1.OutputChunk
	outBytes   int
	done       chan struct{}
	doneAt     time.Time
	persisted  time.Time
	lastUpdate time.Time
}

// Dispatcher tracks commands.
type Dispatcher struct {
	holder *store.Holder
	signer Signer
	fleet  *fleet.Index
	bus    bus.Bus
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	cmds   map[string]*tracked
	queues map[string][]string
}

// New returns a dispatcher.
func New(holder *store.Holder, signer Signer, fl *fleet.Index, b bus.Bus, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		holder: holder, signer: signer, fleet: fl, bus: b, log: log, now: time.Now,
		cmds: map[string]*tracked{}, queues: map[string][]string{},
	}
}

func (d *Dispatcher) st() (*store.Store, error) {
	st := d.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	return st, nil
}

// Submit validates, signs, records and sends (or queues) a command.
func (d *Dispatcher) Submit(ctx context.Context, req Request) (store.Command, error) {
	info, err := ops.Describe(req.Operation)
	if err != nil {
		return store.Command{}, err
	}
	if err := ops.Validate(req.Operation); err != nil {
		return store.Command{}, err
	}
	v, ok := d.fleet.GetInOrg(req.OrgID, req.AgentID)
	if !ok {
		return store.Command{}, ErrNotFound
	}
	if !v.Active() {
		return store.Command{}, ErrRevoked
	}
	if !v.Allows(info.Capability) {
		return store.Command{}, ErrPolicyDenied
	}
	if v.Paused() {
		return store.Command{}, ErrPaused
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	ttl = min(max(ttl, MinTTL), MaxTTL)
	st, err := d.st()
	if err != nil {
		return store.Command{}, err
	}

	now := d.now().UTC()
	id := req.CommandID
	if id == "" {
		id = store.NewID()
	} else if !store.ValidID(id) {
		return store.Command{}, errors.New("dispatch: invalid command ID")
	}
	cmd := &agentv1.Command{
		CommandId: id, AgentId: req.AgentID, OrgId: req.OrgID,
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(ttl)),
		Issuer: &agentv1.Issuer{PrincipalId: req.Issuer.ID, Display: req.Issuer.Display, SourceIp: req.SourceIP},
		JobId:  req.JobID, Operation: req.Operation, Session: req.Session,
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(cmd)
	if err != nil {
		return store.Command{}, err
	}
	sig, keyID := d.signer.SignCommand(raw)
	redacted, err := proto.Marshal(ops.Redact(req.Operation))
	if err != nil {
		return store.Command{}, err
	}
	t := &tracked{
		rec: store.Command{
			ID: id, OrgID: req.OrgID, AgentID: req.AgentID, JobID: req.JobID, OperationType: info.Type,
			OperationProto: redacted, State: store.CommandQueued, ProgressPercent: -1, Issuer: req.Issuer,
			SourceIP: req.SourceIP, CreatedAt: now, ExpiresAt: now.Add(ttl),
		},
		signed: &agentv1.SignedCommand{Command: raw, Signature: sig, KeyId: keyID},
		done:   make(chan struct{}),
	}

	d.mu.Lock()
	if len(d.queues[req.AgentID]) >= maxQueuedAgent || d.countOrg(req.OrgID) >= maxTrackedOrg {
		d.mu.Unlock()
		return store.Command{}, ErrQuota
	}
	d.mu.Unlock()

	if err := st.Commands.Create(ctx, store.Tenant(req.OrgID), &t.rec); err != nil {
		return store.Command{}, err
	}
	d.mu.Lock()
	d.cmds[id] = t
	t.persisted = now
	d.queues[req.AgentID] = append(d.queues[req.AgentID], id)
	d.mu.Unlock()

	d.deliver(ctx, req.AgentID)
	return d.snapshot(id), nil
}

func (d *Dispatcher) countOrg(orgID string) int {
	n := 0
	for _, t := range d.cmds {
		if t.rec.OrgID == orgID && !t.rec.Terminal() {
			n++
		}
	}
	return n
}

func (d *Dispatcher) snapshot(id string) store.Command {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t := d.cmds[id]; t != nil {
		return t.rec
	}
	return store.Command{}
}

// deliver sends an agent's queued commands if it is online.
func (d *Dispatcher) deliver(ctx context.Context, agentID string) {
	conn := d.fleet.Conn(agentID)
	if conn == nil {
		return
	}
	d.mu.Lock()
	ids := d.queues[agentID]
	var remaining []string
	var sent []*tracked
	for _, id := range ids {
		t := d.cmds[id]
		if t == nil || t.rec.State != store.CommandQueued {
			continue
		}
		if err := conn.Send(&agentv1.CentralMessage{Message: &agentv1.CentralMessage_Command{Command: t.signed}}); err != nil {
			remaining = append(remaining, id)
			continue
		}
		t.rec.State = store.CommandSent
		t.lastUpdate = d.now()
		sent = append(sent, t)
	}
	if len(remaining) == 0 {
		delete(d.queues, agentID)
	} else {
		d.queues[agentID] = remaining
	}
	d.mu.Unlock()
	for _, t := range sent {
		d.persistAndPublish(ctx, t, nil, true)
	}
}

func (d *Dispatcher) persistAndPublish(ctx context.Context, t *tracked, output []*agentv1.OutputChunk, force bool) {
	d.mu.Lock()
	rec := t.rec
	doPersist := force || rec.Terminal() || d.now().Sub(t.persisted) >= persistEvery
	if doPersist {
		t.persisted = d.now()
	}
	d.mu.Unlock()
	if doPersist {
		if st := d.holder.Get(); st != nil {
			if err := st.Commands.Update(context.WithoutCancel(ctx), store.Tenant(rec.OrgID), &rec); err != nil {
				d.log.Warn("dispatch: persisting command failed", "command", rec.ID, "error", err)
			}
		}
	}
	if d.bus != nil {
		d.bus.Publish(bus.CommandTopic(rec.ID), Event{Record: rec, Output: output})
	}
}

// finish moves a command to a terminal state (caller holds d.mu).
func (d *Dispatcher) finishLocked(t *tracked, state, code, msg string) {
	t.rec.State = state
	if code != "" {
		t.rec.ErrorCode, t.rec.ErrorMessage = code, msg
	}
	if t.rec.FinishedAt.IsZero() {
		t.rec.FinishedAt = d.now().UTC()
	}
	t.rec.OutputTail = tail(t.output, maxOutputTail)
	t.signed = nil
	t.doneAt = d.now()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func tail(chunks []*agentv1.OutputChunk, n int) []byte {
	var out []byte
	for i := len(chunks) - 1; i >= 0 && len(out) < n; i-- {
		out = append(append([]byte(nil), chunks[i].GetData()...), out...)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

var stateNames = map[agentv1.CommandState]string{
	agentv1.CommandState_COMMAND_STATE_ACCEPTED:  store.CommandAccepted,
	agentv1.CommandState_COMMAND_STATE_RUNNING:   store.CommandRunning,
	agentv1.CommandState_COMMAND_STATE_SUCCEEDED: store.CommandSucceeded,
	agentv1.CommandState_COMMAND_STATE_FAILED:    store.CommandFailed,
	agentv1.CommandState_COMMAND_STATE_REJECTED:  store.CommandRejected,
	agentv1.CommandState_COMMAND_STATE_CANCELLED: store.CommandCancelled,
	agentv1.CommandState_COMMAND_STATE_TIMED_OUT: store.CommandTimedOut,
}

func rank(state string) int {
	switch state {
	case store.CommandQueued:
		return 0
	case store.CommandSent:
		return 1
	case store.CommandAccepted:
		return 2
	case store.CommandRunning:
		return 3
	}
	return 4
}

func sanitize(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes]) + "…"
	}
	return s
}

// ErrorCodeName converts an agent error code to its stored name ("policy_denied", ...).
func ErrorCodeName(c agentv1.ErrorCode) string {
	if c == agentv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return ""
	}
	name, ok := agentv1.ErrorCode_name[int32(c)]
	if !ok {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(name, "ERROR_CODE_"))
}

// HandleUpdate applies a CommandUpdate reported by an agent on its authenticated stream.
func (d *Dispatcher) HandleUpdate(ctx context.Context, orgID, agentID string, u *agentv1.CommandUpdate) {
	id := u.GetCommandId()
	t := d.lookup(ctx, orgID, id)
	if t == nil {
		d.log.Debug("dispatch: update for unknown command", "agent", agentID, "command", id)
		return
	}
	d.mu.Lock()
	if t.rec.AgentID != agentID || t.rec.OrgID != orgID {
		d.mu.Unlock()
		d.log.Warn("dispatch: agent reported on a command addressed to another agent", "agent", agentID, "command", id)
		return
	}
	if t.rec.Terminal() {
		d.mu.Unlock()
		return
	}
	newState, known := stateNames[u.GetState()]
	if newState == store.CommandRejected && t.resent && u.GetError().GetCode() == agentv1.ErrorCode_ERROR_CODE_REPLAYED {
		// We re-sent a command the agent had already received: its original result still counts.
		d.mu.Unlock()
		return
	}
	now := d.now().UTC()
	t.lastUpdate = now
	stateChanged := false
	// Updates can arrive out of order; a stale one only contributes output.
	stale := known && rank(newState) < rank(t.rec.State)
	if known && !stale && newState != t.rec.State {
		t.rec.State = newState
		stateChanged = true
		if rank(newState) >= rank(store.CommandAccepted) {
			t.signed = nil
		}
	}
	if p := u.GetProgressPercent(); !stale && p >= -1 && p <= 100 {
		t.rec.ProgressPercent = int(p)
	}
	if s := u.GetStatus(); !stale && s != "" {
		t.rec.Status = sanitize(s, maxStatusRunes)
	}
	if u.GetOutputTruncated() {
		t.rec.OutputTruncated = true
	}
	if ts := u.GetStartedAt(); ts != nil && t.rec.StartedAt.IsZero() {
		t.rec.StartedAt = ts.AsTime().UTC()
	} else if t.rec.StartedAt.IsZero() && newState == store.CommandRunning {
		t.rec.StartedAt = now
	}
	if ts := u.GetFinishedAt(); ts != nil {
		t.rec.FinishedAt = ts.AsTime().UTC()
	}
	var fresh []*agentv1.OutputChunk
	for _, c := range u.GetOutput() {
		if len(c.GetData()) == 0 || len(c.GetData()) > maxChunkBytes {
			continue
		}
		fresh = append(fresh, c)
		t.output = append(t.output, c)
		t.outBytes += len(c.GetData())
		for t.outBytes > maxOutputMemory && len(t.output) > 1 {
			t.outBytes -= len(t.output[0].GetData())
			t.output = t.output[1:]
			t.rec.OutputTruncated = true
		}
	}
	if r := u.GetResult(); r != nil {
		if data, err := proto.Marshal(r); err == nil && len(data) <= maxResultBytes {
			t.rec.ResultProto = data
		}
	}
	if e := u.GetError(); e != nil {
		t.rec.ErrorCode, t.rec.ErrorMessage = ErrorCodeName(e.GetCode()), sanitize(e.GetMessage(), maxErrorRunes)
	}
	if t.rec.Terminal() {
		d.finishLocked(t, t.rec.State, "", "")
	}
	d.mu.Unlock()
	d.persistAndPublish(ctx, t, fresh, stateChanged)
}

// lookup returns a tracked command, loading non-terminal ones from storage (after a restart).
func (d *Dispatcher) lookup(ctx context.Context, orgID, id string) *tracked {
	if !store.ValidID(id) {
		return nil
	}
	d.mu.Lock()
	t := d.cmds[id]
	d.mu.Unlock()
	if t != nil {
		return t
	}
	st := d.holder.Get()
	if st == nil {
		return nil
	}
	rec, err := st.Commands.Get(ctx, store.Tenant(orgID), id)
	if err != nil {
		return nil
	}
	t = &tracked{rec: *rec, done: make(chan struct{}), persisted: d.now()}
	if rec.Terminal() {
		close(t.done)
		t.doneAt = d.now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing := d.cmds[id]; existing != nil {
		return existing
	}
	d.cmds[id] = t
	return t
}

// OnHello is called after an agent's control stream is accepted. It delivers queued commands,
// re-sends unacknowledged ones, forwards pending cancellations and schedules detection of
// commands whose outcome was lost.
func (d *Dispatcher) OnHello(ctx context.Context, orgID, agentID string, running []string) {
	conn := d.fleet.Conn(agentID)
	helloAt := d.now()
	var resend []*agentv1.CentralMessage
	d.mu.Lock()
	for _, t := range d.cmds {
		if t.rec.AgentID != agentID || t.rec.Terminal() {
			continue
		}
		if t.rec.State == store.CommandSent && t.signed != nil && !slices.Contains(running, t.rec.ID) {
			t.resent = true
			resend = append(resend, &agentv1.CentralMessage{Message: &agentv1.CentralMessage_Command{Command: t.signed}})
		}
		if t.cancel && t.rec.State != store.CommandQueued {
			resend = append(resend, &agentv1.CentralMessage{Message: &agentv1.CentralMessage_Cancel{Cancel: &agentv1.CancelCommand{CommandId: t.rec.ID}}})
		}
	}
	d.mu.Unlock()
	if conn != nil {
		for _, m := range resend {
			_ = conn.Send(m)
		}
	}
	d.deliver(ctx, agentID)
	time.AfterFunc(lostGrace, func() { d.markLost(context.WithoutCancel(ctx), agentID, running, helloAt) })
}

// markLost fails commands the agent neither reported as running nor updated since its Hello.
func (d *Dispatcher) markLost(ctx context.Context, agentID string, running []string, since time.Time) {
	var lost []*tracked
	d.mu.Lock()
	for _, t := range d.cmds {
		if t.rec.AgentID != agentID || t.rec.Terminal() || t.rec.State == store.CommandQueued {
			continue
		}
		if slices.Contains(running, t.rec.ID) || t.lastUpdate.After(since) {
			continue
		}
		d.finishLocked(t, store.CommandFailed, "lost",
			"the connection to the agent was interrupted and the agent did not report a result")
		lost = append(lost, t)
	}
	d.mu.Unlock()
	for _, t := range lost {
		d.persistAndPublish(ctx, t, nil, true)
	}
}

// Cancel asks for a command to stop.
func (d *Dispatcher) Cancel(ctx context.Context, orgID, id string) error {
	t := d.lookup(ctx, orgID, id)
	if t == nil {
		return ErrNotFound
	}
	d.mu.Lock()
	if t.rec.OrgID != orgID {
		d.mu.Unlock()
		return ErrNotFound
	}
	if t.rec.Terminal() {
		d.mu.Unlock()
		return ErrFinished
	}
	agentID := t.rec.AgentID
	if t.rec.State == store.CommandQueued {
		d.finishLocked(t, store.CommandCancelled, "", "")
		d.queues[agentID] = slices.DeleteFunc(d.queues[agentID], func(s string) bool { return s == id })
		d.mu.Unlock()
		d.persistAndPublish(ctx, t, nil, true)
		return nil
	}
	t.cancel = true
	d.mu.Unlock()
	if conn := d.fleet.Conn(agentID); conn != nil {
		_ = conn.Send(&agentv1.CentralMessage{Message: &agentv1.CentralMessage_Cancel{Cancel: &agentv1.CancelCommand{CommandId: id}}})
	}
	return nil
}

// Get returns a command of an organization.
func (d *Dispatcher) Get(ctx context.Context, orgID, id string) (store.Command, error) {
	t := d.lookup(ctx, orgID, id)
	if t == nil {
		return store.Command{}, ErrNotFound
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.rec.OrgID != orgID {
		return store.Command{}, ErrNotFound
	}
	return t.rec, nil
}

// Live returns a command's in-memory record without loading it from storage.
func (d *Dispatcher) Live(orgID, id string) (store.Command, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t := d.cmds[id]; t != nil && t.rec.OrgID == orgID {
		return t.rec, true
	}
	return store.Command{}, false
}

// Wait blocks until the command finishes, the timeout passes or ctx ends, then returns its
// current record.
func (d *Dispatcher) Wait(ctx context.Context, orgID, id string, timeout time.Duration) (store.Command, error) {
	if _, err := d.Get(ctx, orgID, id); err != nil {
		return store.Command{}, err
	}
	t := d.lookup(ctx, orgID, id)
	if t == nil {
		return store.Command{}, ErrNotFound
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	return d.Get(ctx, orgID, id)
}

// Watch subscribes to a command's events and returns its current record and buffered output
// from seq onwards. The caller must Close the subscription.
func (d *Dispatcher) Watch(ctx context.Context, orgID, id string, fromSeq uint64) (store.Command, []*agentv1.OutputChunk, *bus.Subscription, error) {
	t := d.lookup(ctx, orgID, id)
	if t == nil || d.bus == nil {
		return store.Command{}, nil, nil, ErrNotFound
	}
	sub := d.bus.Subscribe(bus.CommandTopic(id), 256)
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.rec.OrgID != orgID {
		sub.Close()
		return store.Command{}, nil, nil, ErrNotFound
	}
	var backlog []*agentv1.OutputChunk
	for _, c := range t.output {
		if c.GetSeq() >= fromSeq {
			backlog = append(backlog, c)
		}
	}
	return t.rec, backlog, sub, nil
}

// Sweep expires queued and unacknowledged commands and forgets old finished ones.
func (d *Dispatcher) Sweep(ctx context.Context) {
	now := d.now()
	var changed []*tracked
	d.mu.Lock()
	for id, t := range d.cmds {
		switch {
		case t.rec.Terminal():
			if now.Sub(t.doneAt) > keepFinished {
				delete(d.cmds, id)
			}
		case t.rec.State == store.CommandQueued && now.After(t.rec.ExpiresAt):
			d.finishLocked(t, store.CommandExpired, "expired", "the agent did not come online before the command expired")
			d.queues[t.rec.AgentID] = slices.DeleteFunc(d.queues[t.rec.AgentID], func(s string) bool { return s == id })
			changed = append(changed, t)
		case t.rec.State == store.CommandSent && now.After(t.rec.ExpiresAt.Add(unacknowledgedBy)):
			d.finishLocked(t, store.CommandExpired, "expired", "the agent did not acknowledge the command before it expired")
			changed = append(changed, t)
		case now.After(t.rec.ExpiresAt.Add(offlineGiveUp)) && d.fleet.Conn(t.rec.AgentID) == nil:
			d.finishLocked(t, store.CommandFailed, "lost", "the agent disconnected and did not report a result")
			changed = append(changed, t)
		}
	}
	for agent, q := range d.queues {
		if len(q) == 0 {
			delete(d.queues, agent)
		}
	}
	d.mu.Unlock()
	for _, t := range changed {
		d.persistAndPublish(ctx, t, nil, true)
	}
}

// Recover handles commands left unfinished by a previous process: queued ones are expired
// (their signed bytes were only in memory), in-flight ones are tracked again so agents can
// still report their results.
func (d *Dispatcher) Recover(ctx context.Context) error {
	st, err := d.st()
	if err != nil {
		return err
	}
	for _, state := range []string{store.CommandQueued, store.CommandSent, store.CommandAccepted, store.CommandRunning} {
		after := ""
		for {
			page, next, err := st.Commands.Find(ctx, store.System(), store.Eq("state", state).Page(store.MaxLimit, after))
			if err != nil {
				return fmt.Errorf("dispatch: recover %s commands: %w", state, err)
			}
			for _, rec := range page {
				t := &tracked{rec: *rec, done: make(chan struct{}), persisted: d.now(), lastUpdate: d.now()}
				d.mu.Lock()
				if d.cmds[rec.ID] != nil {
					d.mu.Unlock()
					continue
				}
				d.cmds[rec.ID] = t
				if state == store.CommandQueued {
					d.finishLocked(t, store.CommandExpired, "expired", "Central restarted before the command was delivered")
				}
				d.mu.Unlock()
				if state == store.CommandQueued {
					d.persistAndPublish(ctx, t, nil, true)
				}
			}
			if next == "" {
				break
			}
			after = next
		}
	}
	return nil
}
