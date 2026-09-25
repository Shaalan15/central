// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package dispatch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/bus"
	ccrypto "github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/memory"
)

type fakeConn struct {
	mu   sync.Mutex
	msgs []*agentv1.CentralMessage
}

func (c *fakeConn) Send(m *agentv1.CentralMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *fakeConn) Close(agentv1.Disconnect_Reason, string) {}

func (c *fakeConn) commands() []*agentv1.SignedCommand {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*agentv1.SignedCommand
	for _, m := range c.msgs {
		if sc := m.GetCommand(); sc != nil {
			out = append(out, sc)
		}
	}
	return out
}

type env struct {
	d   *Dispatcher
	x   *fleet.Index
	st  *store.Store
	pki *pki.Authority
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := store.Open(memory.New())
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := &store.Holder{}
	h.Set(st)
	kr, _ := ccrypto.NewKeyring(bytes.Repeat([]byte{9}, 32))
	a := pki.New(h, kr)
	if err := a.Load(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	x := fleet.New(h, bus.NewMemory(), nil, log)
	for _, id := range []string{"a1", "a2"} {
		if err := x.Create(ctx, &store.Agent{ID: id, OrgID: "org", Name: id, Lifecycle: store.AgentActive}); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{x: x, st: st, pki: a, now: time.Now()}
	e.d = New(h, a, x, bus.NewMemory(), log)
	e.d.now = func() time.Time { return e.now }
	return e
}

func upgrade() *agentv1.Operation {
	return &agentv1.Operation{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{SecurityOnly: true}}}
}

func req(op *agentv1.Operation) Request {
	return Request{OrgID: "org", AgentID: "a1", Operation: op, Issuer: store.PrincipalRef{Kind: "user", ID: "u1", Display: "alice@example.com"}}
}

func (e *env) connect(t *testing.T, agentID string, running ...string) *fakeConn {
	t.Helper()
	c := &fakeConn{}
	if err := e.x.Connect(context.Background(), "org", agentID, c, fleet.ConnectInfo{}); err != nil {
		t.Fatal(err)
	}
	e.d.OnHello(context.Background(), "org", agentID, running)
	return c
}

func TestQueueSignDeliverComplete(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rec, err := e.d.Submit(ctx, req(upgrade()))
	if err != nil || rec.State != store.CommandQueued {
		t.Fatalf("submit: %+v %v", rec, err)
	}
	c := e.connect(t, "a1")
	cmds := c.commands()
	if len(cmds) != 1 {
		t.Fatalf("delivered %d commands", len(cmds))
	}
	// The agent's helper verifies the signature over the exact bytes, then decodes them.
	sc := cmds[0]
	key := e.pki.ActiveSigningKey()
	if sc.GetKeyId() != key.ID || !pki.VerifyCommand(key.PublicKey, sc.GetCommand(), sc.GetSignature()) {
		t.Fatal("bad signature")
	}
	var cmd agentv1.Command
	if err := proto.Unmarshal(sc.GetCommand(), &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.GetAgentId() != "a1" || cmd.GetOrgId() != "org" || cmd.GetCommandId() != rec.ID ||
		cmd.GetExpiresAt().AsTime().Sub(cmd.GetIssuedAt().AsTime()) != DefaultTTL || cmd.GetIssuer().GetDisplay() != "alice@example.com" {
		t.Fatalf("command: %v", &cmd)
	}
	if got, _ := e.d.Get(ctx, "org", rec.ID); got.State != store.CommandSent {
		t.Fatalf("state after delivery: %s", got.State)
	}

	// Another agent cannot report on this command.
	e.d.HandleUpdate(ctx, "org", "a2", &agentv1.CommandUpdate{CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED})
	if got, _ := e.d.Get(ctx, "org", rec.ID); got.Terminal() {
		t.Fatal("foreign agent completed the command")
	}

	_, backlog, sub, err := e.d.Watch(ctx, "org", rec.ID, 0)
	if err != nil || len(backlog) != 0 {
		t.Fatal(err)
	}
	defer sub.Close()
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_ACCEPTED})
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{
		CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_RUNNING, ProgressPercent: 40, Status: "Unpacking openssl",
		Output: []*agentv1.OutputChunk{{Stream: agentv1.OutputChunk_STREAM_STDOUT, Data: []byte("Reading package lists...\n"), Seq: 0}},
	})
	// State never moves backwards.
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_ACCEPTED})
	if got, _ := e.d.Get(ctx, "org", rec.ID); got.State != store.CommandRunning || got.ProgressPercent != 40 {
		t.Fatalf("running: %+v", got)
	}
	done := make(chan store.Command, 1)
	go func() {
		r, _ := e.d.Wait(ctx, "org", rec.ID, 5*time.Second)
		done <- r
	}()
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{
		CommandId: rec.ID, State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED, ProgressPercent: 100,
		Result: &agentv1.CommandResult{Kind: &agentv1.CommandResult_PackagesChange{PackagesChange: &agentv1.PackagesChangeResult{
			Changes: []*agentv1.PackageChange{{Name: "openssl", NewVersion: "3.0.13-0ubuntu3.5"}},
		}}},
	})
	final := <-done
	if final.State != store.CommandSucceeded || len(final.ResultProto) == 0 || !strings.Contains(string(final.OutputTail), "Reading package") {
		t.Fatalf("final: %+v", final)
	}
	// Watchers saw the progress and the output.
	var sawOutput, sawFinal bool
	for len(sub.C) > 0 {
		ev := (<-sub.C).(Event)
		sawOutput = sawOutput || len(ev.Output) > 0
		sawFinal = sawFinal || ev.Record.State == store.CommandSucceeded
	}
	if !sawOutput || !sawFinal {
		t.Fatal("watch events missing")
	}
	stored, _ := e.st.Commands.Get(ctx, store.Tenant("org"), rec.ID)
	if stored.State != store.CommandSucceeded {
		t.Fatalf("stored: %+v", stored)
	}
	if err := e.d.Cancel(ctx, "org", rec.ID); !errors.Is(err, ErrFinished) {
		t.Fatalf("cancel finished: %v", err)
	}
	if _, err := e.d.Get(ctx, "other", rec.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("command visible to another organization")
	}
}

func TestSecretsAreNotStored(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	op := &agentv1.Operation{Kind: &agentv1.Operation_UserSetPassword{UserSetPassword: &agentv1.UserSetPassword{Name: "deploy", Password: "correct horse battery"}}}
	rec, err := e.d.Submit(ctx, req(op))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := e.st.Commands.Get(ctx, store.Tenant("org"), rec.ID)
	if bytes.Contains(stored.OperationProto, []byte("correct horse")) {
		t.Fatal("password persisted")
	}
	// The agent still receives the real value (inside the signed bytes).
	c := e.connect(t, "a1")
	if !bytes.Contains(c.commands()[0].GetCommand(), []byte("correct horse")) {
		t.Fatal("password not delivered")
	}
}

func TestPolicyExpiryCancelAndLoss(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	// Owner policy denies package installs and later pauses the host.
	_ = e.x.SetPolicy(ctx, "a1", &agentv1.EffectivePolicy{Allowed: []agentv1.Capability{agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE}})
	install := &agentv1.Operation{Kind: &agentv1.Operation_PackagesInstall{PackagesInstall: &agentv1.PackagesInstall{Names: []string{"nginx"}}}}
	if _, err := e.d.Submit(ctx, req(install)); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("policy: %v", err)
	}
	_ = e.x.SetPolicy(ctx, "a1", &agentv1.EffectivePolicy{Paused: true, Allowed: []agentv1.Capability{agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE}})
	if _, err := e.d.Submit(ctx, req(upgrade())); !errors.Is(err, ErrPaused) {
		t.Fatalf("paused: %v", err)
	}
	_ = e.x.SetPolicy(ctx, "a1", &agentv1.EffectivePolicy{Allowed: []agentv1.Capability{agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE}})
	if _, err := e.d.Submit(ctx, Request{OrgID: "other", AgentID: "a1", Operation: upgrade()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org submit: %v", err)
	}
	if _, err := e.d.Submit(ctx, req(&agentv1.Operation{})); err == nil {
		t.Fatal("empty operation accepted")
	}

	// Queued commands expire with their TTL; cancelling a queued command is immediate.
	r1, _ := e.d.Submit(ctx, Request{OrgID: "org", AgentID: "a1", Operation: upgrade(), TTL: time.Minute})
	r2, _ := e.d.Submit(ctx, req(upgrade()))
	if err := e.d.Cancel(ctx, "org", r2.ID); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(2 * time.Minute)
	e.d.Sweep(ctx)
	if got, _ := e.d.Get(ctx, "org", r1.ID); got.State != store.CommandExpired {
		t.Fatalf("expiry: %s", got.State)
	}
	if got, _ := e.d.Get(ctx, "org", r2.ID); got.State != store.CommandCancelled {
		t.Fatalf("cancel: %s", got.State)
	}

	// A delivered command whose outcome is unknown after a reconnect is reported as lost.
	r3, _ := e.d.Submit(ctx, req(upgrade()))
	e.connect(t, "a1")
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{CommandId: r3.ID, State: agentv1.CommandState_COMMAND_STATE_RUNNING})
	e.now = e.now.Add(time.Minute)
	c := e.connect(t, "a1") // the agent comes back without listing r3 as running
	e.d.markLost(ctx, "a1", nil, e.now)
	if got, _ := e.d.Get(ctx, "org", r3.ID); got.State != store.CommandFailed || got.ErrorCode != "lost" {
		t.Fatalf("lost: %+v", got)
	}

	// An unacknowledged command is re-sent once on reconnect; a REPLAYED rejection of the
	// re-sent copy does not override the original execution.
	r4, _ := e.d.Submit(ctx, req(upgrade()))
	if n := len(c.commands()); n == 0 {
		t.Fatal("not delivered")
	}
	c2 := e.connect(t, "a1")
	if len(c2.commands()) != 1 {
		t.Fatalf("resent %d", len(c2.commands()))
	}
	e.d.HandleUpdate(ctx, "org", "a1", &agentv1.CommandUpdate{
		CommandId: r4.ID, State: agentv1.CommandState_COMMAND_STATE_REJECTED,
		Error: &agentv1.CommandError{Code: agentv1.ErrorCode_ERROR_CODE_REPLAYED},
	})
	if got, _ := e.d.Get(ctx, "org", r4.ID); got.Terminal() {
		t.Fatalf("replay rejection applied: %+v", got)
	}
}

func TestRecoverAfterRestart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	queued, _ := e.d.Submit(ctx, req(upgrade()))
	c := e.connect(t, "a2")
	_ = c
	running, _ := e.d.Submit(ctx, Request{OrgID: "org", AgentID: "a2", Operation: upgrade()})
	e.d.HandleUpdate(ctx, "org", "a2", &agentv1.CommandUpdate{CommandId: running.ID, State: agentv1.CommandState_COMMAND_STATE_RUNNING})

	fresh := New(e.d.holder, e.pki, e.x, bus.NewMemory(), e.d.log)
	if err := fresh.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := fresh.Get(ctx, "org", queued.ID); got.State != store.CommandExpired {
		t.Fatalf("queued after restart: %s", got.State)
	}
	fresh.HandleUpdate(ctx, "org", "a2", &agentv1.CommandUpdate{CommandId: running.ID, State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED})
	if got, _ := fresh.Get(ctx, "org", running.ID); got.State != store.CommandSucceeded {
		t.Fatalf("running after restart: %s", got.State)
	}
}
