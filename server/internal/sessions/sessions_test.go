// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package sessions

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
)

func TestAttachChecks(t *testing.T) {
	m := NewManager()
	p := m.Create("org", "a1", Terminal)
	good := &agentv1.SessionAttach{SessionId: p.ID, AttachToken: p.Token, CommandId: "c1"}
	if _, err := m.Attach("org", "a1", good); err == nil {
		t.Fatal("attached before the command was recorded")
	}
	m.SetCommand(p, "c1")
	bad := []struct {
		org, agent string
		a          *agentv1.SessionAttach
	}{
		{"org", "a2", good},
		{"org2", "a1", good},
		{"org", "a1", &agentv1.SessionAttach{SessionId: p.ID, AttachToken: []byte("wrong"), CommandId: "c1"}},
		{"org", "a1", &agentv1.SessionAttach{SessionId: p.ID, AttachToken: p.Token, CommandId: "c2"}},
		{"org", "a1", &agentv1.SessionAttach{SessionId: "nope", AttachToken: p.Token, CommandId: "c1"}},
	}
	for i, b := range bad {
		if _, err := m.Attach(b.org, b.agent, b.a); err == nil {
			t.Errorf("case %d attached", i)
		}
	}
	pipe, err := m.Attach("org", "a1", good)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-p.Attached(); got != pipe {
		t.Fatal("consumer did not receive the pipe")
	}
	if _, err := m.Attach("org", "a1", good); err == nil {
		t.Fatal("session attached twice")
	}

	// Expired sessions cannot be attached.
	m.now = func() time.Time { return time.Now().Add(2 * AttachWindow) }
	q := m.Create("org", "a1", Journal)
	m.SetCommand(q, "c3")
	m.now = func() time.Time { return time.Now().Add(4 * AttachWindow) }
	if _, err := m.Attach("org", "a1", &agentv1.SessionAttach{SessionId: q.ID, AttachToken: q.Token, CommandId: "c3"}); err == nil {
		t.Fatal("expired session attached")
	}
}

func TestNextDrainsBeforeClose(t *testing.T) {
	p := newPipe(Terminal)
	_ = p.Deliver(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Data{Data: []byte("x")}}, time.Second)
	_ = p.Deliver(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Close{Close: &agentv1.SessionClose{ExitCode: 3}}}, time.Second)
	p.Close()
	ctx := context.Background()
	if f := p.Next(ctx); string(f.GetData()) != "x" {
		t.Fatalf("first frame %v", f)
	}
	if f := p.Next(ctx); f.GetClose().GetExitCode() != 3 {
		t.Fatalf("close frame lost: %v", f)
	}
	if f := p.Next(ctx); f != nil {
		t.Fatalf("frame after close: %v", f)
	}
}
