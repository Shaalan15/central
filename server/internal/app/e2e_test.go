// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/agentsim"
	"github.com/Shaalan15/central/server/internal/store"
)

// startGateway serves the agent endpoint for the test and returns its URL.
func startGateway(t *testing.T, env *testEnv) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = env.app.Gateway.Serve(ctx, ln)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return "https://" + ln.Addr().String()
}

type simHost struct {
	agent *agentsim.Agent
	stop  context.CancelFunc
	done  chan struct{}
}

// enrollSim enrolls and approves a simulated agent and keeps it connected with handler.
func enrollSim(t *testing.T, env *testEnv, oc agentClients, agentURL, host string, tags []string, handler agentsim.Handler) *simHost {
	t.Helper()
	ctx := context.Background()
	tok, err := oc.enroll.CreateEnrollmentToken(ctx, connect.NewRequest(&apiv1.CreateEnrollmentTokenRequest{Name: host}))
	if err != nil {
		t.Fatal(err)
	}
	machine := store.DeriveID(host)
	e, err := agentsim.Enroll(ctx, agentsim.EnrollOptions{AgentURL: agentURL, Key: tok.Msg.GetEnrollmentKey(), Facts: &agentv1.HostFacts{
		Hostname: host, MachineId: machine, Os: &agentv1.OSInfo{Id: "ubuntu", VersionId: "24.04", PrettyName: "Ubuntu 24.04 LTS"},
		Addresses: []*agentv1.InterfaceAddress{{Interface: "eth0", Cidr: "127.0.0.1/8"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oc.enroll.ApproveEnrollmentRequest(ctx, connect.NewRequest(&apiv1.ApproveEnrollmentRequestRequest{
		RequestId: e.ID, PairingCode: e.PairingCode, Tags: tags,
	})); err != nil {
		t.Fatal(err)
	}
	a, err := e.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	h := &simHost{agent: a, stop: stop, done: make(chan struct{})}
	connected := make(chan struct{})
	go func() {
		defer close(h.done)
		_ = a.Run(runCtx, handler, func(*agentsim.Conn) { close(connected) })
	}()
	select {
	case <-connected:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not connect")
	}
	t.Cleanup(func() { stop(); <-h.done })
	return h
}

// terminalHandler echoes input with a prefix and exits on "exit".
func terminalHandler(t *testing.T) agentsim.Handler {
	return func(ctx context.Context, conn *agentsim.Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
		ok := &agentv1.CommandUpdate{State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED}
		switch cmd.GetOperation().GetKind().(type) {
		case *agentv1.Operation_TerminalOpen:
			s, err := conn.Attach(ctx, cmd)
			if err != nil {
				t.Errorf("attach: %v", err)
				return nil
			}
			_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Data{Data: []byte("welcome, olá\r\n")}})
			for {
				f, err := s.Receive()
				if err != nil {
					return ok
				}
				if d := f.GetData(); len(d) > 0 {
					if string(d) == "exit\n" {
						s.Close(0)
						return ok
					}
					_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Data{Data: append([]byte("echo:"), d...)}})
				}
				if f.GetClose() != nil {
					return ok
				}
			}
		case *agentv1.Operation_JournalFollow:
			s, err := conn.Attach(ctx, cmd)
			if err != nil {
				t.Errorf("attach: %v", err)
				return nil
			}
			_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Journal{Journal: &agentv1.JournalEntries{Entries: []*agentv1.JournalEntry{
				{Time: timestamppb.Now(), Unit: "nginx.service", Message: "started"},
			}}}})
			for {
				f, err := s.Receive()
				if err != nil || f.GetClose() != nil {
					return ok
				}
			}
		}
		return ok
	}
}

func readWS(t *testing.T, ctx context.Context, c *websocket.Conn) (websocket.MessageType, []byte) {
	t.Helper()
	typ, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("websocket read: %v", err)
	}
	return typ, data
}

func TestTerminalJournalAndRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := completeSetup(t)
	agentURL := startGateway(t, env)
	owner, _ := enrollTOTP(t, env, "owner@example.com", ownerPassword)
	oc := owner.agents()
	h := enrollSim(t, env, oc, agentURL, "web-1", []string{"web"}, terminalHandler(t))

	term, err := oc.host.OpenTerminal(ctx, connect.NewRequest(&apiv1.OpenTerminalRequest{AgentId: h.agent.ID, RunAs: "deploy", Cols: 100, Rows: 30}))
	if err != nil {
		t.Fatal(err)
	}
	if !term.Msg.GetRecorded() {
		t.Fatal("recording should be on by default")
	}
	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/ws/terminal?ticket=" + term.Msg.GetTicket()

	// Without the browser's session cookie the ticket is useless (and it is consumed).
	if _, err := dialWS(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {env.srv.URL}}}); err == nil {
		t.Fatal("ticket accepted without the session cookie")
	}
	term, err = oc.host.OpenTerminal(ctx, connect.NewRequest(&apiv1.OpenTerminalRequest{AgentId: h.agent.ID, RunAs: "deploy", Cols: 100, Rows: 30}))
	if err != nil {
		t.Fatal(err)
	}
	wsURL = "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/ws/terminal?ticket=" + term.Msg.GetTicket()
	// A foreign origin is refused.
	if _, err := dialWS(ctx, wsURL, &websocket.DialOptions{HTTPClient: owner.hc, HTTPHeader: http.Header{"Origin": {"https://evil.example"}}}); err == nil {
		t.Fatal("cross-origin terminal accepted")
	}
	term, err = oc.host.OpenTerminal(ctx, connect.NewRequest(&apiv1.OpenTerminalRequest{AgentId: h.agent.ID, RunAs: "deploy", Cols: 100, Rows: 30}))
	if err != nil {
		t.Fatal(err)
	}
	wsURL = "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/ws/terminal?ticket=" + term.Msg.GetTicket()
	ws, err := dialWS(ctx, wsURL, &websocket.DialOptions{HTTPClient: owner.hc, HTTPHeader: http.Header{"Origin": {env.srv.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()

	status := func() map[string]any {
		typ, data := readWS(t, ctx, ws)
		if typ != websocket.MessageText {
			t.Fatalf("expected status, got %q", data)
		}
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		return m
	}
	if m := status(); m["state"] != "connecting" {
		t.Fatalf("status: %v", m)
	}
	if m := status(); m["state"] != "connected" {
		t.Fatalf("status: %v", m)
	}
	if _, data := readWS(t, ctx, ws); !bytes.Contains(data, []byte("welcome")) {
		t.Fatalf("output: %q", data)
	}
	_ = ws.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":120,"rows":40}`))
	_ = ws.Write(ctx, websocket.MessageBinary, []byte("ls\n"))
	if _, data := readWS(t, ctx, ws); string(data) != "echo:ls\n" {
		t.Fatalf("echo: %q", data)
	}
	_ = ws.Write(ctx, websocket.MessageBinary, []byte("exit\n"))
	if m := status(); m["state"] != "closed" || m["exit_code"] != float64(0) {
		t.Fatalf("close: %v", m)
	}

	// The recording is listed and replays the output (not the keystrokes).
	rc := apiv1connect.NewRecordingServiceClient(owner.hc, env.srv.URL+"/api", connect.WithInterceptors(csrfInterceptor(owner)))
	var list *connect.Response[apiv1.ListRecordingsResponse]
	waitUntil(t, "recording finished", func() bool {
		list, err = rc.ListRecordings(ctx, connect.NewRequest(&apiv1.ListRecordingsRequest{AgentId: h.agent.ID}))
		return err == nil && len(list.Msg.GetRecordings()) == 1 && list.Msg.GetRecordings()[0].GetEndedAt() != nil
	})
	rreq := connect.NewRequest(&apiv1.ReadRecordingRequest{RecordingId: list.Msg.GetRecordings()[0].GetId()})
	rreq.Header().Set("X-CSRF-Token", owner.csrf)
	rs, err := rc.ReadRecording(ctx, rreq)
	if err != nil {
		t.Fatal(err)
	}
	var cast bytes.Buffer
	for rs.Receive() {
		cast.Write(rs.Msg().GetAsciicast())
	}
	text := cast.String()
	if !strings.Contains(text, `"version":2`) || !strings.Contains(text, "welcome, olá") || !strings.Contains(text, "echo:ls") ||
		!strings.Contains(text, `"r","120x40"`) || strings.Contains(text, `"i"`) {
		t.Fatalf("asciicast: %s", text)
	}

	// Journal follow streams entries until the client goes away.
	jctx, jcancel := context.WithTimeout(ctx, 20*time.Second)
	jreq := connect.NewRequest(&apiv1.FollowJournalRequest{AgentId: h.agent.ID, Filter: &agentv1.JournalFilter{Units: []string{"nginx.service"}}})
	jreq.Header().Set("X-CSRF-Token", owner.csrf)
	js, err := oc.host.FollowJournal(jctx, jreq)
	if err != nil {
		t.Fatal(err)
	}
	if !js.Receive() || js.Msg().GetEntries()[0].GetMessage() != "started" {
		t.Fatalf("journal: %v %v", js.Msg(), js.Err())
	}
	jcancel()
	_ = js.Close()

	events, _ := owner.audit.ListAuditEvents(ctx, connect.NewRequest(&apiv1.ListAuditEventsRequest{ActionPrefix: "terminal."}))
	var actions []string
	for _, e := range events.Msg.GetEvents() {
		actions = append(actions, e.GetAction())
	}
	if !contains(actions, "terminal.opened") || !contains(actions, "terminal.closed") {
		t.Fatalf("audit: %v", actions)
	}
}

func dialWS(ctx context.Context, u string, opts *websocket.DialOptions) (*websocket.Conn, error) {
	c, resp, err := websocket.Dial(ctx, u, opts)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return c, err
}

func csrfInterceptor(b *browser) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("X-CSRF-Token", b.csrf)
			return next(ctx, req)
		}
	})
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFleetJobRollout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := completeSetup(t)
	agentURL := startGateway(t, env)
	owner, _ := enrollTOTP(t, env, "owner@example.com", ownerPassword)
	oc := owner.agents()

	var mu sync.Mutex
	ran := map[string]int{}
	handler := func(fail bool, block bool) agentsim.Handler {
		return func(ctx context.Context, conn *agentsim.Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
			mu.Lock()
			ran[cmd.GetAgentId()]++
			mu.Unlock()
			if block {
				<-ctx.Done() // runs until Central cancels it
				return &agentv1.CommandUpdate{State: agentv1.CommandState_COMMAND_STATE_CANCELLED}
			}
			if fail {
				return &agentv1.CommandUpdate{
					State: agentv1.CommandState_COMMAND_STATE_FAILED,
					Error: &agentv1.CommandError{Code: agentv1.ErrorCode_ERROR_CODE_EXECUTION_FAILED, Message: "dpkg error"},
				}
			}
			return &agentv1.CommandUpdate{State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED}
		}
	}
	w1 := enrollSim(t, env, oc, agentURL, "web-1", []string{"web"}, handler(false, false))
	w2 := enrollSim(t, env, oc, agentURL, "web-2", []string{"web"}, handler(true, false))
	w3 := enrollSim(t, env, oc, agentURL, "web-3", []string{"web"}, handler(false, false))
	db := enrollSim(t, env, oc, agentURL, "db-1", []string{"db"}, handler(false, true))

	jc := apiv1connect.NewJobServiceClient(owner.hc, env.srv.URL+"/api", connect.WithInterceptors(csrfInterceptor(owner)))
	upgrade := &agentv1.Operation{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{}}}
	sel := &apiv1.TargetSelector{Tags: []string{"web"}}
	prev, err := jc.PreviewTargets(ctx, connect.NewRequest(&apiv1.PreviewTargetsRequest{Selector: sel}))
	if err != nil || prev.Msg.GetCount() != 3 || prev.Msg.GetOnline() != 3 {
		t.Fatalf("preview: %v %v", prev, err)
	}

	// Above the confirmation threshold the target count must be confirmed.
	st := env.app.Holder.Get()
	org, _ := st.Orgs.Get(ctx, store.System(), ownerOrg(t, env))
	org.Settings.MassActionConfirmThreshold = 2
	_ = st.Orgs.Update(ctx, store.System(), org)
	create := func(confirm uint32, maxFail uint32) (*apiv1.Job, error) {
		res, err := jc.CreateJob(ctx, connect.NewRequest(&apiv1.CreateJobRequest{
			Name: "security updates", Operation: upgrade, Selector: sel, ConfirmTargetCount: confirm,
			Rollout: &apiv1.RolloutStrategy{BatchSize: 1, MaxFailurePercent: maxFail},
		}))
		if err != nil {
			return nil, err
		}
		return res.Msg.GetJob(), nil
	}
	if _, err := create(0, 0); code(err) != connect.CodeFailedPrecondition || reason(err) != "confirm_target_count" {
		t.Fatalf("unconfirmed: %v", err)
	}

	// Batches of one, abort on the first failure: web-1 succeeds, web-2 fails, web-3 is skipped.
	job, err := create(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	wreq := connect.NewRequest(&apiv1.WatchJobRequest{JobId: job.GetId()})
	wreq.Header().Set("X-CSRF-Token", owner.csrf)
	watch, err := jc.WatchJob(ctx, wreq)
	if err != nil {
		t.Fatal(err)
	}
	var last *apiv1.Job
	for watch.Receive() {
		if j := watch.Msg().GetJob(); j != nil {
			last = j
		}
	}
	if last.GetState() != apiv1.JobState_JOB_STATE_ABORTED || last.GetCounts().GetSucceeded() != 1 ||
		last.GetCounts().GetFailed() != 1 || last.GetCounts().GetSkipped() != 1 {
		t.Fatalf("job: %v", last)
	}
	mu.Lock()
	if ran[w1.agent.ID] != 1 || ran[w2.agent.ID] != 1 || ran[w3.agent.ID] != 0 {
		t.Fatalf("ran: %v", ran)
	}
	mu.Unlock()
	execs, err := jc.ListJobExecutions(ctx, connect.NewRequest(&apiv1.ListJobExecutionsRequest{JobId: job.GetId()}))
	if err != nil || len(execs.Msg.GetExecutions()) != 3 {
		t.Fatalf("executions: %v %v", execs, err)
	}
	for _, e := range execs.Msg.GetExecutions() {
		if e.GetAgentId() == w3.agent.ID && !e.GetSkipped() {
			t.Fatalf("web-3 not skipped: %v", e)
		}
		if e.GetAgentId() == w2.agent.ID && e.GetError().GetMessage() != "dpkg error" {
			t.Fatalf("web-2 error: %v", e)
		}
	}

	// Cancelling a job stops its running commands on the agents.
	blocking, err := jc.CreateJob(ctx, connect.NewRequest(&apiv1.CreateJobRequest{
		Name: "db upgrade", Operation: upgrade, Selector: &apiv1.TargetSelector{Tags: []string{"db"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "db command running", func() bool { mu.Lock(); defer mu.Unlock(); return ran[db.agent.ID] == 1 })
	if _, err := jc.CancelJob(ctx, connect.NewRequest(&apiv1.CancelJobRequest{JobId: blocking.Msg.GetJob().GetId()})); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "job cancelled", func() bool {
		j, err := jc.GetJob(ctx, connect.NewRequest(&apiv1.GetJobRequest{JobId: blocking.Msg.GetJob().GetId()}))
		return err == nil && j.Msg.GetJob().GetState() == apiv1.JobState_JOB_STATE_CANCELLED
	})

	// Exec is refused for jobs by an operator (no exec.run), and terminals never run as jobs.
	term := &agentv1.Operation{Kind: &agentv1.Operation_TerminalOpen{TerminalOpen: &agentv1.TerminalOpen{}}}
	if _, err := jc.CreateJob(ctx, connect.NewRequest(&apiv1.CreateJobRequest{Operation: term, Selector: sel, ConfirmTargetCount: 3})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("terminal job: %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
