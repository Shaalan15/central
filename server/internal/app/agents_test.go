// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/store"
)

type agentClients struct {
	enroll  apiv1connect.EnrollmentAdminServiceClient
	fleet   apiv1connect.FleetServiceClient
	metrics apiv1connect.MetricsServiceClient
	host    apiv1connect.HostServiceClient
}

// headerInterceptor adds request headers (credentials, CSRF token) to unary and streaming calls.
type headerInterceptor func(http.Header)

func (h headerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		h(req.Header())
		return next(ctx, req)
	}
}

func (h headerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		h(conn.RequestHeader())
		return conn
	}
}

func (h headerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func newAgentClients(hc *http.Client, base string, header func(http.Header)) agentClients {
	opt := connect.WithInterceptors(headerInterceptor(header))
	return agentClients{
		enroll:  apiv1connect.NewEnrollmentAdminServiceClient(hc, base+"/api", opt),
		fleet:   apiv1connect.NewFleetServiceClient(hc, base+"/api", opt),
		metrics: apiv1connect.NewMetricsServiceClient(hc, base+"/api", opt),
		host:    apiv1connect.NewHostServiceClient(hc, base+"/api", opt),
	}
}

func (b *browser) agents() agentClients {
	return newAgentClients(b.hc, b.base, func(h http.Header) { h.Set("X-CSRF-Token", b.csrf) })
}

// simulateEnroll submits an enrollment request the way the gateway does for a real agent.
func simulateEnroll(t *testing.T, env *testEnv, key, host, machine string) *enrollment.SubmitResult {
	t.Helper()
	tokenID, secret, _, err := enrollment.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	res, err := env.app.Enroll.Submit(context.Background(), enrollment.SubmitInput{
		TokenID: tokenID, TokenSecret: secret, CSRDER: csr, AgentVersion: "0.1.0", ProtocolVersion: 1,
		SourceIP: netip.MustParseAddr("10.0.0.7"),
		Facts: &agentv1.HostFacts{
			Hostname: host, MachineId: machine, Os: &agentv1.OSInfo{Id: "ubuntu", VersionId: "24.04"},
			Addresses: []*agentv1.InterfaceAddress{{Cidr: "10.0.0.7/24"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAgentManagementAPI(t *testing.T) {
	ctx := context.Background()
	env := completeSetup(t)
	owner, secret := enrollTOTP(t, env, "owner@example.com", ownerPassword)
	oc := owner.agents()

	// Enrollment tokens require a fresh step-up.
	expireStepUp(t, env)
	if _, err := oc.enroll.CreateEnrollmentToken(ctx, connect.NewRequest(&apiv1.CreateEnrollmentTokenRequest{Name: "web"})); reason(err) != authz.ReasonStepUpRequired {
		t.Fatalf("token without step-up: %v", err)
	}
	allowTOTPReuse(t, env)
	stepUp(t, owner, secret, time.Now())
	tok, err := oc.enroll.CreateEnrollmentToken(ctx, connect.NewRequest(&apiv1.CreateEnrollmentTokenRequest{Name: "web", MaxUses: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Msg.GetEnrollmentKey(), enrollment.KeyPrefix) || !strings.Contains(tok.Msg.GetInstallCommand(), "/install-agent.sh") ||
		strings.Contains(tok.Msg.GetInstallCommand(), tok.Msg.GetEnrollmentKey()) {
		t.Fatalf("token response: %v", tok.Msg)
	}
	list, _ := oc.enroll.ListEnrollmentTokens(ctx, connect.NewRequest(&apiv1.ListEnrollmentTokensRequest{}))
	if len(list.Msg.GetTokens()) != 1 || list.Msg.GetTokens()[0].GetUses() != 0 {
		t.Fatalf("tokens: %v", list.Msg)
	}

	// An agent requests enrollment; the owner approves it with the pairing code.
	res := simulateEnroll(t, env, tok.Msg.GetEnrollmentKey(), "web-1", strings.Repeat("a", 32))
	pending, err := oc.enroll.ListEnrollmentRequests(ctx, connect.NewRequest(&apiv1.ListEnrollmentRequestsRequest{}))
	if err != nil || len(pending.Msg.GetRequests()) != 1 || pending.Msg.GetRequests()[0].GetPairingCode() != res.Request.PairingCode {
		t.Fatalf("pending: %v %v", pending, err)
	}
	if _, err := oc.enroll.ApproveEnrollmentRequest(ctx, connect.NewRequest(&apiv1.ApproveEnrollmentRequestRequest{
		RequestId: res.Request.ID, PairingCode: "AAAA-AAAA",
	})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong pairing code: %v", err)
	}
	approved, err := oc.enroll.ApproveEnrollmentRequest(ctx, connect.NewRequest(&apiv1.ApproveEnrollmentRequestRequest{
		RequestId: res.Request.ID, PairingCode: res.Request.PairingCode, Name: "Web 1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	agentID := approved.Msg.GetRequest().GetAgentId()
	if approved.Msg.GetRequest().GetPairingCode() != "" {
		t.Fatal("pairing code returned after the decision")
	}

	// The fleet lists it; a live watch sees changes.
	agents, err := oc.fleet.ListAgents(ctx, connect.NewRequest(&apiv1.ListAgentsRequest{}))
	if err != nil || len(agents.Msg.GetAgents()) != 1 || agents.Msg.GetAgents()[0].GetName() != "Web 1" {
		t.Fatalf("agents: %v %v", agents, err)
	}
	watchCtx, cancelWatch := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWatch()
	wreq := connect.NewRequest(&apiv1.WatchFleetRequest{})
	wreq.Header().Set("X-CSRF-Token", owner.csrf)
	watch, err := oc.fleet.WatchFleet(watchCtx, wreq)
	if err != nil {
		t.Fatal(err)
	}
	if !watch.Receive() || len(watch.Msg().GetSnapshot().GetAgents()) != 1 {
		t.Fatalf("snapshot: %v %v", watch.Msg(), watch.Err())
	}
	if _, err := oc.fleet.UpdateAgent(ctx, connect.NewRequest(&apiv1.UpdateAgentRequest{
		AgentId: agentID, Tags: &apiv1.TagList{Tags: []string{"web", "prod"}},
	})); err != nil {
		t.Fatal(err)
	}
	gotUpsert := false
	for !gotUpsert && watch.Receive() {
		if u := watch.Msg().GetUpsert(); u != nil && len(u.GetTags()) == 2 {
			gotUpsert = true
		}
	}
	if !gotUpsert {
		t.Fatalf("no upsert: %v", watch.Err())
	}
	cancelWatch()
	_ = watch.Close()

	// A scoped operator API key: only sees agents tagged "db", cannot run exec.
	key, err := owner.keys.CreateApiKey(ctx, connect.NewRequest(&apiv1.CreateApiKeyRequest{
		Name: "ops-bot", RoleBinding: &apiv1.RoleBinding{RoleId: authz.RoleOperator, Scope: &apiv1.AgentScope{Tags: []string{"db"}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bot := newAgentClients(http.DefaultClient, env.srv.URL, func(h http.Header) { h.Set("Authorization", "Bearer "+key.Msg.GetSecret()) })
	if l, _ := bot.fleet.ListAgents(ctx, connect.NewRequest(&apiv1.ListAgentsRequest{})); len(l.Msg.GetAgents()) != 0 {
		t.Fatal("out-of-scope agent listed")
	}
	if _, err := bot.fleet.GetAgent(ctx, connect.NewRequest(&apiv1.GetAgentRequest{AgentId: agentID})); code(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope agent visible: %v", err)
	}
	upgrade := &agentv1.Operation{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{}}}
	if _, err := bot.host.RunOperation(ctx, connect.NewRequest(&apiv1.RunOperationRequest{AgentId: agentID, Operation: upgrade})); code(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope operation: %v", err)
	}
	if _, err := oc.fleet.UpdateAgent(ctx, connect.NewRequest(&apiv1.UpdateAgentRequest{
		AgentId: agentID, Tags: &apiv1.TagList{Tags: []string{"web", "db"}},
	})); err != nil {
		t.Fatal(err)
	}
	run, err := bot.host.RunOperation(ctx, connect.NewRequest(&apiv1.RunOperationRequest{AgentId: agentID, Operation: upgrade}))
	if err != nil {
		t.Fatal(err)
	}
	cmd := run.Msg.GetCommand()
	if cmd.GetOperationType() != "packages_upgrade" || cmd.GetStatus() != "Queued until the agent connects" || cmd.GetIssuer().GetKind() != apiv1.PrincipalRef_KIND_API_KEY {
		t.Fatalf("command: %v", cmd)
	}
	exec := &agentv1.Operation{Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{Argv: []string{"/bin/id"}}}}
	if _, err := bot.host.RunOperation(ctx, connect.NewRequest(&apiv1.RunOperationRequest{AgentId: agentID, Operation: exec})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator exec: %v", err)
	}
	history, err := bot.host.ListCommands(ctx, connect.NewRequest(&apiv1.ListCommandsRequest{AgentId: agentID}))
	if err != nil || len(history.Msg.GetCommands()) != 1 {
		t.Fatalf("history: %v %v", history, err)
	}
	if _, err := bot.host.CancelCommand(ctx, connect.NewRequest(&apiv1.CancelCommandRequest{CommandId: cmd.GetCommandId()})); err != nil {
		t.Fatal(err)
	}
	orgID := env.app.Fleet.All(ownerOrg(t, env), nil)[0].Agent.OrgID
	if got, err := env.app.Dispatch.Get(ctx, orgID, cmd.GetCommandId()); err != nil || got.State != store.CommandCancelled {
		t.Fatalf("cancelled command: %+v %v", got, err)
	}
	// API keys cannot manage groups (org-wide agents.manage needed) or approve enrollments.
	if _, err := bot.fleet.CreateGroup(ctx, connect.NewRequest(&apiv1.CreateGroupRequest{Name: "db"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped key created a group: %v", err)
	}
	if _, err := bot.enroll.ListEnrollmentRequests(ctx, connect.NewRequest(&apiv1.ListEnrollmentRequestsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator listed enrollment requests: %v", err)
	}
	if m, err := bot.metrics.GetAgentMetrics(ctx, connect.NewRequest(&apiv1.GetAgentMetricsRequest{AgentId: agentID})); err != nil ||
		m.Msg.GetSeries().GetResolution() != apiv1.MetricsResolution_METRICS_RESOLUTION_RAW {
		t.Fatalf("metrics: %v %v", m, err)
	}

	// Seeing what a command did needs its operation's permission: the operator key (no
	// files.read) sees that a file was read on its agent, but not which file or its contents.
	readFile := &agentv1.Operation{Kind: &agentv1.Operation_FileRead{FileRead: &agentv1.FileRead{Path: "/etc/hostname"}}}
	fr, err := oc.host.RunOperation(ctx, connect.NewRequest(&apiv1.RunOperationRequest{
		AgentId: agentID, Operation: readFile, Wait: durationpb.New(0),
	}))
	if err != nil {
		t.Fatal(err)
	}
	readID := fr.Msg.GetCommand().GetCommandId()
	find := func(c agentClients) *apiv1.CommandRecord {
		t.Helper()
		h, err := c.host.ListCommands(ctx, connect.NewRequest(&apiv1.ListCommandsRequest{AgentId: agentID}))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range h.Msg.GetCommands() {
			if r.GetCommandId() == readID {
				return r
			}
		}
		t.Fatal("command not listed")
		return nil
	}
	if r := find(bot); r.GetOperationType() != "file_read" || r.GetOperation() != nil || r.GetResult() != nil {
		t.Fatalf("operator sees file_read details: %v", r)
	}
	if r := find(oc); r.GetOperation().GetFileRead().GetPath() != "/etc/hostname" {
		t.Fatalf("owner misses file_read details: %v", r)
	}
	botWatch, err := bot.host.WatchCommand(ctx, connect.NewRequest(&apiv1.WatchCommandRequest{CommandId: readID}))
	if err != nil {
		t.Fatal(err)
	}
	if botWatch.Receive() || code(botWatch.Err()) != connect.CodePermissionDenied {
		t.Fatalf("operator watched file_read output: %v", botWatch.Err())
	}
	_ = botWatch.Close()
	ownerWatch, err := oc.host.WatchCommand(ctx, connect.NewRequest(&apiv1.WatchCommandRequest{CommandId: readID}))
	if err != nil {
		t.Fatal(err)
	}
	if !ownerWatch.Receive() || ownerWatch.Msg().GetUpdate().GetCommandId() != readID {
		t.Fatalf("owner watch: %v", ownerWatch.Err())
	}
	_ = ownerWatch.Close()
	if _, err := bot.host.CancelCommand(ctx, connect.NewRequest(&apiv1.CancelCommandRequest{CommandId: readID})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator cancelled file_read: %v", err)
	}

	// Summary, then revocation (step-up) removes the agent from the default list.
	sum, _ := oc.fleet.GetFleetSummary(ctx, connect.NewRequest(&apiv1.GetFleetSummaryRequest{}))
	if sum.Msg.GetSummary().GetTotal() != 1 || sum.Msg.GetSummary().GetOffline() != 1 {
		t.Fatalf("summary: %v", sum.Msg)
	}
	if _, err := oc.fleet.RevokeAgent(ctx, connect.NewRequest(&apiv1.RevokeAgentRequest{AgentId: agentID, Reason: "decommissioned"})); err != nil {
		t.Fatal(err)
	}
	if l, _ := oc.fleet.ListAgents(ctx, connect.NewRequest(&apiv1.ListAgentsRequest{})); len(l.Msg.GetAgents()) != 0 {
		t.Fatal("revoked agent listed by default")
	}
	events, _ := owner.audit.ListAuditEvents(ctx, connect.NewRequest(&apiv1.ListAuditEventsRequest{ActionPrefix: "agent."}))
	var actions []string
	for _, e := range events.Msg.GetEvents() {
		actions = append(actions, e.GetAction())
	}
	for _, want := range []string{"agent.approved", "agent.updated", "agent.revoked"} {
		if !contains(actions, want) {
			t.Errorf("audit log misses %s: %v", want, actions)
		}
	}
}

// ownerOrg returns the organization created by the setup wizard.
func ownerOrg(t *testing.T, env *testEnv) string {
	t.Helper()
	orgs, err := env.app.Holder.Get().Orgs.All(context.Background(), store.System(), store.Query{})
	if err != nil || len(orgs) != 1 {
		t.Fatalf("orgs: %v %v", orgs, err)
	}
	return orgs[0].ID
}

// A member whose roles are scoped by tags must not be able to re-tag an agent into the scope
// of a more powerful binding they hold elsewhere.
func TestRetaggingCannotEscalate(t *testing.T) {
	ctx := context.Background()
	env := completeSetup(t)
	owner, _ := enrollTOTP(t, env, "owner@example.com", ownerPassword)
	oc := owner.agents()
	tok, err := oc.enroll.CreateEnrollmentToken(ctx, connect.NewRequest(&apiv1.CreateEnrollmentTokenRequest{Name: "t", MaxUses: 2}))
	if err != nil {
		t.Fatal(err)
	}
	res := simulateEnroll(t, env, tok.Msg.GetEnrollmentKey(), "web-1", strings.Repeat("b", 32))
	ap, err := oc.enroll.ApproveEnrollmentRequest(ctx, connect.NewRequest(&apiv1.ApproveEnrollmentRequestRequest{
		RequestId: res.Request.ID, PairingCode: res.Request.PairingCode, Tags: []string{"web"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	agentID := ap.Msg.GetRequest().GetAgentId()

	// Org-wide roles cannot be scoped (the request is refused rather than silently widened).
	if _, err := owner.mem.InviteMember(ctx, connect.NewRequest(&apiv1.InviteMemberRequest{
		Email: "sam@example.com", RoleBindings: []*apiv1.RoleBinding{
			{RoleId: authz.RoleAdmin, Scope: &apiv1.AgentScope{Tags: []string{"db"}}},
		},
	})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("scoped admin binding: %v", err)
	}
	// A custom role with shell access, bound only to "db" agents.
	if err := env.app.Holder.Get().Roles.Create(ctx, store.Tenant(ownerOrg(t, env)), &store.Role{
		ID: "shell", OrgID: ownerOrg(t, env), Name: "Shell", Permissions: []string{authz.FleetView, authz.ExecRun},
	}); err != nil {
		t.Fatal(err)
	}
	inv, err := owner.mem.InviteMember(ctx, connect.NewRequest(&apiv1.InviteMemberRequest{
		Email: "sam@example.com", RoleBindings: []*apiv1.RoleBinding{
			{RoleId: authz.RoleOperator, Scope: &apiv1.AgentScope{Tags: []string{"web"}}},
			{RoleId: "shell", Scope: &apiv1.AgentScope{Tags: []string{"db"}}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	link := inv.Msg.GetInviteUrl()
	anon := newBrowser(t, env.srv.URL)
	if _, err := anon.auth.AcceptInvite(ctx, connect.NewRequest(&apiv1.AcceptInviteRequest{
		InviteToken: link[strings.Index(link, "#")+1:], DisplayName: "Sam", Password: "quiet-harbor-maple-93",
	})); err != nil {
		t.Fatal(err)
	}
	sam, _ := enrollTOTP(t, env, "sam@example.com", "quiet-harbor-maple-93")
	sc := sam.agents()
	if _, err := sc.fleet.UpdateAgent(ctx, connect.NewRequest(&apiv1.UpdateAgentRequest{
		AgentId: agentID, Tags: &apiv1.TagList{Tags: []string{"web", "db"}},
	})); code(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "additional permissions") {
		t.Fatalf("escalating re-tag: %v", err)
	}
	name := "web-1 (renamed)"
	if _, err := sc.fleet.UpdateAgent(ctx, connect.NewRequest(&apiv1.UpdateAgentRequest{AgentId: agentID, Name: &name})); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// The operator binding does not include exec, and the shell binding does not cover web agents.
	exec := &agentv1.Operation{Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{Argv: []string{"/bin/id"}}}}
	if _, err := sc.host.RunOperation(ctx, connect.NewRequest(&apiv1.RunOperationRequest{AgentId: agentID, Operation: exec})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("exec through the wrong scope: %v", err)
	}
}

func TestDiscoveryAndInstallScript(t *testing.T) {
	env := completeSetup(t)
	res, err := http.Get(env.srv.URL + "/.well-known/central-agent.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	_ = json.NewDecoder(res.Body).Decode(&doc)
	_ = res.Body.Close()
	if doc["agent_url"] != "https://localhost:9443" || doc["ca_pin"] != env.app.PKI.Pin() {
		t.Fatalf("discovery: %v", doc)
	}
	res, err = http.Get(env.srv.URL + "/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(body), "AGENT_URL='https://localhost:9443'") || !strings.HasPrefix(string(body), "#!/usr/bin/env bash") {
		t.Fatalf("script header: %.300s", body)
	}
	checkShellSyntax(t, string(body))

	// Values are quoted: an agent URL cannot break out of its assignment.
	evil := renderInstallScript("https://x'; touch /tmp/pwned; echo '", "https://releases.example.com/", []byte{1, 2, 3})
	if !strings.Contains(evil, `AGENT_URL='https://x'\''; touch /tmp/pwned; echo '\'''`) ||
		!strings.Contains(evil, "RELEASE_URL='https://releases.example.com'") || !strings.Contains(evil, "RELEASE_KEY_B64='AQID'") {
		t.Fatalf("quoting: %.600s", evil)
	}
	checkShellSyntax(t, evil)
}

func checkShellSyntax(t *testing.T, script string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command(bash, "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

func TestDearmor(t *testing.T) {
	raw := []byte("pretend this is an OpenPGP key packet")
	armored := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n" +
		base64.StdEncoding.EncodeToString(raw)[:20] + "\n" + base64.StdEncoding.EncodeToString(raw)[20:] +
		"\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"
	got, err := dearmor(armored)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("dearmor: %q %v", got, err)
	}
	if _, err := dearmor("not armored"); err == nil {
		t.Fatal("accepted garbage")
	}
}
