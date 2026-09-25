// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/agentsim"
)

// TestSimulatedFleet enrolls a fleet of simulated hosts with an auto-approval token and checks
// telemetry, inventory, policy enforcement and a fleet-wide job. CENTRAL_SIM_AGENTS=1000 turns
// it into a load test that reports memory use and command dispatch latency.
func TestSimulatedFleet(t *testing.T) {
	n := 20
	if v, err := strconv.Atoi(os.Getenv("CENTRAL_SIM_AGENTS")); err == nil && v > 0 {
		n = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	env := completeSetup(t)
	agentURL := startGateway(t, env)
	owner, _ := enrollTOTP(t, env, "owner@example.com", ownerPassword)
	oc := owner.agents()
	tok, err := oc.enroll.CreateEnrollmentToken(ctx, connect.NewRequest(&apiv1.CreateEnrollmentTokenRequest{
		Name: "sim", ApprovalMode: apiv1.ApprovalMode_APPROVAL_MODE_AUTO, MaxUses: uint32(n), ExpiresIn: durationpb.New(time.Hour),
		DefaultTags: []string{"sim"},
	}))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	runCtx, stopAgents := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { stopAgents(); wg.Wait() }()
	sem := make(chan struct{}, 32)
	var mu sync.Mutex
	var latencies []time.Duration
	for i := range n {
		name := fmt.Sprintf("sim-%04d", i+1)
		profile := agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER
		if i%5 == 4 {
			profile = agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE // cannot upgrade packages
		}
		h := agentsim.NewHost(name, uint64(i)+1, profile)
		wg.Go(func() {
			sem <- struct{}{}
			e, err := agentsim.Enroll(runCtx, agentsim.EnrollOptions{AgentURL: agentURL, Key: tok.Msg.GetEnrollmentKey(), Facts: h.Facts()})
			if err != nil {
				<-sem
				t.Errorf("%s enroll: %v", name, err)
				return
			}
			a, err := e.Wait(runCtx)
			<-sem
			if err != nil {
				t.Errorf("%s wait: %v", name, err)
				return
			}
			a.Facts, a.Policy = h.Facts(), h.Policy
			handler := func(ctx context.Context, conn *agentsim.Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
				mu.Lock()
				latencies = append(latencies, time.Since(cmd.GetIssuedAt().AsTime()))
				mu.Unlock()
				return h.Handle(ctx, conn, cmd)
			}
			_ = a.Run(runCtx, handler, func(c *agentsim.Conn) {
				h.SendInventory(c)
				_ = c.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricsReport{
					Samples: []*agentv1.MetricsSample{h.Sample(time.Now())},
				}}})
			})
		})
	}
	fc := oc.fleet
	waitFor := func(what string, timeout time.Duration, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitFor("all agents online with metrics", 5*time.Minute, func() bool {
		s, err := fc.GetFleetSummary(ctx, connect.NewRequest(&apiv1.GetFleetSummaryRequest{}))
		if err != nil || s.Msg.GetSummary().GetOnline() != uint32(n) {
			return false
		}
		l, err := fc.ListAgents(ctx, connect.NewRequest(&apiv1.ListAgentsRequest{Page: &apiv1.PageRequest{PageSize: 500}}))
		return err == nil && slices.ContainsFunc(l.Msg.GetAgents(), func(a *apiv1.AgentSummary) bool { return a.GetCpuPercent() > 0 })
	})
	online := time.Since(start)
	sum, _ := fc.GetFleetSummary(ctx, connect.NewRequest(&apiv1.GetFleetSummaryRequest{}))
	if sum.Msg.GetSummary().GetTotalUpdates() == 0 || sum.Msg.GetSummary().GetAgentsWithUpdates() == 0 {
		t.Fatalf("inventory did not reach the summary: %v", sum.Msg.GetSummary())
	}

	// A fleet-wide security upgrade: observe-profile hosts refuse it (policy), the rest succeed.
	jc := apiv1connect.NewJobServiceClient(owner.hc, env.srv.URL+"/api", connect.WithInterceptors(csrfInterceptor(owner)))
	res, err := jc.CreateJob(ctx, connect.NewRequest(&apiv1.CreateJobRequest{
		Name: "security updates", ConfirmTargetCount: uint32(n),
		Operation: &agentv1.Operation{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{SecurityOnly: true}}},
		Selector:  &apiv1.TargetSelector{Tags: []string{"sim"}},
		Rollout:   &apiv1.RolloutStrategy{BatchSize: uint32(max(n/4, 1)), MaxFailurePercent: 100},
	}))
	if err != nil {
		t.Fatal(err)
	}
	jobStart := time.Now()
	var job *apiv1.Job
	waitFor("job finished", 5*time.Minute, func() bool {
		j, err := jc.GetJob(ctx, connect.NewRequest(&apiv1.GetJobRequest{JobId: res.Msg.GetJob().GetId()}))
		if err != nil {
			return false
		}
		job = j.Msg.GetJob()
		return job.GetState() != apiv1.JobState_JOB_STATE_RUNNING && job.GetState() != apiv1.JobState_JOB_STATE_PENDING
	})
	observe := uint32(n / 5)
	c := job.GetCounts()
	if c.GetRejected() != observe || c.GetSucceeded() != uint32(n)-observe || job.GetState() != apiv1.JobState_JOB_STATE_PARTIALLY_FAILED {
		t.Fatalf("job: %v %v", job.GetState(), c)
	}
	// After the upgrade the hosts re-report updates without security fixes.
	waitFor("security updates cleared", time.Minute, func() bool {
		s, err := fc.GetFleetSummary(ctx, connect.NewRequest(&apiv1.GetFleetSummaryRequest{}))
		return err == nil && s.Msg.GetSummary().GetAgentsWithSecurityUpdates() <= observe
	})

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	mu.Lock()
	slices.Sort(latencies)
	p := func(q float64) time.Duration { return latencies[min(len(latencies)-1, int(q*float64(len(latencies))))] }
	t.Logf("%d agents online in %s; job over %d agents took %s; dispatch latency p50=%s p99=%s; heap in use %d MiB (test process: Central + simulated agents)",
		n, online.Round(time.Millisecond), n, time.Since(jobStart).Round(time.Millisecond), p(0.5).Round(time.Microsecond),
		p(0.99).Round(time.Microsecond), ms.HeapInuse>>20)
	mu.Unlock()
}
