// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package jobs runs one operation across many agents with a controlled rollout: batches, a
// concurrency limit, a failure threshold that aborts the job, a pause between batches and
// cancellation. Each target gets its own signed command through the dispatcher, so every
// command is individually verified and policy-checked by its agent.
//
// The operation (which may contain secrets) lives only in memory while the job runs; the
// stored job holds the redacted copy. A Central restart therefore aborts running jobs rather
// than resuming them with incomplete data.
package jobs

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/ops"
	"github.com/Shaalan15/central/server/internal/store"
)

// Limits.
const (
	DefaultTTL        = time.Hour
	MaxRunningPerOrg  = 20
	MaxTargets        = 10_000
	maxBatchDelay     = 24 * time.Hour
	persistJobEvery   = time.Second
	waitGrace         = time.Hour + 5*time.Minute // beyond the dispatcher's own give-up
	pollCommandsEvery = 2 * time.Second
)

// StateSkipped marks executions that were not attempted.
const StateSkipped = "skipped"

// Errors.
var (
	ErrTooMany  = errors.New("jobs: too many jobs are running in this organization")
	ErrNotFound = errors.New("jobs: job not found")
	ErrFinished = errors.New("jobs: the job has already finished")

	// errUserCancel distinguishes CancelJob from a Central shutdown: only the former cancels
	// commands that are already running on agents.
	errUserCancel = errors.New("jobs: cancelled by a user")
)

// Event is published on bus.JobTopic(id).
type Event struct {
	Job       store.Job
	Execution *store.JobExecution
}

// Selector resolves targets.
type Selector = store.TargetSelectorSpec

// Matches reports whether an agent is selected. Agents matching any of AgentIDs, or all of
// Tags and any of GroupIDs (when either is given), are selected; AllAgents selects all.
func Matches(sel Selector, v *fleet.View) bool {
	if !v.Active() {
		return false
	}
	if sel.AllAgents || slices.Contains(sel.AgentIDs, v.Agent.ID) {
		return true
	}
	if len(sel.Tags) == 0 && len(sel.GroupIDs) == 0 {
		return false
	}
	for _, t := range sel.Tags {
		if !slices.Contains(v.Agent.Tags, t) {
			return false
		}
	}
	return len(sel.GroupIDs) == 0 || slices.Contains(sel.GroupIDs, v.Agent.GroupID)
}

// Spec is a job to start.
type Spec struct {
	OrgID      string
	Name       string
	Operation  *agentv1.Operation
	Targets    []fleet.View
	Selector   Selector
	Rollout    store.RolloutSpec
	CommandTTL time.Duration
	Issuer     store.PrincipalRef
	SourceIP   string
}

type run struct {
	job    store.Job
	op     *agentv1.Operation
	execs  []*store.JobExecution
	cancel context.CancelCauseFunc
	issuer store.PrincipalRef
	ip     string
	online bool
	saved  time.Time
}

// Runner executes jobs.
type Runner struct {
	holder   *store.Holder
	fleet    *fleet.Index
	dispatch *dispatch.Dispatcher
	bus      bus.Bus
	log      *slog.Logger

	mu   sync.Mutex
	runs map[string]*run
	wg   sync.WaitGroup
	base context.Context
}

// New returns a runner. Jobs run under base (cancelled at shutdown).
func New(base context.Context, holder *store.Holder, fl *fleet.Index, d *dispatch.Dispatcher, b bus.Bus, log *slog.Logger) *Runner {
	return &Runner{holder: holder, fleet: fl, dispatch: d, bus: b, log: log, runs: map[string]*run{}, base: base}
}

// Wait blocks until running jobs have stopped (after base is cancelled).
func (r *Runner) Wait() { r.wg.Wait() }

func (r *Runner) st() (*store.Store, error) {
	st := r.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	return st, nil
}

// Start validates and launches a job. Authorization is the caller's responsibility.
func (r *Runner) Start(ctx context.Context, spec Spec) (store.Job, error) { //nolint:contextcheck // jobs outlive the request that started them
	info, err := ops.Describe(spec.Operation)
	if err != nil {
		return store.Job{}, err
	}
	if info.Session {
		return store.Job{}, errors.New(info.Type + " cannot run as a fleet job")
	}
	if err := ops.Validate(spec.Operation); err != nil {
		return store.Job{}, err
	}
	if len(spec.Targets) == 0 {
		return store.Job{}, errors.New("the selector matches no agents")
	}
	if len(spec.Targets) > MaxTargets {
		return store.Job{}, errors.New("too many targets")
	}
	st, err := r.st()
	if err != nil {
		return store.Job{}, err
	}
	ro := spec.Rollout
	if ro.BatchSize <= 0 || ro.BatchSize > len(spec.Targets) {
		ro.BatchSize = len(spec.Targets)
	}
	if ro.MaxConcurrency <= 0 || ro.MaxConcurrency > ro.BatchSize {
		ro.MaxConcurrency = ro.BatchSize
	}
	ro.MaxFailurePercent = min(max(ro.MaxFailurePercent, 0), 100)
	ro.BatchDelaySec = min(max(ro.BatchDelaySec, 0), int(maxBatchDelay.Seconds()))
	ttl := spec.CommandTTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	ttl = min(max(ttl, dispatch.MinTTL), dispatch.MaxTTL)
	redacted, err := proto.Marshal(ops.Redact(spec.Operation))
	if err != nil {
		return store.Job{}, err
	}

	r.mu.Lock()
	n := 0
	for _, x := range r.runs {
		if x.job.OrgID == spec.OrgID {
			n++
		}
	}
	r.mu.Unlock()
	if n >= MaxRunningPerOrg {
		return store.Job{}, ErrTooMany
	}

	now := time.Now().UTC()
	job := store.Job{
		ID: store.NewID(), OrgID: spec.OrgID, Name: spec.Name, OperationType: info.Type, OperationProto: redacted,
		Selector: spec.Selector, Rollout: ro, State: store.JobPending, CreatedBy: spec.Issuer,
		CommandTTLSec: int(ttl.Seconds()), CreatedAt: now,
	}
	job.Counts = store.JobCounts{Total: len(spec.Targets), Pending: len(spec.Targets)}
	if err := st.Jobs.Create(ctx, store.Tenant(spec.OrgID), &job); err != nil {
		return store.Job{}, err
	}
	x := &run{job: job, op: spec.Operation, issuer: spec.Issuer, ip: spec.SourceIP, online: spec.Selector.OnlineOnly}
	for i, v := range spec.Targets {
		e := &store.JobExecution{
			ID: store.DeriveID(job.ID, v.Agent.ID), OrgID: spec.OrgID, JobID: job.ID, AgentID: v.Agent.ID,
			AgentName: v.Agent.Name, State: store.CommandQueued, Batch: i / ro.BatchSize,
		}
		if err := st.JobExecutions.Create(ctx, store.Tenant(spec.OrgID), e); err != nil {
			return store.Job{}, err
		}
		x.execs = append(x.execs, e)
	}
	runCtx, cancel := context.WithCancelCause(r.base)
	x.cancel = cancel
	r.mu.Lock()
	r.runs[job.ID] = x
	r.mu.Unlock()
	r.wg.Go(func() { r.execute(runCtx, x) })
	return job, nil
}

// execState maps a finished command to the execution's state.
func execState(c store.Command) string {
	switch c.State {
	case store.CommandSucceeded, store.CommandRejected, store.CommandCancelled:
		return c.State
	}
	return store.CommandFailed
}

func (r *Runner) recount(x *run) {
	c := store.JobCounts{Total: len(x.execs)}
	for _, e := range x.execs {
		switch e.State {
		case store.CommandQueued:
			c.Pending++
		case store.CommandSucceeded:
			c.Succeeded++
		case store.CommandFailed:
			c.Failed++
		case store.CommandRejected:
			c.Rejected++
		case store.CommandCancelled, StateSkipped:
			c.Skipped++
		default:
			c.Running++
		}
	}
	x.job.Counts = c
}

// save persists an execution (if given) and, at most once a second, the job.
func (r *Runner) save(ctx context.Context, x *run, e *store.JobExecution, force bool) {
	st := r.holder.Get()
	if st == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	r.mu.Lock()
	r.recount(x)
	job := x.job
	var exec *store.JobExecution
	if e != nil {
		cp := *e
		exec = &cp
	}
	persistJob := force || time.Since(x.saved) >= persistJobEvery
	if persistJob {
		x.saved = time.Now()
	}
	r.mu.Unlock()
	if exec != nil {
		if err := st.JobExecutions.Update(ctx, store.Tenant(job.OrgID), exec); err != nil {
			r.log.Warn("jobs: saving execution failed", "job", job.ID, "agent", exec.AgentID, "error", err)
		}
	}
	if persistJob {
		if err := st.Jobs.Update(ctx, store.Tenant(job.OrgID), &job); err != nil {
			r.log.Warn("jobs: saving job failed", "job", job.ID, "error", err)
		}
	}
	if r.bus != nil {
		r.bus.Publish(bus.JobTopic(job.ID), Event{Job: job, Execution: exec})
	}
}

func (r *Runner) execute(ctx context.Context, x *run) {
	defer func() {
		r.mu.Lock()
		delete(r.runs, x.job.ID)
		r.mu.Unlock()
		x.cancel(nil)
	}()
	r.mu.Lock()
	x.job.State, x.job.StartedAt = store.JobRunning, time.Now().UTC()
	r.mu.Unlock()
	r.save(ctx, x, nil, true)

	stopped := func() string {
		if errors.Is(context.Cause(ctx), errUserCancel) {
			return store.JobCancelled
		}
		return store.JobAborted // Central is shutting down
	}
	final := store.JobSucceeded
	batches := 0
	for _, e := range x.execs {
		batches = max(batches, e.Batch+1)
	}
	for b := range batches {
		if ctx.Err() != nil {
			final = stopped()
			break
		}
		var batch []*store.JobExecution
		for _, e := range x.execs {
			if e.Batch == b {
				batch = append(batch, e)
			}
		}
		r.runBatch(ctx, x, batch)
		if ctx.Err() != nil {
			final = stopped()
			break
		}
		if r.overThreshold(x) {
			final = store.JobAborted
			break
		}
		if b < batches-1 && x.job.Rollout.BatchDelaySec > 0 {
			select {
			case <-time.After(time.Duration(x.job.Rollout.BatchDelaySec) * time.Second):
			case <-ctx.Done():
			}
		}
	}
	// Anything not attempted is skipped.
	r.mu.Lock()
	var skipped []*store.JobExecution
	for _, e := range x.execs {
		if e.State == store.CommandQueued {
			e.State, e.ErrorCode, e.ErrorMessage = StateSkipped, final, "not attempted: the job was "+final
			skipped = append(skipped, e)
		}
	}
	if final == store.JobSucceeded {
		r.recount(x)
		if x.job.Counts.Failed+x.job.Counts.Rejected > 0 {
			final = store.JobPartiallyFailed
		}
	}
	x.job.State, x.job.FinishedAt = final, time.Now().UTC()
	r.mu.Unlock()
	for _, e := range skipped {
		r.save(ctx, x, e, false)
	}
	r.save(ctx, x, nil, true)
}

// overThreshold reports whether the failure rate among finished executions exceeds the limit.
func (r *Runner) overThreshold(x *run) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recount(x)
	c := x.job.Counts
	done := c.Succeeded + c.Failed + c.Rejected
	if done == 0 || x.job.Rollout.MaxFailurePercent >= 100 {
		return false
	}
	bad := c.Failed + c.Rejected
	if x.job.Rollout.MaxFailurePercent == 0 {
		return bad > 0
	}
	return bad*100 > x.job.Rollout.MaxFailurePercent*done
}

func (r *Runner) runBatch(ctx context.Context, x *run, batch []*store.JobExecution) {
	sem := make(chan struct{}, x.job.Rollout.MaxConcurrency)
	var wg sync.WaitGroup
	for _, e := range batch {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Go(func() {
			defer func() { <-sem }()
			r.runOne(ctx, x, e)
		})
	}
	wg.Wait()
}

func (r *Runner) runOne(ctx context.Context, x *run, e *store.JobExecution) {
	orgID := x.job.OrgID
	if x.online {
		if v, ok := r.fleet.Get(e.AgentID); !ok || !v.Online {
			r.mu.Lock()
			e.State, e.ErrorCode, e.ErrorMessage = StateSkipped, "offline", "the agent was offline when its batch started"
			r.mu.Unlock()
			r.save(ctx, x, e, false)
			return
		}
	}
	r.mu.Lock()
	e.StartedAt = time.Now().UTC()
	r.mu.Unlock()
	rec, err := r.dispatch.Submit(ctx, dispatch.Request{
		OrgID: orgID, AgentID: e.AgentID, JobID: x.job.ID, Operation: x.op, Issuer: x.issuer, SourceIP: x.ip,
		TTL: time.Duration(x.job.CommandTTLSec) * time.Second,
	})
	if err != nil {
		r.mu.Lock()
		e.FinishedAt = time.Now().UTC()
		switch {
		case errors.Is(err, dispatch.ErrPolicyDenied):
			e.State, e.ErrorCode, e.ErrorMessage = store.CommandRejected, "policy_denied", err.Error()
		case errors.Is(err, dispatch.ErrPaused):
			e.State, e.ErrorCode, e.ErrorMessage = store.CommandRejected, "paused", err.Error()
		default:
			e.State, e.ErrorCode, e.ErrorMessage = store.CommandFailed, "not_sent", err.Error()
		}
		r.mu.Unlock()
		r.save(ctx, x, e, false)
		return
	}
	r.mu.Lock()
	e.CommandID, e.State = rec.ID, store.CommandSent
	r.mu.Unlock()
	r.save(ctx, x, e, false)

	deadline := time.Now().Add(time.Duration(x.job.CommandTTLSec)*time.Second + waitGrace)
	for {
		c, err := r.dispatch.Wait(ctx, orgID, rec.ID, pollCommandsEvery)
		if err == nil && c.Terminal() {
			r.mu.Lock()
			e.State, e.ErrorCode, e.ErrorMessage, e.FinishedAt = execState(c), c.ErrorCode, c.ErrorMessage, time.Now().UTC()
			r.mu.Unlock()
			r.save(ctx, x, e, false)
			return
		}
		if err == nil && c.State != e.State {
			r.mu.Lock()
			e.State = c.State
			r.mu.Unlock()
			r.save(ctx, x, e, false)
		}
		if ctx.Err() != nil && !errors.Is(context.Cause(ctx), errUserCancel) {
			return // shutdown: the agent keeps running the command; its record stays in history
		}
		if ctx.Err() != nil {
			// Cancelled by a user: ask the agent to stop and record the outcome as cancelled.
			_ = r.dispatch.Cancel(context.WithoutCancel(ctx), orgID, rec.ID)
			r.mu.Lock()
			e.State, e.ErrorCode, e.ErrorMessage, e.FinishedAt = store.CommandCancelled, "cancelled", "the job was cancelled", time.Now().UTC()
			r.mu.Unlock()
			r.save(ctx, x, e, false)
			return
		}
		if time.Now().After(deadline) {
			r.mu.Lock()
			e.State, e.ErrorCode, e.ErrorMessage, e.FinishedAt = store.CommandFailed, "timeout", "no result before the job's deadline", time.Now().UTC()
			r.mu.Unlock()
			r.save(ctx, x, e, false)
			return
		}
	}
}

// Cancel stops a running job.
func (r *Runner) Cancel(orgID, jobID string) error {
	r.mu.Lock()
	x := r.runs[jobID]
	r.mu.Unlock()
	if x == nil || x.job.OrgID != orgID {
		return ErrFinished
	}
	x.cancel(errUserCancel)
	return nil
}

// Live returns a running job's in-memory record.
func (r *Runner) Live(orgID, jobID string) (store.Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x := r.runs[jobID]
	if x == nil || x.job.OrgID != orgID {
		return store.Job{}, false
	}
	return x.job, true
}

// Recover aborts jobs left running by a previous process.
func (r *Runner) Recover(ctx context.Context) error {
	st, err := r.st()
	if err != nil {
		return err
	}
	for _, state := range []string{store.JobPending, store.JobRunning} {
		jobs, _, err := st.Jobs.Find(ctx, store.System(), store.Eq("state", state).Page(store.MaxLimit, ""))
		if err != nil {
			return err
		}
		for _, j := range jobs {
			execs, err := st.JobExecutions.All(ctx, store.Tenant(j.OrgID), store.Eq("job_id", j.ID))
			if err != nil {
				return err
			}
			x := &run{job: *j, execs: execs}
			for _, e := range execs {
				if e.State == store.CommandQueued {
					e.State, e.ErrorCode, e.ErrorMessage = StateSkipped, store.JobAborted, "not attempted: Central restarted"
					_ = st.JobExecutions.Update(ctx, store.Tenant(j.OrgID), e)
				}
			}
			r.recount(x)
			x.job.State, x.job.FinishedAt = store.JobAborted, time.Now().UTC()
			if err := st.Jobs.Update(ctx, store.Tenant(j.OrgID), &x.job); err != nil {
				return err
			}
		}
	}
	return nil
}
