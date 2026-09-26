// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/jobs"
	"github.com/Shaalan15/central/server/internal/ops"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/terminal"
	"github.com/Shaalan15/central/server/internal/validate"
)

// JobService implements JobService.
type JobService struct {
	apiv1connect.UnimplementedJobServiceHandler
	D *Deps
}

// ReasonConfirmCount asks the client to confirm the number of targets.
const ReasonConfirmCount = "confirm_target_count"

var jobStates = map[string]apiv1.JobState{
	store.JobPending:         apiv1.JobState_JOB_STATE_PENDING,
	store.JobRunning:         apiv1.JobState_JOB_STATE_RUNNING,
	store.JobSucceeded:       apiv1.JobState_JOB_STATE_SUCCEEDED,
	store.JobPartiallyFailed: apiv1.JobState_JOB_STATE_PARTIALLY_FAILED,
	store.JobAborted:         apiv1.JobState_JOB_STATE_ABORTED,
	store.JobCancelled:       apiv1.JobState_JOB_STATE_CANCELLED,
}

func u32(n int) uint32 { return uint32(max(n, 0)) } //nolint:gosec // non-negative counts

func jobProto(j *store.Job) *apiv1.Job {
	out := &apiv1.Job{
		Id: j.ID, Name: j.Name, OperationType: j.OperationType, State: jobStates[j.State],
		Selector: &apiv1.TargetSelector{
			AgentIds: j.Selector.AgentIDs, Tags: j.Selector.Tags, GroupIds: j.Selector.GroupIDs,
			AllAgents: j.Selector.AllAgents, OnlineOnly: j.Selector.OnlineOnly,
		},
		Rollout: &apiv1.RolloutStrategy{
			BatchSize: u32(j.Rollout.BatchSize), MaxConcurrency: u32(j.Rollout.MaxConcurrency),
			MaxFailurePercent: u32(j.Rollout.MaxFailurePercent), BatchDelay: dur(j.Rollout.BatchDelaySec),
		},
		Counts: &apiv1.JobCounts{
			Total: u32(j.Counts.Total), Pending: u32(j.Counts.Pending), Running: u32(j.Counts.Running),
			Succeeded: u32(j.Counts.Succeeded), Failed: u32(j.Counts.Failed), Rejected: u32(j.Counts.Rejected),
			Skipped: u32(j.Counts.Skipped),
		},
		CreatedBy: principalProto(j.CreatedBy), CreatedAt: ts(j.CreatedAt), StartedAt: ts(j.StartedAt),
		FinishedAt: ts(j.FinishedAt), CommandTtl: dur(j.CommandTTLSec),
	}
	if len(j.OperationProto) > 0 {
		op := &agentv1.Operation{}
		if proto.Unmarshal(j.OperationProto, op) == nil {
			out.Operation = op
		}
	}
	return out
}

func execProto(e *store.JobExecution) *apiv1.JobExecution {
	out := &apiv1.JobExecution{
		JobId: e.JobID, AgentId: e.AgentID, AgentName: e.AgentName, CommandId: e.CommandID,
		State: commandStates[e.State], Batch: u32(e.Batch), StartedAt: ts(e.StartedAt), FinishedAt: ts(e.FinishedAt),
		Skipped: e.State == jobs.StateSkipped,
	}
	if e.ErrorCode != "" || e.ErrorMessage != "" {
		out.Error = &agentv1.CommandError{Code: errorCodeProto(e.ErrorCode), Message: e.ErrorMessage}
	}
	return out
}

func selectorFromProto(s *apiv1.TargetSelector) (store.TargetSelectorSpec, error) {
	out := store.TargetSelectorSpec{AllAgents: s.GetAllAgents(), OnlineOnly: s.GetOnlineOnly(), GroupIDs: s.GetGroupIds()}
	if len(s.GetAgentIds()) > jobs.MaxTargets || len(s.GetGroupIds()) > 100 {
		return out, errors.New("too many agent or group IDs")
	}
	for _, id := range s.GetAgentIds() {
		if err := validate.ID("agent_id", id); err != nil {
			return out, err
		}
	}
	out.AgentIDs = s.GetAgentIds()
	for _, id := range s.GetGroupIds() {
		if err := validate.ID("group_id", id); err != nil {
			return out, err
		}
	}
	tags, err := validate.Tags(s.GetTags())
	if err != nil {
		return out, err
	}
	out.Tags = tags
	if !out.AllAgents && len(out.AgentIDs) == 0 && len(out.Tags) == 0 && len(out.GroupIDs) == 0 {
		return out, errors.New("the selector is empty: choose agents, tags, groups or all agents")
	}
	return out, nil
}

// targets resolves a selector to the agents the caller can see.
func (s *JobService) targets(p *authz.Principal, sel store.TargetSelectorSpec) []fleet.View {
	views := s.D.Fleet.All(p.OrgID, func(v *fleet.View) bool {
		return p.HasOnAgent(authz.FleetView, v.Ref()) && jobs.Matches(sel, v)
	})
	fleet.Sort(views, fleet.SortName, false)
	return views
}

// PreviewTargets implements JobService.
func (s *JobService) PreviewTargets(ctx context.Context, req *connect.Request[apiv1.PreviewTargetsRequest]) (*connect.Response[apiv1.PreviewTargetsResponse], error) {
	if _, err := s.D.Store(); err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, err
	}
	sel, err := selectorFromProto(req.Msg.GetSelector())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	views := s.targets(p, sel)
	out := &apiv1.PreviewTargetsResponse{Count: u32(len(views))}
	for i := range views {
		if views[i].Online {
			out.Online++
		}
		if i < 50 {
			out.SampleAgentIds = append(out.SampleAgentIds, views[i].Agent.ID)
			out.SampleAgentNames = append(out.SampleAgentNames, views[i].Agent.Name)
		}
	}
	return connect.NewResponse(out), nil
}

// CreateJob implements JobService.
func (s *JobService) CreateJob(ctx context.Context, req *connect.Request[apiv1.CreateJobRequest]) (*connect.Response[apiv1.CreateJobResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	m := req.Msg
	info, err := ops.Describe(m.GetOperation())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	p, err := authz.Require(ctx, authz.JobsRun)
	if err != nil {
		return nil, err
	}
	if _, err := authz.Require(ctx, info.Permission); err != nil {
		return nil, err
	}
	if info.Session || info.Disabled != "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s cannot run as a fleet job", info.Type))
	}
	if err := ops.Validate(m.GetOperation()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	sel, err := selectorFromProto(m.GetSelector())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	targets := s.targets(p, sel)
	if len(targets) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the selector matches no agents"))
	}
	// The caller needs the operation's permission (and jobs.run) on every target.
	missing := 0
	for i := range targets {
		ref := targets[i].Ref()
		if !p.HasOnAgent(info.Permission, ref) || !p.HasOnAgent(authz.JobsRun, ref) {
			missing++
		}
	}
	if missing > 0 {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf(
			"you lack %s or %s on %d of the %d selected agents", info.Permission, authz.JobsRun, missing, len(targets)))
	}
	threshold := store.DefaultOrgSettings().MassActionConfirmThreshold
	if org, err := st.Orgs.Get(ctx, store.System(), p.OrgID); err == nil && org.Settings.MassActionConfirmThreshold > 0 {
		threshold = org.Settings.MassActionConfirmThreshold
	}
	if len(targets) > threshold && int(m.GetConfirmTargetCount()) != len(targets) {
		return nil, reasonError(connect.CodeFailedPrecondition, ReasonConfirmCount,
			fmt.Errorf("this job targets %d agents: confirm by sending confirm_target_count=%d", len(targets), len(targets)))
	}
	name := m.GetName()
	if name == "" {
		name = info.Type
	}
	if name, err = validate.DisplayText("name", name, 100); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	ro := m.GetRollout()
	if ro.GetMaxFailurePercent() > 100 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("max_failure_percent must be 0-100"))
	}
	delay := 0
	if d := ro.GetBatchDelay(); d != nil && d.AsDuration() > 0 {
		if delay, err = boundSec(d, time.Second, 24*time.Hour, "batch_delay"); err != nil {
			return nil, err
		}
	}
	maxFail := 100
	if ro != nil {
		maxFail = int(ro.GetMaxFailurePercent())
	}
	ttl := time.Duration(0)
	if t := m.GetCommandTtl(); t != nil {
		ttl = t.AsDuration()
	}
	job, err := s.D.Jobs.Start(ctx, jobs.Spec{
		OrgID: p.OrgID, Name: name, Operation: m.GetOperation(), Targets: targets, Selector: sel,
		Rollout: store.RolloutSpec{
			BatchSize: int(ro.GetBatchSize()), MaxConcurrency: int(ro.GetMaxConcurrency()), MaxFailurePercent: maxFail,
			BatchDelaySec: delay,
		},
		CommandTTL: ttl, Issuer: p.Ref(), SourceIP: clientIP(ctx),
	})
	if errors.Is(err, jobs.ErrTooMany) {
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "job.created", TargetType: "job", TargetID: job.ID, TargetDisplay: name,
		Details: map[string]string{"operation": info.Type, "targets": strconv.Itoa(len(targets))},
	})
	return connect.NewResponse(&apiv1.CreateJobResponse{Job: jobProto(&job)}), nil
}

func (s *JobService) load(ctx context.Context, st *store.Store, orgID, id string) (*store.Job, error) {
	if live, ok := s.D.Jobs.Live(orgID, id); ok {
		return &live, nil
	}
	j, err := st.Jobs.Get(ctx, store.Tenant(orgID), id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("job not found"))
	}
	return j, nil
}

// ListJobs implements JobService.
func (s *JobService) ListJobs(ctx context.Context, req *connect.Request[apiv1.ListJobsRequest]) (*connect.Response[apiv1.ListJobsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.JobsView)
	if err != nil {
		return nil, err
	}
	size := int(min(max(req.Msg.GetPage().GetPageSize(), 1), 500))
	if req.Msg.GetPage().GetPageSize() == 0 {
		size = 50
	}
	q := store.Query{}.Order("created_at", true).Page(size, req.Msg.GetPage().GetPageToken())
	var states []string
	for _, js := range req.Msg.GetStates() {
		for name, v := range jobStates {
			if v == js {
				states = append(states, name)
			}
		}
	}
	if len(states) > 0 {
		q = q.And("state", store.OpIn, states)
	}
	rows, next, err := st.Jobs.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListJobsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	for _, j := range rows {
		if live, ok := s.D.Jobs.Live(p.OrgID, j.ID); ok {
			j = &live
		}
		out.Jobs = append(out.Jobs, jobProto(j))
	}
	return connect.NewResponse(out), nil
}

// GetJob implements JobService.
func (s *JobService) GetJob(ctx context.Context, req *connect.Request[apiv1.GetJobRequest]) (*connect.Response[apiv1.GetJobResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.JobsView)
	if err != nil {
		return nil, err
	}
	j, err := s.load(ctx, st, p.OrgID, req.Msg.GetJobId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.GetJobResponse{Job: jobProto(j)}), nil
}

// CancelJob implements JobService.
func (s *JobService) CancelJob(ctx context.Context, req *connect.Request[apiv1.CancelJobRequest]) (*connect.Response[apiv1.CancelJobResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.RequireHeld(ctx, authz.JobsRun)
	if err != nil {
		return nil, err
	}
	j, err := s.load(ctx, st, p.OrgID, req.Msg.GetJobId())
	if err != nil {
		return nil, err
	}
	if err := s.D.Jobs.Cancel(p.OrgID, j.ID); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "job.cancelled", TargetType: "job", TargetID: j.ID, TargetDisplay: j.Name})
	return connect.NewResponse(&apiv1.CancelJobResponse{Job: jobProto(j)}), nil
}

// ListJobExecutions implements JobService.
func (s *JobService) ListJobExecutions(ctx context.Context, req *connect.Request[apiv1.ListJobExecutionsRequest]) (*connect.Response[apiv1.ListJobExecutionsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.JobsView)
	if err != nil {
		return nil, err
	}
	if _, err := s.load(ctx, st, p.OrgID, req.Msg.GetJobId()); err != nil {
		return nil, err
	}
	size := int(min(max(req.Msg.GetPage().GetPageSize(), 1), 500))
	if req.Msg.GetPage().GetPageSize() == 0 {
		size = 100
	}
	q := store.Eq("job_id", req.Msg.GetJobId()).Order("batch", false).Page(size, req.Msg.GetPage().GetPageToken())
	var states []string
	for _, cs := range req.Msg.GetStates() {
		for name, v := range commandStates {
			if v == cs {
				states = append(states, name)
			}
		}
	}
	if len(states) > 0 {
		q = q.And("state", store.OpIn, states)
	}
	rows, next, err := st.JobExecutions.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListJobExecutionsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	for _, e := range rows {
		out.Executions = append(out.Executions, execProto(e))
	}
	return connect.NewResponse(out), nil
}

func jobFinished(state string) bool {
	return state != store.JobPending && state != store.JobRunning
}

// WatchJob implements JobService.
func (s *JobService) WatchJob(ctx context.Context, req *connect.Request[apiv1.WatchJobRequest], stream *connect.ServerStream[apiv1.WatchJobResponse]) error {
	st, err := s.D.Store()
	if err != nil {
		return err
	}
	p, err := authz.Require(ctx, authz.JobsView)
	if err != nil {
		return err
	}
	sub := s.D.Bus.Subscribe(bus.JobTopic(req.Msg.GetJobId()), 1024)
	defer sub.Close()
	j, err := s.load(ctx, st, p.OrgID, req.Msg.GetJobId())
	if err != nil {
		return err
	}
	if err := stream.Send(&apiv1.WatchJobResponse{Event: &apiv1.WatchJobResponse_Job{Job: jobProto(j)}}); err != nil {
		return err
	}
	if jobFinished(j.State) {
		return nil
	}
	recheck := time.NewTicker(streamRecheck)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-recheck.C:
			if p = s.D.refreshPrincipal(ctx, p); p == nil || !p.Has(authz.JobsView) {
				return errStreamAuth
			}
		case msg, ok := <-sub.C:
			if !ok {
				return nil
			}
			ev, ok := msg.(jobs.Event)
			if !ok || ev.Job.OrgID != p.OrgID {
				continue
			}
			if ev.Execution != nil {
				if err := stream.Send(&apiv1.WatchJobResponse{Event: &apiv1.WatchJobResponse_Execution{Execution: execProto(ev.Execution)}}); err != nil {
					return err
				}
			}
			if err := stream.Send(&apiv1.WatchJobResponse{Event: &apiv1.WatchJobResponse_Job{Job: jobProto(&ev.Job)}}); err != nil {
				return err
			}
			if jobFinished(ev.Job.State) {
				return nil
			}
		}
	}
}

// ---- Recordings ----

// RecordingService implements RecordingService.
type RecordingService struct {
	apiv1connect.UnimplementedRecordingServiceHandler
	D *Deps
}

func recordingProto(r *store.Recording) *apiv1.Recording {
	return &apiv1.Recording{
		Id: r.ID, AgentId: r.AgentID, AgentName: r.AgentName,
		User:  principalProto(store.PrincipalRef{Kind: store.PrincipalUser, ID: r.UserID, Display: r.UserDisplay}),
		RunAs: r.RunAs, Cols: u32(r.Cols), Rows: u32(r.Rows), StartedAt: ts(r.StartedAt), EndedAt: ts(r.EndedAt),
		OutputBytes: uint64(max(r.OutputBytes, 0)), ExitCode: int32(r.ExitCode), Truncated: r.Truncated, //nolint:gosec // bounded
	}
}

// ListRecordings implements RecordingService.
func (s *RecordingService) ListRecordings(ctx context.Context, req *connect.Request[apiv1.ListRecordingsRequest]) (*connect.Response[apiv1.ListRecordingsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.AuditView)
	if err != nil {
		return nil, err
	}
	size := int(min(max(req.Msg.GetPage().GetPageSize(), 1), 500))
	if req.Msg.GetPage().GetPageSize() == 0 {
		size = 50
	}
	q := store.Query{}.Order("started_at", true).Page(size, req.Msg.GetPage().GetPageToken())
	if a := req.Msg.GetAgentId(); a != "" {
		q = q.And("agent_id", store.OpEq, a)
	}
	rows, next, err := st.Recordings.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListRecordingsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	for _, r := range rows {
		out.Recordings = append(out.Recordings, recordingProto(r))
	}
	return connect.NewResponse(out), nil
}

// ReadRecording implements RecordingService.
func (s *RecordingService) ReadRecording(ctx context.Context, req *connect.Request[apiv1.ReadRecordingRequest], stream *connect.ServerStream[apiv1.ReadRecordingResponse]) error {
	st, err := s.D.Store()
	if err != nil {
		return err
	}
	p, err := authz.Require(ctx, authz.AuditView)
	if err != nil {
		return err
	}
	r, err := st.Recordings.Get(ctx, store.Tenant(p.OrgID), req.Msg.GetRecordingId())
	if err != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("recording not found"))
	}
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "recording.viewed", TargetType: "recording", TargetID: r.ID, TargetDisplay: r.AgentName})
	if err := stream.Send(&apiv1.ReadRecordingResponse{Part: &apiv1.ReadRecordingResponse_Recording{Recording: recordingProto(r)}}); err != nil {
		return err
	}
	return terminal.ReadChunks(ctx, st, p.OrgID, r.ID, func(data []byte) error {
		for len(data) > 0 {
			n := min(len(data), 256<<10)
			if err := stream.Send(&apiv1.ReadRecordingResponse{Part: &apiv1.ReadRecordingResponse_Asciicast{Asciicast: data[:n]}}); err != nil {
				return err
			}
			data = data[n:]
		}
		return nil
	})
}
