// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/dispatch"
	"github.com/Shaalan15/central/server/internal/ops"
	"github.com/Shaalan15/central/server/internal/store"
)

// HostService implements HostService.
type HostService struct {
	apiv1connect.UnimplementedHostServiceHandler
	D *Deps
}

// Machine-readable reasons for refused operations.
const (
	ReasonPolicyDenied = "policy_denied"
	ReasonPaused       = "paused"
)

var commandStates = map[string]agentv1.CommandState{
	store.CommandAccepted:  agentv1.CommandState_COMMAND_STATE_ACCEPTED,
	store.CommandRunning:   agentv1.CommandState_COMMAND_STATE_RUNNING,
	store.CommandSucceeded: agentv1.CommandState_COMMAND_STATE_SUCCEEDED,
	store.CommandFailed:    agentv1.CommandState_COMMAND_STATE_FAILED,
	store.CommandRejected:  agentv1.CommandState_COMMAND_STATE_REJECTED,
	store.CommandCancelled: agentv1.CommandState_COMMAND_STATE_CANCELLED,
	store.CommandTimedOut:  agentv1.CommandState_COMMAND_STATE_TIMED_OUT,
	store.CommandExpired:   agentv1.CommandState_COMMAND_STATE_TIMED_OUT,
}

func commandProto(c *store.Command) *apiv1.CommandRecord {
	out := &apiv1.CommandRecord{
		CommandId: c.ID, AgentId: c.AgentID, JobId: c.JobID, OperationType: c.OperationType,
		State: commandStates[c.State], ProgressPercent: int32(c.ProgressPercent), Status: c.Status, //nolint:gosec // -1..100
		Issuer: principalProto(c.Issuer), CreatedAt: ts(c.CreatedAt), StartedAt: ts(c.StartedAt),
		FinishedAt: ts(c.FinishedAt), ExpiresAt: ts(c.ExpiresAt), OutputTruncated: c.OutputTruncated,
	}
	if out.Status == "" {
		switch c.State {
		case store.CommandQueued:
			out.Status = "Queued until the agent connects"
		case store.CommandSent:
			out.Status = "Sent, waiting for the agent"
		}
	}
	if len(c.OperationProto) > 0 {
		op := &agentv1.Operation{}
		if proto.Unmarshal(c.OperationProto, op) == nil {
			out.Operation = op
		}
	}
	if len(c.ResultProto) > 0 {
		r := &agentv1.CommandResult{}
		if proto.Unmarshal(c.ResultProto, r) == nil {
			out.Result = r
		}
	}
	if c.ErrorCode != "" || c.ErrorMessage != "" {
		code := agentv1.ErrorCode(agentv1.ErrorCode_value["ERROR_CODE_"+strings.ToUpper(c.ErrorCode)])
		out.Error = &agentv1.CommandError{Code: code, Message: c.ErrorMessage}
	}
	return out
}

func reasonError(code connect.Code, reason string, err error) error {
	ce := connect.NewError(code, err)
	ce.Meta().Set(authz.ReasonHeader, reason)
	return ce
}

func (d *Deps) dispatchError(err error) error {
	switch {
	case errors.Is(err, dispatch.ErrNotFound):
		return errAgentNotFound
	case errors.Is(err, dispatch.ErrRevoked), errors.Is(err, dispatch.ErrFinished):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, dispatch.ErrPolicyDenied):
		return reasonError(connect.CodeFailedPrecondition, ReasonPolicyDenied, err)
	case errors.Is(err, dispatch.ErrPaused):
		return reasonError(connect.CodeFailedPrecondition, ReasonPaused, err)
	case errors.Is(err, dispatch.ErrQuota):
		return connect.NewError(connect.CodeResourceExhausted, err)
	}
	return d.internal(err)
}

// audited reports whether running an operation is recorded in the audit log: everything that
// changes a host, and reads that need more than fleet.view (logs, files).
func audited(info ops.Info) bool { return info.Mutating || info.Permission != authz.FleetView }

// RunOperation implements HostService.
func (s *HostService) RunOperation(ctx context.Context, req *connect.Request[apiv1.RunOperationRequest]) (*connect.Response[apiv1.RunOperationResponse], error) {
	m := req.Msg
	info, err := ops.Describe(m.GetOperation())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if info.Session {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New(info.Type+" needs an interactive session; use OpenTerminal, FollowJournal or CreateFileTransfer"))
	}
	p, v, err := s.D.agentFor(ctx, info.Permission, m.GetAgentId())
	if err != nil {
		return nil, err
	}
	if info.Disabled != "" {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New(info.Disabled))
	}
	if err := ops.Validate(m.GetOperation()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	wait := 20 * time.Second
	if w := m.GetWait(); w != nil {
		wait = min(max(w.AsDuration(), 0), 60*time.Second)
	}
	var ttl time.Duration
	if t := m.GetTtl(); t != nil {
		ttl = t.AsDuration()
	}
	rec, err := s.D.Dispatch.Submit(ctx, dispatch.Request{
		OrgID: p.OrgID, AgentID: v.Agent.ID, Operation: m.GetOperation(), TTL: ttl, Issuer: p.Ref(), SourceIP: clientIP(ctx),
	})
	if err != nil {
		if audited(info) && (errors.Is(err, dispatch.ErrPolicyDenied) || errors.Is(err, dispatch.ErrPaused)) {
			_ = s.D.Audit.Record(ctx, audit.Event{
				Action: "host.operation", TargetType: "agent", TargetID: v.Agent.ID, TargetDisplay: v.Agent.Name,
				Result: store.AuditDenied, Details: map[string]string{"operation": info.Type, "reason": err.Error()},
			})
		}
		return nil, s.D.dispatchError(err)
	}
	if audited(info) {
		_ = s.D.Audit.Record(ctx, audit.Event{
			Action: "host.operation", TargetType: "agent", TargetID: v.Agent.ID, TargetDisplay: v.Agent.Name,
			Details: map[string]string{"operation": info.Type, "command_id": rec.ID},
		})
	}
	if wait > 0 {
		if done, err := s.D.Dispatch.Wait(ctx, p.OrgID, rec.ID, wait); err == nil {
			rec = done
		}
	}
	return connect.NewResponse(&apiv1.RunOperationResponse{Command: commandProto(&rec)}), nil
}

// command loads a command and checks perm on its agent.
func (s *HostService) command(ctx context.Context, id string, perm func(*store.Command) string) (*authz.Principal, store.Command, error) {
	if _, err := s.D.Store(); err != nil {
		return nil, store.Command{}, err
	}
	p, err := authz.Require(ctx, authz.FleetView)
	if err != nil {
		return nil, store.Command{}, err
	}
	rec, err := s.D.Dispatch.Get(ctx, p.OrgID, id)
	if err != nil {
		return nil, store.Command{}, connect.NewError(connect.CodeNotFound, errors.New("command not found"))
	}
	if _, _, err := s.D.agentFor(ctx, perm(&rec), rec.AgentID); err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, store.Command{}, connect.NewError(connect.CodeNotFound, errors.New("command not found"))
		}
		return nil, store.Command{}, err
	}
	return p, rec, nil
}

func viewPerm(*store.Command) string { return authz.FleetView }

// WatchCommand implements HostService.
func (s *HostService) WatchCommand(ctx context.Context, req *connect.Request[apiv1.WatchCommandRequest], stream *connect.ServerStream[apiv1.WatchCommandResponse]) error {
	p, _, err := s.command(ctx, req.Msg.GetCommandId(), viewPerm)
	if err != nil {
		return err
	}
	rec, backlog, sub, err := s.D.Dispatch.Watch(ctx, p.OrgID, req.Msg.GetCommandId(), req.Msg.GetFromOutputSeq())
	if err != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("command not found"))
	}
	defer sub.Close()
	if err := stream.Send(&apiv1.WatchCommandResponse{Event: &apiv1.WatchCommandResponse_Update{Update: commandProto(&rec)}}); err != nil {
		return err
	}
	for _, c := range backlog {
		if err := stream.Send(&apiv1.WatchCommandResponse{Event: &apiv1.WatchCommandResponse_Output{Output: c}}); err != nil {
			return err
		}
	}
	if rec.Terminal() {
		return nil
	}
	recheck := time.NewTicker(streamRecheck)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-recheck.C:
			if p = s.D.refreshPrincipal(ctx, p); p == nil {
				return errStreamAuth
			}
			if _, _, err := s.command(authz.WithPrincipal(ctx, p), rec.ID, viewPerm); err != nil {
				return err
			}
		case msg, ok := <-sub.C:
			if !ok {
				return nil
			}
			ev, ok := msg.(dispatch.Event)
			if !ok {
				continue
			}
			for _, c := range ev.Output {
				if err := stream.Send(&apiv1.WatchCommandResponse{Event: &apiv1.WatchCommandResponse_Output{Output: c}}); err != nil {
					return err
				}
			}
			if err := stream.Send(&apiv1.WatchCommandResponse{Event: &apiv1.WatchCommandResponse_Update{Update: commandProto(&ev.Record)}}); err != nil {
				return err
			}
			if ev.Record.Terminal() {
				return nil
			}
		}
	}
}

// CancelCommand implements HostService. Cancelling needs the permission that authorized the
// operation.
func (s *HostService) CancelCommand(ctx context.Context, req *connect.Request[apiv1.CancelCommandRequest]) (*connect.Response[apiv1.CancelCommandResponse], error) {
	p, rec, err := s.command(ctx, req.Msg.GetCommandId(), func(c *store.Command) string {
		if info, ok := ops.Lookup(c.OperationType); ok {
			return info.Permission
		}
		return authz.AgentsManage
	})
	if err != nil {
		return nil, err
	}
	if err := s.D.Dispatch.Cancel(ctx, p.OrgID, rec.ID); err != nil {
		return nil, s.D.dispatchError(err)
	}
	_ = s.D.Audit.Record(ctx, audit.Event{
		Action: "host.command_cancelled", TargetType: "agent", TargetID: rec.AgentID,
		Details: map[string]string{"command_id": rec.ID, "operation": rec.OperationType},
	})
	return connect.NewResponse(&apiv1.CancelCommandResponse{}), nil
}

// ListCommands implements HostService.
func (s *HostService) ListCommands(ctx context.Context, req *connect.Request[apiv1.ListCommandsRequest]) (*connect.Response[apiv1.ListCommandsResponse], error) {
	p, v, err := s.D.agentFor(ctx, authz.FleetView, req.Msg.GetAgentId())
	if err != nil {
		return nil, err
	}
	st, _ := s.D.Store()
	size := int(min(max(req.Msg.GetPage().GetPageSize(), 1), 500))
	if req.Msg.GetPage().GetPageSize() == 0 {
		size = 50
	}
	q := store.Eq("agent_id", v.Agent.ID).Order("created_at", true).Page(size, req.Msg.GetPage().GetPageToken())
	rows, next, err := st.Commands.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListCommandsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	for _, r := range rows {
		// Prefer the live record (fresher than the throttled persisted state).
		if live, ok := s.D.Dispatch.Live(p.OrgID, r.ID); ok {
			r = &live
		}
		out.Commands = append(out.Commands, commandProto(r))
	}
	return connect.NewResponse(out), nil
}
