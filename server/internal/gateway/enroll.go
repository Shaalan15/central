// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/gen/go/central/agent/v1/agentv1connect"
	"github.com/Shaalan15/central/server/internal/enrollment"
	"github.com/Shaalan15/central/server/internal/httpx"
	"github.com/Shaalan15/central/server/internal/store"
)

type enrollmentService struct {
	agentv1connect.UnimplementedEnrollmentServiceHandler
	g *Gateway
}

var errRateLimited = connect.NewError(connect.CodeResourceExhausted, errors.New("too many requests; retry later"))

func enrollmentStatus(s string) agentv1.EnrollmentStatus {
	switch s {
	case store.EnrollmentPending:
		return agentv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING
	case store.EnrollmentApproved:
		return agentv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED
	case store.EnrollmentDenied:
		return agentv1.EnrollmentStatus_ENROLLMENT_STATUS_DENIED
	case store.EnrollmentExpired:
		return agentv1.EnrollmentStatus_ENROLLMENT_STATUS_EXPIRED
	}
	return agentv1.EnrollmentStatus_ENROLLMENT_STATUS_UNSPECIFIED
}

// Enroll implements EnrollmentService.
func (s *enrollmentService) Enroll(ctx context.Context, req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	ip := httpx.ClientIPFrom(ctx)
	if !s.g.limits.enrollIP.Allow(ip.String()) || !s.g.limits.enrollToken.Allow(req.Msg.GetTokenId()) {
		return nil, errRateLimited
	}
	m := req.Msg
	res, err := s.g.Enroll.Submit(ctx, enrollment.SubmitInput{
		TokenID: m.GetTokenId(), TokenSecret: m.GetTokenSecret(), CSRDER: m.GetCsrDer(), Facts: m.GetFacts(),
		AgentVersion: m.GetAgentVersion(), ProtocolVersion: m.GetProtocolVersion(), SourceIP: ip,
	})
	if err != nil {
		return nil, err
	}
	r := res.Request
	return connect.NewResponse(&agentv1.EnrollResponse{
		EnrollmentId: r.ID, PollSecret: res.PollSecret, ServerNonce: r.ServerNonce, PairingCode: r.PairingCode,
		Status: enrollmentStatus(r.Status), ExpiresAt: timestamppb.New(r.ExpiresAt),
		PollInterval: durationpb.New(enrollment.PollInterval),
	}), nil
}

// GetEnrollmentStatus implements EnrollmentService.
func (s *enrollmentService) GetEnrollmentStatus(ctx context.Context, req *connect.Request[agentv1.GetEnrollmentStatusRequest]) (*connect.Response[agentv1.GetEnrollmentStatusResponse], error) {
	if !s.g.limits.pollIP.Allow(httpx.ClientIPFrom(ctx).String()) {
		return nil, errRateLimited
	}
	wait := enrollment.DefaultWait
	if w := req.Msg.GetWait(); w != nil {
		wait = w.AsDuration()
	}
	res, err := s.g.Enroll.Status(ctx, req.Msg.GetEnrollmentId(), req.Msg.GetPollSecret(), wait)
	if err != nil {
		return nil, err
	}
	out := &agentv1.GetEnrollmentStatusResponse{Status: enrollmentStatus(res.Request.Status), Credentials: res.Credentials}
	if res.Request.Status == store.EnrollmentDenied || res.Request.Status == store.EnrollmentExpired {
		out.Reason = res.Request.DecisionNote
	}
	return connect.NewResponse(out), nil
}
