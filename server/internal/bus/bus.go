// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package bus is Central's internal publish/subscribe fabric: fleet updates, command progress,
// live metrics and session events flow through it from the component that produces them to
// every UI stream that watches them.
//
// Phase 1 ships an in-process implementation. The interface is deliberately small so a NATS
// implementation can back multi-replica deployments later without touching callers.
package bus

import (
	"sync"
	"sync/atomic"
)

// Bus delivers messages published on a topic to every current subscriber of that topic.
type Bus interface {
	// Publish delivers msg to subscribers without blocking. Slow subscribers drop messages
	// (and are told via Subscription.Dropped) rather than stalling publishers.
	Publish(topic string, msg any)
	// Subscribe registers interest in a topic. Call Close when done.
	Subscribe(topic string, buffer int) *Subscription
}

// Subscription receives messages for one topic.
type Subscription struct {
	C       <-chan any
	ch      chan any
	topic   string
	bus     *Memory
	once    sync.Once
	dropped atomic.Uint64
	closed  atomic.Bool
}

// Dropped returns how many messages were discarded because the subscriber was too slow.
// Consumers that need completeness (e.g. fleet watches) resync with a snapshot when this grows.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Close unsubscribes and closes C.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.bus.remove(s)
	})
}

// Memory is the in-process Bus.
type Memory struct {
	mu   sync.RWMutex
	subs map[string]map[*Subscription]struct{}
}

// NewMemory returns an in-process bus.
func NewMemory() *Memory { return &Memory{subs: map[string]map[*Subscription]struct{}{}} }

// Publish implements Bus.
func (m *Memory) Publish(topic string, msg any) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for s := range m.subs[topic] {
		select {
		case s.ch <- msg:
		default:
			s.dropped.Add(1)
		}
	}
}

// Subscribe implements Bus.
func (m *Memory) Subscribe(topic string, buffer int) *Subscription {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan any, buffer)
	s := &Subscription{C: ch, ch: ch, topic: topic, bus: m}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subs[topic] == nil {
		m.subs[topic] = map[*Subscription]struct{}{}
	}
	m.subs[topic][s] = struct{}{}
	return s
}

func (m *Memory) remove(s *Subscription) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.subs[s.topic]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(m.subs, s.topic)
		}
	}
	if s.closed.CompareAndSwap(false, true) {
		close(s.ch)
	}
}

// Subscribers returns the number of subscribers of a topic (for tests and metrics).
func (m *Memory) Subscribers(topic string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.subs[topic])
}

// Topic helpers keep naming consistent across producers and consumers.

// FleetTopic carries fleet index changes for an organization.
func FleetTopic(orgID string) string { return "fleet." + orgID }

// AgentMetricsTopic carries live metric samples for one agent.
func AgentMetricsTopic(agentID string) string { return "metrics." + agentID }

// CommandTopic carries progress and output of one command.
func CommandTopic(commandID string) string { return "command." + commandID }

// JobTopic carries progress of one job.
func JobTopic(jobID string) string { return "job." + jobID }

// EnrollmentTopic carries enrollment request changes (by request ID) for long-polling agents.
func EnrollmentTopic(requestID string) string { return "enrollment." + requestID }

// SessionTopic carries attach events for interactive sessions.
func SessionTopic(sessionID string) string { return "session." + sessionID }
