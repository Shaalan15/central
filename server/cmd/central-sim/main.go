// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command central-sim runs simulated agents that speak the real agent protocol.
// It exists for UI development, end-to-end tests and load tests before the real
// agent is available. It is never shipped to managed servers.
//
//	central-sim --agent-url https://localhost:9443 --key-file key.txt --agents 50
//
// The first run enrolls the agents with the enrollment key (use an auto-approval token for
// many agents, or approve each pairing code in the UI) and stores their credentials in
// --state-dir; later runs reconnect the same agents without a key.
package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/agentsim"
)

type options struct {
	agentURL, serverName, keyFile, prefix, stateDir, profile string
	agents, enrollConcurrency                                int
	statsEvery, rampUp                                       time.Duration
}

type stats struct {
	connected, commands, reconnects, rejected atomic.Int64
	mu                                        sync.Mutex
	latencies                                 []time.Duration
}

func (s *stats) observe(d time.Duration) {
	s.mu.Lock()
	s.latencies = append(s.latencies, d)
	s.mu.Unlock()
}

func (s *stats) report(log *slog.Logger) {
	s.mu.Lock()
	lat := s.latencies
	s.latencies = nil
	s.mu.Unlock()
	attrs := []any{"connected", s.connected.Load(), "commands", s.commands.Load(), "reconnects", s.reconnects.Load(), "rejected", s.rejected.Load()}
	if len(lat) > 0 {
		slices.Sort(lat)
		p := func(q float64) time.Duration { return lat[min(len(lat)-1, int(q*float64(len(lat))))] }
		attrs = append(attrs, "dispatch_p50", p(0.50).Round(time.Millisecond), "dispatch_p99", p(0.99).Round(time.Millisecond), "samples", len(lat))
	}
	log.Info("central-sim", attrs...)
}

func main() {
	var o options
	flag.StringVar(&o.agentURL, "agent-url", envOr("CENTRAL_SIM_AGENT_URL", "https://localhost:9443"), "Central agent endpoint")
	flag.StringVar(&o.serverName, "server-name", "", "TLS server name to verify (default: the agent URL's host, or localhost for IPs)")
	flag.StringVar(&o.keyFile, "key-file", "", "file with the enrollment key (\"-\" for stdin; or set CENTRAL_SIM_KEY)")
	flag.IntVar(&o.agents, "agents", 25, "number of simulated agents")
	flag.StringVar(&o.prefix, "prefix", "sim", "hostname prefix")
	flag.StringVar(&o.stateDir, "state-dir", ".central-sim", "where agent credentials are stored")
	flag.StringVar(&o.profile, "profile", "mixed", "owner policy profile: observe, operate, administer, full or mixed")
	flag.IntVar(&o.enrollConcurrency, "enroll-concurrency", 8, "parallel enrollments")
	flag.DurationVar(&o.statsEvery, "stats", 15*time.Second, "how often to log statistics")
	flag.DurationVar(&o.rampUp, "ramp-up", 5*time.Second, "spread initial connections over this duration")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, o, log)
	stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("central-sim failed", "error", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string { return cmp.Or(os.Getenv(key), def) }

func readKey(o options) (string, error) {
	if k := strings.TrimSpace(os.Getenv("CENTRAL_SIM_KEY")); k != "" {
		return k, nil
	}
	if o.keyFile == "" {
		return "", nil
	}
	var data []byte
	var err error
	if o.keyFile == "-" {
		data, err = bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
	} else {
		data, err = os.ReadFile(o.keyFile)
	}
	return strings.TrimSpace(string(data)), err
}

var profiles = map[string]agentv1.PolicyProfile{
	"observe": agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE, "operate": agentv1.PolicyProfile_POLICY_PROFILE_OPERATE,
	"administer": agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER, "full": agentv1.PolicyProfile_POLICY_PROFILE_FULL,
}

func profileFor(o options, i int) (agentv1.PolicyProfile, error) {
	if o.profile == "mixed" { // mostly administer, some of each other profile
		return []agentv1.PolicyProfile{
			agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER, agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER,
			agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER, agentv1.PolicyProfile_POLICY_PROFILE_OPERATE,
			agentv1.PolicyProfile_POLICY_PROFILE_FULL, agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE,
		}[i%6], nil
	}
	p, ok := profiles[o.profile]
	if !ok {
		return 0, fmt.Errorf("unknown profile %q", o.profile)
	}
	return p, nil
}

func seed(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}

func run(ctx context.Context, o options, log *slog.Logger) error {
	if o.agents < 1 || o.agents > 10_000 {
		return errors.New("--agents must be between 1 and 10000")
	}
	if o.serverName == "" {
		u, err := url.Parse(o.agentURL)
		if err != nil {
			return fmt.Errorf("--agent-url: %w", err)
		}
		o.serverName = u.Hostname()
		if strings.Trim(o.serverName, "0123456789.:[]") == "" {
			o.serverName = "localhost" // Central's agent certificate always covers localhost
		}
	}
	key, err := readKey(o)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.stateDir, 0o700); err != nil {
		return err
	}

	st := &stats{}
	agents := make([]*agentsim.Agent, o.agents)
	hosts := make([]*agentsim.Host, o.agents)
	sem := make(chan struct{}, max(o.enrollConcurrency, 1))
	var wg sync.WaitGroup
	var firstErr atomic.Value
	for i := range o.agents {
		name := fmt.Sprintf("%s-%03d", o.prefix, i+1)
		profile, err := profileFor(o, i)
		if err != nil {
			return err
		}
		hosts[i] = agentsim.NewHost(name, seed(name), profile)
		path := filepath.Join(o.stateDir, name+".json")
		if a, err := agentsim.Load(path); err == nil {
			agents[i] = a
			continue
		}
		if key == "" {
			return fmt.Errorf("%s has no stored credentials: pass --key-file or CENTRAL_SIM_KEY to enroll", name)
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			a, err := enroll(ctx, o, key, hosts[i], log)
			if err != nil {
				firstErr.CompareAndSwap(nil, fmt.Errorf("%s: %w", name, err))
				return
			}
			if err := a.Save(path); err != nil {
				firstErr.CompareAndSwap(nil, err)
				return
			}
			agents[i] = a
		})
	}
	wg.Wait()
	if err, ok := firstErr.Load().(error); ok && err != nil {
		return err
	}
	log.Info("central-sim: agents ready", "agents", o.agents, "endpoint", o.agentURL)

	for i := range agents {
		wg.Go(func() {
			if o.rampUp > 0 {
				select {
				case <-time.After(rand.N(o.rampUp)):
				case <-ctx.Done():
					return
				}
			}
			runAgent(ctx, agents[i], hosts[i], st, log)
		})
	}
	tick := time.NewTicker(o.statsEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			st.report(log)
			return nil
		case <-tick.C:
			st.report(log)
		}
	}
}

func enroll(ctx context.Context, o options, key string, h *agentsim.Host, log *slog.Logger) (*agentsim.Agent, error) {
	facts := h.Facts()
	var e *agentsim.Enrollment
	var err error
	for attempt := range 10 { // back off on rate limits
		e, err = agentsim.Enroll(ctx, agentsim.EnrollOptions{AgentURL: o.agentURL, ServerName: o.serverName, Key: key, Facts: facts})
		if err == nil || !strings.Contains(err.Error(), "resource_exhausted") {
			break
		}
		select {
		case <-time.After(time.Duration(1<<attempt) * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	log.Info("central-sim: enrollment requested: approve it in Central", "host", facts.GetHostname(), "pairing_code", e.PairingCode)
	a, err := e.Wait(ctx)
	if err != nil {
		return nil, err
	}
	log.Info("central-sim: enrolled", "host", facts.GetHostname(), "agent_id", a.ID)
	return a, nil
}

func runAgent(ctx context.Context, a *agentsim.Agent, h *agentsim.Host, st *stats, log *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		runCtx, cancel := context.WithCancel(ctx)
		rebooted := make(chan struct{}, 1)
		h.SetReboot(func() {
			select {
			case rebooted <- struct{}{}:
			default:
			}
			cancel()
		})
		a.Facts, a.Policy = h.Facts(), h.Policy
		started := time.Now()
		handler := func(ctx context.Context, conn *agentsim.Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
			st.commands.Add(1)
			st.observe(time.Since(cmd.GetIssuedAt().AsTime()))
			u := h.Handle(ctx, conn, cmd)
			if u.GetState() == agentv1.CommandState_COMMAND_STATE_REJECTED {
				st.rejected.Add(1)
			}
			return u
		}
		wasConnected := false
		err := a.Run(runCtx, handler, func(c *agentsim.Conn) {
			wasConnected = true
			st.connected.Add(1)
			go telemetry(c, h)
		})
		if wasConnected {
			st.connected.Add(-1)
		}
		cancel()
		if errors.Is(err, agentsim.ErrRevoked) {
			log.Warn("central-sim: agent revoked, stopping it", "agent_id", a.ID)
			return
		}
		if ctx.Err() != nil {
			return
		}
		st.reconnects.Add(1)
		select {
		case <-rebooted: // simulated reboot: come back after a short boot
			backoff = 10 * time.Second
		default:
			if time.Since(started) > time.Minute {
				backoff = time.Second
			}
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// telemetry sends inventory once and then metrics and heartbeats until the stream ends.
func telemetry(c *agentsim.Conn, h *agentsim.Host) {
	h.SendInventory(c)
	interval := c.Ack.GetConfig().GetMetricsInterval().AsDuration()
	if interval < 5*time.Second {
		interval = 15 * time.Second
	}
	metrics := time.NewTicker(interval)
	defer metrics.Stop()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	send := func() {
		_ = c.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Metrics{Metrics: &agentv1.MetricsReport{
			Samples: []*agentv1.MetricsSample{h.Sample(time.Now())},
		}}})
	}
	send()
	for {
		select {
		case <-c.Context().Done():
			return
		case <-metrics.C:
			send()
		case <-heartbeat.C:
			_ = c.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}})
		}
	}
}
