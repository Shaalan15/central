// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimit provides keyed token-bucket limiters (per IP, per account, per token).
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Keyed is a set of token buckets indexed by key. Idle buckets are evicted, and the number of
// tracked keys is bounded so hostile traffic with random keys cannot exhaust memory: when the
// table is full, unknown keys share one overflow bucket (fail-safe: they get limited harder).
type Keyed struct {
	mu       sync.Mutex
	limit    rate.Limit
	burst    int
	maxKeys  int
	idle     time.Duration
	buckets  map[string]*entry
	overflow *rate.Limiter
	lastGC   time.Time
	now      func() time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// New creates a limiter allowing `events` per `per` with the given burst.
func New(events int, per time.Duration, burst int) *Keyed {
	lim := rate.Limit(float64(events) / per.Seconds())
	return &Keyed{
		limit:    lim,
		burst:    burst,
		maxKeys:  100_000,
		idle:     max(per*2, 10*time.Minute),
		buckets:  map[string]*entry{},
		overflow: rate.NewLimiter(lim, burst),
		now:      time.Now,
	}
}

// Allow reports whether an event for key may happen now.
func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if now.Sub(k.lastGC) > time.Minute {
		for key, e := range k.buckets {
			if now.Sub(e.seen) > k.idle {
				delete(k.buckets, key)
			}
		}
		k.lastGC = now
	}
	e, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			return k.overflow.AllowN(now, 1)
		}
		e = &entry{lim: rate.NewLimiter(k.limit, k.burst)}
		k.buckets[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// Reset forgets a key (e.g. after a successful login).
func (k *Keyed) Reset(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.buckets, key)
}
