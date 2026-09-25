// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestKeyed(t *testing.T) {
	now := time.Unix(1000, 0)
	k := New(5, time.Minute, 5)
	k.now = func() time.Time { return now }
	for i := range 5 {
		if !k.Allow("ip1") {
			t.Fatalf("event %d denied", i)
		}
	}
	if k.Allow("ip1") {
		t.Fatal("burst exceeded but allowed")
	}
	if !k.Allow("ip2") {
		t.Fatal("independent key limited")
	}
	now = now.Add(13 * time.Second) // 5/min refills one token every 12s
	if !k.Allow("ip1") {
		t.Fatal("token not refilled")
	}
	k.Reset("ip1")
	if !k.Allow("ip1") {
		t.Fatal("reset did not clear")
	}
}

func TestOverflowBucket(t *testing.T) {
	k := New(1, time.Minute, 1)
	k.maxKeys = 3
	for i := range 3 {
		k.Allow(strconv.Itoa(i))
	}
	allowed := 0
	for i := range 50 {
		if k.Allow(fmt.Sprintf("random-%d", i)) {
			allowed++
		}
	}
	if allowed > 1 {
		t.Fatalf("overflow bucket allowed %d", allowed)
	}
}
