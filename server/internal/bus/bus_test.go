// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package bus

import (
	"sync"
	"testing"
)

func TestPublishSubscribe(t *testing.T) {
	b := NewMemory()
	s1 := b.Subscribe("t", 4)
	s2 := b.Subscribe("t", 4)
	other := b.Subscribe("u", 4)
	b.Publish("t", 1)
	if (<-s1.C).(int) != 1 || (<-s2.C).(int) != 1 {
		t.Fatal("fan-out failed")
	}
	select {
	case <-other.C:
		t.Fatal("message leaked to another topic")
	default:
	}
	s1.Close()
	s1.Close() // idempotent
	if _, ok := <-s1.C; ok {
		t.Fatal("channel not closed")
	}
	if b.Subscribers("t") != 1 {
		t.Fatal("unsubscribe failed")
	}
	b.Publish("t", 2) // must not panic on closed subscription
	s2.Close()
	other.Close()
	if b.Subscribers("t") != 0 || b.Subscribers("u") != 0 {
		t.Fatal("topics not cleaned up")
	}
}

func TestSlowSubscriberDrops(t *testing.T) {
	b := NewMemory()
	s := b.Subscribe("t", 2)
	for i := range 10 {
		b.Publish("t", i)
	}
	if s.Dropped() != 8 {
		t.Fatalf("dropped = %d", s.Dropped())
	}
	s.Close()
}

func TestConcurrentUse(t *testing.T) {
	b := NewMemory()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				s := b.Subscribe("t", 1)
				b.Publish("t", "x")
				s.Close()
			}
		}()
	}
	wg.Wait()
}
