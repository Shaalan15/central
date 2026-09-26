// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package jobs

import (
	"testing"

	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/store"
)

func TestMatches(t *testing.T) {
	v := func(id, group string, tags ...string) *fleet.View {
		return &fleet.View{Agent: store.Agent{ID: id, GroupID: group, Tags: tags, Lifecycle: store.AgentActive}}
	}
	web := v("a1", "g1", "web", "prod")
	cases := []struct {
		sel  Selector
		want bool
	}{
		{Selector{AllAgents: true}, true},
		{Selector{AgentIDs: []string{"a1"}}, true},
		{Selector{Tags: []string{"web"}}, true},
		{Selector{Tags: []string{"web", "staging"}}, false},
		{Selector{Tags: []string{"web"}, GroupIDs: []string{"g2"}}, false},
		{Selector{GroupIDs: []string{"g1"}}, true},
		{Selector{}, false},
	}
	for i, c := range cases {
		if got := Matches(c.sel, web); got != c.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
	revoked := v("a2", "", "web")
	revoked.Agent.Lifecycle = store.AgentRevoked
	if Matches(Selector{AllAgents: true}, revoked) {
		t.Error("revoked agents must never be targeted")
	}
}
