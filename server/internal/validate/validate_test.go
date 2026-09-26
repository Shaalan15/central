// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package validate

import (
	"strings"
	"testing"
)

func TestEmail(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"  Alice@Example.COM ", "alice@example.com"},
		{"a.b+c@sub.example.org", "a.b+c@sub.example.org"},
	} {
		got, err := Email(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("Email(%q) = %q, %v", tc.in, got, err)
		}
	}
	for _, in := range []string{
		"", "alice", "alice@", "@example.com", "Alice <a@example.com>", "a@localhost",
		"a b@example.com", strings.Repeat("a", 250) + "@example.com", "a@exa\"mple.com",
	} {
		if _, err := Email(in); err == nil {
			t.Errorf("Email(%q) accepted", in)
		}
	}
}

func TestDisplayText(t *testing.T) {
	if v, err := DisplayText("name", "  Acme Ops  ", 50); err != nil || v != "Acme Ops" {
		t.Fatalf("got %q %v", v, err)
	}
	for _, in := range []string{"", "   ", "a\nb", "evil\u202etxt", "x\x00", strings.Repeat("x", 51)} {
		if _, err := DisplayText("name", in, 50); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if v, err := OptionalText("note", "", 10); err != nil || v != "" {
		t.Fatal("optional empty")
	}
}

func TestTags(t *testing.T) {
	got, err := Tags([]string{"Web", "web", "env:prod", "region/eu-1"})
	if err != nil || len(got) != 3 || got[0] != "web" {
		t.Fatalf("Tags = %v, %v", got, err)
	}
	for _, bad := range []string{"", "-x", "has space", "UPPER!", strings.Repeat("a", 64)} {
		if _, err := Tag(bad); err == nil {
			t.Errorf("Tag(%q) accepted", bad)
		}
	}
}

func TestID(t *testing.T) {
	if ID("id", "0192f1c4a8b27c3e9d0a1b2c3d4e5f60") != nil {
		t.Fatal("valid id rejected")
	}
	for _, bad := range []string{"", "../x", "ABC", "a-b", strings.Repeat("a", 37)} {
		if ID("id", bad) == nil {
			t.Errorf("ID(%q) accepted", bad)
		}
	}
}
