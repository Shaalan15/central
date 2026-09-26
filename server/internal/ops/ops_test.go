// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"strings"
	"testing"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/authz"
)

func TestEveryOperationIsDescribed(t *testing.T) {
	fields := (&agentv1.Operation{}).ProtoReflect().Descriptor().Oneofs().ByName("kind").Fields()
	if fields.Len() != len(table) {
		t.Errorf("proto has %d operations, table has %d", fields.Len(), len(table))
	}
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		info, ok := table[name]
		if !ok {
			t.Errorf("operation %s has no descriptor", name)
			continue
		}
		if _, ok := authz.Lookup(info.Permission); !ok {
			t.Errorf("%s: unknown permission %q", name, info.Permission)
		}
		if info.Capability == agentv1.Capability_CAPABILITY_UNSPECIFIED {
			t.Errorf("%s: no capability", name)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := []*agentv1.Operation{
		{Kind: &agentv1.Operation_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgrade{}}},
		{Kind: &agentv1.Operation_PackagesInstall{PackagesInstall: &agentv1.PackagesInstall{Names: []string{"nginx", "libc6:amd64", "curl=8.5.0-2ubuntu10.4"}}}},
		{Kind: &agentv1.Operation_ServiceAction{ServiceAction: &agentv1.ServiceAction{Unit: "nginx.service", Action: agentv1.ServiceAction_ACTION_RESTART}}},
		{Kind: &agentv1.Operation_ServiceAction{ServiceAction: &agentv1.ServiceAction{Unit: "getty@tty1.service", Action: agentv1.ServiceAction_ACTION_STOP}}},
		{Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{Argv: []string{"/usr/bin/uptime"}, Env: []string{"LANG=C"}}}},
		{Kind: &agentv1.Operation_FileRead{FileRead: &agentv1.FileRead{Path: "/etc/hosts"}}},
		{Kind: &agentv1.Operation_UserCreate{UserCreate: &agentv1.UserCreate{Name: "deploy", FullName: "Deploy User", Password: "s3cret pass"}}},
		{Kind: &agentv1.Operation_ProcessSignal{ProcessSignal: &agentv1.ProcessSignal{Pid: 1234, Signal: agentv1.ProcessSignal_SIGNAL_TERM}}},
	}
	for _, op := range ok {
		if err := Validate(op); err != nil {
			t.Errorf("%s: %v", Kind(op), err)
		}
	}
	bad := map[string]*agentv1.Operation{
		"empty":             {},
		"no install names":  {Kind: &agentv1.Operation_PackagesInstall{PackagesInstall: &agentv1.PackagesInstall{}}},
		"option injection":  {Kind: &agentv1.Operation_PackagesInstall{PackagesInstall: &agentv1.PackagesInstall{Names: []string{"-o=APT::foo"}}}},
		"upper pkg":         {Kind: &agentv1.Operation_PackagesRemove{PackagesRemove: &agentv1.PackagesRemove{Names: []string{"Nginx"}}}},
		"unit injection":    {Kind: &agentv1.Operation_ServiceAction{ServiceAction: &agentv1.ServiceAction{Unit: "--all", Action: agentv1.ServiceAction_ACTION_STOP}}},
		"no action":         {Kind: &agentv1.Operation_ServiceAction{ServiceAction: &agentv1.ServiceAction{Unit: "nginx"}}},
		"relative path":     {Kind: &agentv1.Operation_FileRead{FileRead: &agentv1.FileRead{Path: "etc/passwd"}}},
		"dotdot path":       {Kind: &agentv1.Operation_FileRead{FileRead: &agentv1.FileRead{Path: "/var/www/../../etc/shadow"}}},
		"delete root":       {Kind: &agentv1.Operation_FileDelete{FileDelete: &agentv1.FileDelete{Path: "/", Recursive: true}}},
		"gecos colon":       {Kind: &agentv1.Operation_UserCreate{UserCreate: &agentv1.UserCreate{Name: "x", FullName: "a:0:0"}}},
		"password newline":  {Kind: &agentv1.Operation_UserSetPassword{UserSetPassword: &agentv1.UserSetPassword{Name: "x", Password: "a\nroot:pw"}}},
		"key newline":       {Kind: &agentv1.Operation_AuthorizedKeysSet{AuthorizedKeysSet: &agentv1.AuthorizedKeysSet{User: "x", Lines: []string{"ssh-ed25519 AAAA\ncommand=evil"}}}},
		"bad user":          {Kind: &agentv1.Operation_UserDelete{UserDelete: &agentv1.UserDelete{Name: "Root!"}}},
		"no argv":           {Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{}}},
		"nul argv":          {Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{Argv: []string{"/bin/echo", "a\x00b"}}}},
		"bad env":           {Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{Argv: []string{"/bin/true"}, Env: []string{"NOEQUALS"}}}},
		"signal init":       {Kind: &agentv1.Operation_ProcessSignal{ProcessSignal: &agentv1.ProcessSignal{Pid: 1, Signal: agentv1.ProcessSignal_SIGNAL_KILL}}},
		"network disabled":  {Kind: &agentv1.Operation_NetworkApply{NetworkApply: &agentv1.NetworkApply{ChangeId: "c"}}},
		"setuid+ mode":      {Kind: &agentv1.Operation_FileChmod{FileChmod: &agentv1.FileChmod{Path: "/tmp/x", Mode: 0o17777}}},
		"chown nothing":     {Kind: &agentv1.Operation_FileChown{FileChown: &agentv1.FileChown{Path: "/tmp/x"}}},
		"huge limit":        {Kind: &agentv1.Operation_JournalQuery{JournalQuery: &agentv1.JournalQuery{Limit: 1 << 20}}},
		"unknown inventory": {Kind: &agentv1.Operation_InventoryRefresh{InventoryRefresh: &agentv1.InventoryRefresh{Kinds: []agentv1.InventoryKind{99}}}},
	}
	for name, op := range bad {
		if err := Validate(op); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRedact(t *testing.T) {
	op := &agentv1.Operation{Kind: &agentv1.Operation_UserSetPassword{UserSetPassword: &agentv1.UserSetPassword{Name: "x", Password: "hunter2hunter2"}}}
	r := Redact(op)
	if r.GetUserSetPassword().GetPassword() != RedactedMarker || op.GetUserSetPassword().GetPassword() != "hunter2hunter2" {
		t.Fatal("password not redacted in copy only")
	}
	ex := Redact(&agentv1.Operation{Kind: &agentv1.Operation_Exec{Exec: &agentv1.Exec{
		Argv: []string{"/bin/true"}, Env: []string{"TOKEN=abc"}, Stdin: []byte("secret"),
	}}})
	if ex.GetExec().GetEnv()[0] != "TOKEN="+RedactedMarker || strings.Contains(string(ex.GetExec().GetStdin()), "secret") {
		t.Fatalf("exec not redacted: %v", ex)
	}
	fw := Redact(&agentv1.Operation{Kind: &agentv1.Operation_FileWrite{FileWrite: &agentv1.FileWrite{Path: "/x", Content: []byte("data")}}})
	if len(fw.GetFileWrite().GetContent()) != 0 {
		t.Fatal("file content kept")
	}
}
