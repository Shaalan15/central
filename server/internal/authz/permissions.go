// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package authz defines Central's permission catalog, built-in roles and the authorization
// decision logic (role bindings scoped to agent groups/tags, step-up requirements).
package authz

import "slices"

// Permission names. Keep in sync with docs and the UI (the catalog is served by RoleService).
const (
	FleetView       = "fleet.view"
	AgentsManage    = "agents.manage"
	AgentsApprove   = "agents.approve"
	AgentsRevoke    = "agents.revoke"
	TokensManage    = "tokens.manage"
	LogsView        = "logs.view"
	PackagesManage  = "packages.manage"
	ServicesManage  = "services.manage"
	ProcessesSignal = "processes.signal"
	PowerManage     = "power.manage"
	NetworkManage   = "network.manage"
	FilesRead       = "files.read"
	FilesWrite      = "files.write"
	UsersManage     = "users.manage"
	TerminalOpen    = "terminal.open"
	ExecRun         = "exec.run"
	JobsView        = "jobs.view"
	JobsRun         = "jobs.run"
	AuditView       = "audit.view"
	MembersManage   = "members.manage"
	RolesManage     = "roles.manage"
	APIKeysManage   = "apikeys.manage"
	OrgSettings     = "org.settings.manage"
	SystemView      = "system.view"
	SystemKeyExport = "system.keys.export"
)

// PermissionInfo describes one permission.
type PermissionInfo struct {
	Name        string
	Description string
	Category    string
	// StepUp: using this permission requires a recent MFA re-authentication.
	StepUp bool
	// AgentScoped: grants can be limited to agent groups/tags.
	AgentScoped bool
}

// Catalog lists every permission in display order.
var Catalog = []PermissionInfo{
	{FleetView, "View agents, metrics, inventory and command history", "Fleet", false, true},
	{AgentsManage, "Rename, tag and group agents; manage agent groups", "Fleet", false, true},
	{AgentsApprove, "Approve or deny agent enrollment requests", "Enrollment", true, false},
	{AgentsRevoke, "Revoke agents (disconnects them immediately)", "Enrollment", true, true},
	{TokensManage, "Create and revoke enrollment tokens", "Enrollment", true, false},
	{LogsView, "Read system logs (journal) on agents", "Hosts", false, true},
	{PackagesManage, "Refresh, upgrade, install and remove packages", "Hosts", false, true},
	{ServicesManage, "Start, stop, restart, enable and disable services", "Hosts", false, true},
	{ProcessesSignal, "Send signals to processes", "Hosts", false, true},
	{PowerManage, "Reboot and power off agents", "Hosts", true, true},
	{NetworkManage, "Change network and firewall configuration", "Hosts", true, true},
	{FilesRead, "Browse and download files on agents", "Hosts", false, true},
	{FilesWrite, "Create, edit, delete files and change permissions", "Hosts", true, true},
	{UsersManage, "Manage Linux users, groups and SSH keys", "Hosts", true, true},
	{TerminalOpen, "Open interactive terminals", "Hosts", true, true},
	{ExecRun, "Run arbitrary commands", "Hosts", true, true},
	{JobsView, "View fleet jobs", "Jobs", false, false},
	{JobsRun, "Run fleet-wide jobs (plus the operation's own permission)", "Jobs", true, true},
	{AuditView, "View and verify the audit log", "Administration", false, false},
	{MembersManage, "Invite and remove members, change their roles", "Administration", true, false},
	{RolesManage, "Create and edit custom roles", "Administration", true, false},
	{APIKeysManage, "Create and revoke API keys", "Administration", true, false},
	{OrgSettings, "Change organization settings", "Administration", true, false},
	{SystemView, "View system information", "Administration", false, false},
	{SystemKeyExport, "Export the encrypted key backup", "Administration", true, false},
}

var catalogByName = func() map[string]PermissionInfo {
	m := make(map[string]PermissionInfo, len(Catalog))
	for _, p := range Catalog {
		m[p.Name] = p
	}
	return m
}()

// Lookup returns a permission's metadata.
func Lookup(name string) (PermissionInfo, bool) {
	p, ok := catalogByName[name]
	return p, ok
}

// RequiresStepUp reports whether a permission needs recent re-authentication.
func RequiresStepUp(name string) bool { return catalogByName[name].StepUp }

// Built-in role IDs (stable; stored in role bindings).
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
	RoleAuditor  = "auditor"
)

// BuiltinRole is a code-defined role.
type BuiltinRole struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

func allPermissions(except ...string) []string {
	var out []string
	for _, p := range Catalog {
		if !slices.Contains(except, p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

// BuiltinRoles lists the built-in roles.
var BuiltinRoles = []BuiltinRole{
	{RoleOwner, "Owner", "Full control, including key backup and ownership", allPermissions()},
	{RoleAdmin, "Admin", "Full administration except key export", allPermissions(SystemKeyExport)},
	{RoleOperator, "Operator", "Day-to-day operations: updates, services, reboots, jobs", []string{
		FleetView, AgentsManage, LogsView, PackagesManage, ServicesManage, ProcessesSignal, PowerManage,
		JobsView, JobsRun,
	}},
	{RoleViewer, "Viewer", "Read-only access to the fleet", []string{FleetView, JobsView}},
	{RoleAuditor, "Auditor", "Read-only access plus the audit log", []string{FleetView, JobsView, AuditView, SystemView}},
}

// Builtin returns a built-in role by ID.
func Builtin(id string) (BuiltinRole, bool) {
	for _, r := range BuiltinRoles {
		if r.ID == id {
			return r, true
		}
	}
	return BuiltinRole{}, false
}
