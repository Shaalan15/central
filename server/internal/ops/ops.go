// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package ops describes the typed operations Central can send to agents: which Central
// permission authorizes each one, which agent capability the owner policy must allow, whether it
// needs an attached session, how its arguments are validated, and which fields are secret.
//
// Central validates arguments as defense in depth; the agent's privileged helper validates them
// again and has the final word (it enforces the owner policy).
package ops

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/authz"
)

// Info describes one operation type.
type Info struct {
	// Type is the oneof field name, e.g. "packages_upgrade".
	Type string
	// Permission is the Central permission required on the target agent.
	Permission string
	// Capability is what the agent's owner policy must allow.
	Capability agentv1.Capability
	// Mutating operations change the host (read-only ones only collect data).
	Mutating bool
	// Session operations need an attached session (terminal, journal follow, file transfer)
	// and cannot be sent with RunOperation.
	Session bool
	// Disabled operations are defined in the protocol but not enabled in this release.
	Disabled string
}

func read(perm string, c agentv1.Capability) Info { return Info{Permission: perm, Capability: c} }
func write(perm string, c agentv1.Capability) Info {
	return Info{Permission: perm, Capability: c, Mutating: true}
}

func session(i Info) Info { i.Session = true; return i }

func disabled(i Info, why string) Info { i.Disabled = why; return i }

const phase1b = "network and firewall changes with automatic rollback are not enabled in this release"

var table = map[string]Info{
	"packages_refresh":    write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE),
	"packages_upgrade":    write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE),
	"packages_install":    write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_INSTALL),
	"packages_remove":     write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_REMOVE),
	"packages_hold":       write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE),
	"packages_autoremove": write(authz.PackagesManage, agentv1.Capability_CAPABILITY_PACKAGES_REMOVE),
	"packages_list":       read(authz.FleetView, agentv1.Capability_CAPABILITY_PACKAGES_READ),

	"service_list":   read(authz.FleetView, agentv1.Capability_CAPABILITY_SERVICES_READ),
	"service_action": write(authz.ServicesManage, agentv1.Capability_CAPABILITY_SERVICES_MANAGE),
	"service_status": read(authz.FleetView, agentv1.Capability_CAPABILITY_SERVICES_READ),

	"journal_query":  read(authz.LogsView, agentv1.Capability_CAPABILITY_LOGS_READ),
	"journal_follow": session(read(authz.LogsView, agentv1.Capability_CAPABILITY_LOGS_READ)),

	"process_list":   read(authz.FleetView, agentv1.Capability_CAPABILITY_PROCESSES_READ),
	"process_signal": write(authz.ProcessesSignal, agentv1.Capability_CAPABILITY_PROCESSES_SIGNAL),

	"power":         write(authz.PowerManage, agentv1.Capability_CAPABILITY_POWER),
	"exec":          write(authz.ExecRun, agentv1.Capability_CAPABILITY_EXEC),
	"terminal_open": session(write(authz.TerminalOpen, agentv1.Capability_CAPABILITY_TERMINAL)),
	"storage_get":   read(authz.FleetView, agentv1.Capability_CAPABILITY_STORAGE_READ),

	"network_get":     read(authz.FleetView, agentv1.Capability_CAPABILITY_NETWORK_READ),
	"network_apply":   disabled(write(authz.NetworkManage, agentv1.Capability_CAPABILITY_NETWORK_MANAGE), phase1b),
	"network_confirm": disabled(write(authz.NetworkManage, agentv1.Capability_CAPABILITY_NETWORK_MANAGE), phase1b),
	"firewall_get":    read(authz.FleetView, agentv1.Capability_CAPABILITY_NETWORK_READ),
	"firewall_apply":  disabled(write(authz.NetworkManage, agentv1.Capability_CAPABILITY_FIREWALL_MANAGE), phase1b),

	"file_list":     read(authz.FilesRead, agentv1.Capability_CAPABILITY_FILES_READ),
	"file_stat":     read(authz.FilesRead, agentv1.Capability_CAPABILITY_FILES_READ),
	"file_read":     read(authz.FilesRead, agentv1.Capability_CAPABILITY_FILES_READ),
	"file_write":    write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_WRITE),
	"file_mkdir":    write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_WRITE),
	"file_delete":   write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_WRITE),
	"file_rename":   write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_WRITE),
	"file_chmod":    write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_PERMISSIONS),
	"file_chown":    write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_PERMISSIONS),
	"file_acl_get":  read(authz.FilesRead, agentv1.Capability_CAPABILITY_FILES_READ),
	"file_download": session(read(authz.FilesRead, agentv1.Capability_CAPABILITY_FILES_READ)),
	"file_upload":   session(write(authz.FilesWrite, agentv1.Capability_CAPABILITY_FILES_WRITE)),

	"user_list":           read(authz.FleetView, agentv1.Capability_CAPABILITY_USERS_READ),
	"user_create":         write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"user_modify":         write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"user_delete":         write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"user_set_password":   write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"group_create":        write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"group_delete":        write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"group_set_members":   write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),
	"authorized_keys_get": read(authz.FleetView, agentv1.Capability_CAPABILITY_USERS_READ),
	"authorized_keys_set": write(authz.UsersManage, agentv1.Capability_CAPABILITY_USERS_MANAGE),

	"agent_upgrade":     write(authz.AgentsManage, agentv1.Capability_CAPABILITY_AGENT_UPGRADE),
	"agent_uninstall":   write(authz.AgentsRevoke, agentv1.Capability_CAPABILITY_AGENT_UNINSTALL),
	"inventory_refresh": read(authz.FleetView, agentv1.Capability_CAPABILITY_TELEMETRY),
}

// ErrNoOperation is returned for an empty Operation.
var ErrNoOperation = errors.New("no operation specified")

// Kind returns the oneof field name of op ("" if unset).
func Kind(op *agentv1.Operation) string {
	fd := kindField(op)
	if fd == nil {
		return ""
	}
	return string(fd.Name())
}

func kindField(op *agentv1.Operation) protoreflect.FieldDescriptor {
	if op == nil {
		return nil
	}
	m := op.ProtoReflect()
	return m.WhichOneof(m.Descriptor().Oneofs().ByName("kind"))
}

// Describe returns the metadata of an operation.
func Describe(op *agentv1.Operation) (Info, error) {
	k := Kind(op)
	if k == "" {
		return Info{}, ErrNoOperation
	}
	info, ok := table[k]
	if !ok {
		return Info{}, fmt.Errorf("operation %q is not supported", k)
	}
	info.Type = k
	return info, nil
}

// Lookup returns the metadata of an operation type by name.
func Lookup(kind string) (Info, bool) {
	info, ok := table[kind]
	info.Type = kind
	return info, ok
}

// Types lists every known operation type.
func Types() []string {
	out := make([]string, 0, len(table))
	for k := range table {
		out = append(out, k)
	}
	return out
}

// Limits for operation arguments.
const (
	maxNames        = 500
	maxPathBytes    = 4096
	maxFileRead     = 1 << 20
	maxFileContent  = 4 << 20
	maxExecArgs     = 256
	maxExecArgBytes = 128 << 10
	maxExecStdin    = 1 << 20
	maxExecEnv      = 64
	maxTimeout      = 24 * time.Hour
	maxListLimit    = 10000
	maxKeyLines     = 1000
	maxKeyLineBytes = 16 << 10
	maxMembers      = 1000
)

var (
	pkgRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{0,127}(:[a-z0-9]{1,16})?$`)
	pkgVersionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{0,127}(:[a-z0-9]{1,16})?(=[A-Za-z0-9.+~:\-]{1,128})?$`)
	unitRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\\-]{0,254}$`)
	userRe       = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	envKeyRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	termRe       = regexp.MustCompile(`^[a-z0-9.+\-]{0,32}$`)
	versionRe    = regexp.MustCompile(`^[0-9A-Za-z.+~\-]{1,64}$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func invalid(format string, args ...any) error { return fmt.Errorf(format, args...) }

func checkNames(field string, names []string, re *regexp.Regexp, required bool) error {
	if required && len(names) == 0 {
		return invalid("%s: at least one name is required", field)
	}
	if len(names) > maxNames {
		return invalid("%s: at most %d names", field, maxNames)
	}
	for _, n := range names {
		if !re.MatchString(n) {
			return invalid("%s: invalid name %q", field, truncate(n, 64))
		}
	}
	return nil
}

// CheckPath validates an absolute, normalized path.
func CheckPath(field, p string) error {
	switch {
	case p == "":
		return invalid("%s is required", field)
	case len(p) > maxPathBytes:
		return invalid("%s is too long", field)
	case !utf8.ValidString(p) || strings.ContainsRune(p, 0):
		return invalid("%s contains invalid characters", field)
	case !strings.HasPrefix(p, "/"):
		return invalid("%s must be absolute", field)
	case path.Clean(p) != p:
		return invalid("%s must be normalized (no \"..\", \".\" or duplicate slashes)", field)
	}
	return nil
}

func checkUser(field, u string, required bool) error {
	if u == "" && !required {
		return nil
	}
	if !userRe.MatchString(u) {
		return invalid("%s: invalid user or group name %q", field, truncate(u, 40))
	}
	return nil
}

func checkUnit(u string) error {
	if !unitRe.MatchString(u) {
		return invalid("unit: invalid unit name %q", truncate(u, 64))
	}
	return nil
}

// checkLine rejects text that could break line-oriented formats on the host (passwd, chpasswd,
// authorized_keys): control characters, newlines and NULs.
func checkLine(field, s string, maxBytes int, forbidden string) error {
	if len(s) > maxBytes {
		return invalid("%s is too long", field)
	}
	if !utf8.ValidString(s) {
		return invalid("%s is not valid UTF-8", field)
	}
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune(forbidden, r) {
			return invalid("%s contains a forbidden character", field)
		}
	}
	return nil
}

func checkDuration(field string, d interface{ AsDuration() time.Duration }, isSet bool) error {
	if !isSet {
		return nil
	}
	v := d.AsDuration()
	if v < 0 || v > maxTimeout {
		return invalid("%s must be between 0 and 24h", field)
	}
	return nil
}

func checkLimit(v uint32) error {
	if v > maxListLimit {
		return invalid("limit must be at most %d", maxListLimit)
	}
	return nil
}

func checkMode(field string, m uint32) error {
	if m > 0o7777 {
		return invalid("%s must be a permission mode (at most 07777)", field)
	}
	return nil
}

func checkJournalFilter(f *agentv1.JournalFilter) error {
	if f == nil {
		return nil
	}
	if len(f.GetUnits()) > 64 {
		return invalid("filter.units: at most 64 units")
	}
	for _, u := range f.GetUnits() {
		if err := checkUnit(u); err != nil {
			return err
		}
	}
	if f.GetMaxPriority() > 7 {
		return invalid("filter.max_priority must be 0-7")
	}
	if err := checkLine("filter.contains", f.GetContains(), 256, ""); err != nil {
		return err
	}
	return checkLine("filter.after_cursor", f.GetAfterCursor(), 512, "")
}

// Validate checks an operation's arguments.
func Validate(op *agentv1.Operation) error {
	info, err := Describe(op)
	if err != nil {
		return err
	}
	if info.Disabled != "" {
		return errors.New(info.Disabled)
	}
	switch k := op.GetKind().(type) {
	case *agentv1.Operation_PackagesRefresh, *agentv1.Operation_PackagesAutoremove, *agentv1.Operation_StorageGet,
		*agentv1.Operation_NetworkGet, *agentv1.Operation_FirewallGet, *agentv1.Operation_ServiceList,
		*agentv1.Operation_UserList:
		return nil
	case *agentv1.Operation_PackagesUpgrade:
		return checkNames("names", k.PackagesUpgrade.GetNames(), pkgRe, false)
	case *agentv1.Operation_PackagesInstall:
		return checkNames("names", k.PackagesInstall.GetNames(), pkgVersionRe, true)
	case *agentv1.Operation_PackagesRemove:
		return checkNames("names", k.PackagesRemove.GetNames(), pkgRe, true)
	case *agentv1.Operation_PackagesHold:
		return checkNames("names", k.PackagesHold.GetNames(), pkgRe, true)
	case *agentv1.Operation_PackagesList:
		if err := checkLine("query", k.PackagesList.GetQuery(), 128, ""); err != nil {
			return err
		}
		return checkLimit(k.PackagesList.GetLimit())
	case *agentv1.Operation_ServiceAction:
		if k.ServiceAction.GetAction() == agentv1.ServiceAction_ACTION_UNSPECIFIED {
			return invalid("action is required")
		}
		return checkUnit(k.ServiceAction.GetUnit())
	case *agentv1.Operation_ServiceStatus:
		return checkUnit(k.ServiceStatus.GetUnit())
	case *agentv1.Operation_JournalQuery:
		if err := checkLimit(k.JournalQuery.GetLimit()); err != nil {
			return err
		}
		return checkJournalFilter(k.JournalQuery.GetFilter())
	case *agentv1.Operation_JournalFollow:
		if k.JournalFollow.GetBacklog() > 1000 {
			return invalid("backlog must be at most 1000")
		}
		return checkJournalFilter(k.JournalFollow.GetFilter())
	case *agentv1.Operation_ProcessList:
		return checkLimit(k.ProcessList.GetLimit())
	case *agentv1.Operation_ProcessSignal:
		if k.ProcessSignal.GetPid() <= 1 {
			return invalid("pid must be greater than 1")
		}
		if k.ProcessSignal.GetSignal() == agentv1.ProcessSignal_SIGNAL_UNSPECIFIED {
			return invalid("signal is required")
		}
		return nil
	case *agentv1.Operation_Power:
		p := k.Power
		if p.GetAction() == agentv1.PowerAction_ACTION_UNSPECIFIED {
			return invalid("action is required")
		}
		if err := checkDuration("delay", p.GetDelay(), p.GetDelay() != nil); err != nil {
			return err
		}
		return checkLine("message", p.GetMessage(), 256, "")
	case *agentv1.Operation_Exec:
		return validateExec(k.Exec)
	case *agentv1.Operation_TerminalOpen:
		t := k.TerminalOpen
		if err := checkUser("run_as", t.GetRunAs(), false); err != nil {
			return err
		}
		if t.GetCols() > 1000 || t.GetRows() > 1000 {
			return invalid("terminal size is too large")
		}
		if !termRe.MatchString(t.GetTerm()) {
			return invalid("term: invalid terminal type")
		}
		return checkDuration("idle_timeout", t.GetIdleTimeout(), t.GetIdleTimeout() != nil)
	case *agentv1.Operation_FileList:
		if err := checkLimit(k.FileList.GetLimit()); err != nil {
			return err
		}
		return CheckPath("path", k.FileList.GetPath())
	case *agentv1.Operation_FileStat:
		return CheckPath("path", k.FileStat.GetPath())
	case *agentv1.Operation_FileRead:
		if k.FileRead.GetLength() > maxFileRead {
			return invalid("length must be at most %d bytes (use a file download for larger files)", maxFileRead)
		}
		return CheckPath("path", k.FileRead.GetPath())
	case *agentv1.Operation_FileWrite:
		w := k.FileWrite
		if len(w.GetContent()) > maxFileContent {
			return invalid("content must be at most %d bytes (use a file upload for larger files)", maxFileContent)
		}
		if w.GetExpectedSha256() != "" && !sha256Re.MatchString(w.GetExpectedSha256()) {
			return invalid("expected_sha256 must be lowercase hex SHA-256")
		}
		if err := checkMode("create_mode", w.GetCreateMode()); err != nil {
			return err
		}
		if err := checkUser("create_owner", w.GetCreateOwner(), false); err != nil {
			return err
		}
		if err := checkUser("create_group", w.GetCreateGroup(), false); err != nil {
			return err
		}
		return CheckPath("path", w.GetPath())
	case *agentv1.Operation_FileMkdir:
		if err := checkMode("mode", k.FileMkdir.GetMode()); err != nil {
			return err
		}
		return CheckPath("path", k.FileMkdir.GetPath())
	case *agentv1.Operation_FileDelete:
		if k.FileDelete.GetPath() == "/" {
			return invalid("path: refusing to delete /")
		}
		return CheckPath("path", k.FileDelete.GetPath())
	case *agentv1.Operation_FileRename:
		if err := CheckPath("from_path", k.FileRename.GetFromPath()); err != nil {
			return err
		}
		return CheckPath("to_path", k.FileRename.GetToPath())
	case *agentv1.Operation_FileChmod:
		if err := checkMode("mode", k.FileChmod.GetMode()); err != nil {
			return err
		}
		return CheckPath("path", k.FileChmod.GetPath())
	case *agentv1.Operation_FileChown:
		c := k.FileChown
		if c.GetOwner() == "" && c.GetGroup() == "" {
			return invalid("owner or group is required")
		}
		if err := checkUser("owner", c.GetOwner(), false); err != nil {
			return err
		}
		if err := checkUser("group", c.GetGroup(), false); err != nil {
			return err
		}
		return CheckPath("path", c.GetPath())
	case *agentv1.Operation_FileAclGet:
		return CheckPath("path", k.FileAclGet.GetPath())
	case *agentv1.Operation_FileDownload:
		return CheckPath("path", k.FileDownload.GetPath())
	case *agentv1.Operation_FileUpload:
		u := k.FileUpload
		if !sha256Re.MatchString(u.GetSha256()) {
			return invalid("sha256 must be lowercase hex SHA-256")
		}
		if u.GetExpectedSha256() != "" && !sha256Re.MatchString(u.GetExpectedSha256()) {
			return invalid("expected_sha256 must be lowercase hex SHA-256")
		}
		if err := checkMode("create_mode", u.GetCreateMode()); err != nil {
			return err
		}
		return CheckPath("path", u.GetPath())
	case *agentv1.Operation_UserCreate:
		return validateUserCreate(k.UserCreate)
	case *agentv1.Operation_UserModify:
		m := k.UserModify
		if err := checkUser("name", m.GetName(), true); err != nil {
			return err
		}
		if m.FullName != nil {
			if err := checkLine("full_name", m.GetFullName(), 256, ":,="); err != nil {
				return err
			}
		}
		if m.Shell != nil {
			if err := CheckPath("shell", m.GetShell()); err != nil {
				return err
			}
		}
		if m.GetGroups() != nil {
			return checkNames("groups", m.GetGroups().GetValues(), userRe, false)
		}
		return nil
	case *agentv1.Operation_UserDelete:
		return checkUser("name", k.UserDelete.GetName(), true)
	case *agentv1.Operation_UserSetPassword:
		if err := checkUser("name", k.UserSetPassword.GetName(), true); err != nil {
			return err
		}
		return checkPassword(k.UserSetPassword.GetPassword(), true)
	case *agentv1.Operation_GroupCreate:
		return checkUser("name", k.GroupCreate.GetName(), true)
	case *agentv1.Operation_GroupDelete:
		return checkUser("name", k.GroupDelete.GetName(), true)
	case *agentv1.Operation_GroupSetMembers:
		if err := checkUser("name", k.GroupSetMembers.GetName(), true); err != nil {
			return err
		}
		if len(k.GroupSetMembers.GetMembers()) > maxMembers {
			return invalid("members: at most %d", maxMembers)
		}
		return checkNames("members", k.GroupSetMembers.GetMembers(), userRe, false)
	case *agentv1.Operation_AuthorizedKeysGet:
		return checkUser("user", k.AuthorizedKeysGet.GetUser(), true)
	case *agentv1.Operation_AuthorizedKeysSet:
		if err := checkUser("user", k.AuthorizedKeysSet.GetUser(), true); err != nil {
			return err
		}
		return checkKeyLines(k.AuthorizedKeysSet.GetLines())
	case *agentv1.Operation_AgentUpgrade:
		if v := k.AgentUpgrade.GetVersion(); v != "" && !versionRe.MatchString(v) {
			return invalid("version: invalid version")
		}
		return nil
	case *agentv1.Operation_AgentUninstall:
		return nil
	case *agentv1.Operation_InventoryRefresh:
		for _, kind := range k.InventoryRefresh.GetKinds() {
			if _, ok := agentv1.InventoryKind_name[int32(kind)]; !ok || kind == agentv1.InventoryKind_INVENTORY_KIND_UNSPECIFIED {
				return invalid("kinds: unknown inventory kind")
			}
		}
		return nil
	}
	return fmt.Errorf("operation %q has no validator", info.Type)
}

func validateExec(e *agentv1.Exec) error {
	argv := e.GetArgv()
	if len(argv) == 0 || argv[0] == "" {
		return invalid("argv: a program is required")
	}
	if len(argv) > maxExecArgs {
		return invalid("argv: at most %d arguments", maxExecArgs)
	}
	total := 0
	for _, a := range argv {
		total += len(a)
		if strings.ContainsRune(a, 0) || !utf8.ValidString(a) {
			return invalid("argv: arguments must be valid UTF-8 without NUL bytes")
		}
	}
	if total > maxExecArgBytes {
		return invalid("argv: arguments are too long")
	}
	if err := checkUser("run_as", e.GetRunAs(), false); err != nil {
		return err
	}
	if e.GetWorkingDir() != "" {
		if err := CheckPath("working_dir", e.GetWorkingDir()); err != nil {
			return err
		}
	}
	if len(e.GetEnv()) > maxExecEnv {
		return invalid("env: at most %d variables", maxExecEnv)
	}
	for _, kv := range e.GetEnv() {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || !envKeyRe.MatchString(key) {
			return invalid("env: entries must be KEY=VALUE")
		}
		if err := checkLine("env value", val, 32<<10, ""); err != nil {
			return err
		}
	}
	if len(e.GetStdin()) > maxExecStdin {
		return invalid("stdin must be at most %d bytes", maxExecStdin)
	}
	return checkDuration("timeout", e.GetTimeout(), e.GetTimeout() != nil)
}

func validateUserCreate(u *agentv1.UserCreate) error {
	if err := checkUser("name", u.GetName(), true); err != nil {
		return err
	}
	if err := checkLine("full_name", u.GetFullName(), 256, ":,="); err != nil {
		return err
	}
	if u.GetShell() != "" {
		if err := CheckPath("shell", u.GetShell()); err != nil {
			return err
		}
	}
	if err := checkNames("groups", u.GetGroups(), userRe, false); err != nil {
		return err
	}
	if err := checkPassword(u.GetPassword(), false); err != nil {
		return err
	}
	return checkKeyLines(u.GetAuthorizedKeys())
}

func checkPassword(p string, required bool) error {
	if p == "" {
		if required {
			return invalid("password is required")
		}
		return nil
	}
	if len(p) > 1024 {
		return invalid("password is too long")
	}
	// chpasswd reads "user:password\n": control characters would inject extra records.
	return checkLine("password", p, 1024, "")
}

func checkKeyLines(lines []string) error {
	if len(lines) > maxKeyLines {
		return invalid("authorized keys: at most %d lines", maxKeyLines)
	}
	for _, l := range lines {
		if err := checkLine("authorized key", l, maxKeyLineBytes, ""); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RedactedMarker replaces secret values in stored operations.
const RedactedMarker = "<redacted>"

// Redact returns a copy of op with secret or bulky fields removed, suitable for storage, logs and
// the command history. The original (unredacted) operation is only ever signed and sent.
func Redact(op *agentv1.Operation) *agentv1.Operation {
	if op == nil {
		return nil
	}
	out := proto.CloneOf(op)
	switch k := out.GetKind().(type) {
	case *agentv1.Operation_UserCreate:
		if k.UserCreate.GetPassword() != "" {
			k.UserCreate.Password = RedactedMarker
		}
	case *agentv1.Operation_UserSetPassword:
		k.UserSetPassword.Password = RedactedMarker
	case *agentv1.Operation_Exec:
		if len(k.Exec.GetStdin()) > 0 {
			k.Exec.Stdin = []byte(RedactedMarker)
		}
		for i, kv := range k.Exec.GetEnv() {
			if key, _, ok := strings.Cut(kv, "="); ok {
				k.Exec.Env[i] = key + "=" + RedactedMarker
			}
		}
	case *agentv1.Operation_FileWrite:
		k.FileWrite.Content = nil
	case *agentv1.Operation_NetworkApply:
		for name := range k.NetworkApply.GetFiles() {
			k.NetworkApply.Files[name] = RedactedMarker
		}
	}
	return out
}
