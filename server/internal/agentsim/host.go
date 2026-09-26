// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package agentsim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/ops"
)

// Capabilities per owner-policy profile (docs/agent/local-policy.md).
var profileCaps = map[agentv1.PolicyProfile][]agentv1.Capability{
	agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE: {
		agentv1.Capability_CAPABILITY_TELEMETRY, agentv1.Capability_CAPABILITY_PACKAGES_READ,
		agentv1.Capability_CAPABILITY_SERVICES_READ, agentv1.Capability_CAPABILITY_LOGS_READ,
		agentv1.Capability_CAPABILITY_PROCESSES_READ, agentv1.Capability_CAPABILITY_NETWORK_READ,
		agentv1.Capability_CAPABILITY_USERS_READ, agentv1.Capability_CAPABILITY_STORAGE_READ,
	},
}

func init() {
	observe := profileCaps[agentv1.PolicyProfile_POLICY_PROFILE_OBSERVE]
	operate := append(slices.Clone(observe),
		agentv1.Capability_CAPABILITY_PACKAGES_UPGRADE, agentv1.Capability_CAPABILITY_SERVICES_MANAGE,
		agentv1.Capability_CAPABILITY_PROCESSES_SIGNAL, agentv1.Capability_CAPABILITY_POWER,
		agentv1.Capability_CAPABILITY_AGENT_UPGRADE)
	administer := append(slices.Clone(operate),
		agentv1.Capability_CAPABILITY_PACKAGES_INSTALL, agentv1.Capability_CAPABILITY_PACKAGES_REMOVE,
		agentv1.Capability_CAPABILITY_NETWORK_MANAGE, agentv1.Capability_CAPABILITY_FIREWALL_MANAGE,
		agentv1.Capability_CAPABILITY_FILES_READ, agentv1.Capability_CAPABILITY_FILES_WRITE,
		agentv1.Capability_CAPABILITY_FILES_PERMISSIONS, agentv1.Capability_CAPABILITY_USERS_MANAGE)
	full := append(slices.Clone(administer), agentv1.Capability_CAPABILITY_EXEC, agentv1.Capability_CAPABILITY_TERMINAL)
	profileCaps[agentv1.PolicyProfile_POLICY_PROFILE_OPERATE] = operate
	profileCaps[agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER] = administer
	profileCaps[agentv1.PolicyProfile_POLICY_PROFILE_FULL] = full
}

// PolicyFor returns the effective policy of a profile.
func PolicyFor(p agentv1.PolicyProfile) *agentv1.EffectivePolicy {
	caps := profileCaps[p]
	if caps == nil {
		p, caps = agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER, profileCaps[agentv1.PolicyProfile_POLICY_PROFILE_ADMINISTER]
	}
	sum := sha256.Sum256([]byte("simulated policy " + p.String()))
	pol := &agentv1.EffectivePolicy{
		Version: 1, Profile: p, Digest: hex.EncodeToString(sum[:]), Allowed: slices.Clone(caps), LoadedAt: timestamppb.Now(),
		Files:    &agentv1.FilesPolicy{ReadAllow: []string{"/etc/**", "/var/log/**", "/srv/**"}, WriteAllow: []string{"/srv/**"}, Deny: []string{"/etc/shadow", "/etc/sudoers*"}},
		Users:    &agentv1.UsersPolicy{ProtectedUsers: []string{"root", "central-agent"}},
		Services: &agentv1.ServicesPolicy{ProtectedUnits: []string{"central-agent*.service", "ssh.service"}},
		RunAs:    &agentv1.RunAsPolicy{AllowedUsers: []string{"ubuntu", "deploy"}, DefaultUser: "ubuntu"},
	}
	if p == agentv1.PolicyProfile_POLICY_PROFILE_FULL {
		pol.RunAs = &agentv1.RunAsPolicy{AllowedUsers: []string{"root", "ubuntu", "deploy"}, DefaultUser: "root", AllowRoot: true}
	}
	return pol
}

var distros = []struct{ id, version, codename, pretty, kernel string }{
	{"ubuntu", "24.04", "noble", "Ubuntu 24.04.1 LTS", "6.8.0-45-generic"},
	{"ubuntu", "22.04", "jammy", "Ubuntu 22.04.5 LTS", "5.15.0-122-generic"},
	{"debian", "12", "bookworm", "Debian GNU/Linux 12 (bookworm)", "6.1.0-25-amd64"},
	{"debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)", "6.12.9-amd64"},
}

var basePackages = []struct{ name, version, section string }{
	{"bash", "5.2.21-2ubuntu4", "shells"},
	{"coreutils", "9.4-3ubuntu6", "utils"},
	{"openssl", "3.0.13-0ubuntu3.4", "utils"},
	{"libssl3t64", "3.0.13-0ubuntu3.4", "libs"},
	{"openssh-server", "1:9.6p1-3ubuntu13.5", "net"},
	{"curl", "8.5.0-2ubuntu10.4", "web"},
	{"nginx", "1.24.0-2ubuntu7.1", "httpd"},
	{"systemd", "255.4-1ubuntu8.4", "admin"},
	{"linux-image-generic", "6.8.0-45.45", "kernel"},
	{"libc6", "2.39-0ubuntu8.3", "libs"},
	{"python3", "3.12.3-0ubuntu2", "python"},
	{"vim", "2:9.1.0016-1ubuntu7.2", "editors"},
	{"git", "1:2.43.0-1ubuntu7.1", "vcs"},
	{"sudo", "1.9.15p5-3ubuntu5", "admin"},
	{"tzdata", "2024a-3ubuntu1.1", "localization"},
	{"ca-certificates", "20240203", "misc"},
	{"postgresql-16", "16.4-0ubuntu0.24.04.2", "database"},
	{"rsync", "3.2.7-1ubuntu1", "net"},
}

var baseServices = []string{
	"nginx.service", "ssh.service", "cron.service", "systemd-journald.service", "systemd-networkd.service",
	"systemd-resolved.service", "rsyslog.service", "unattended-upgrades.service", "central-agent.service",
	"central-agent-helper.service", "postgresql@16-main.service",
}

// Host is a simulated machine.
type Host struct {
	mu sync.Mutex

	name, machineID, bootID string
	ip                      string
	distro                  int
	booted                  time.Time
	rnd                     *rand.Rand
	threads                 uint32
	memTotal                uint64
	diskTotal               uint64

	cpuBase, cpu, mem, disk float64
	netRx, netTx            float64
	lastSample              time.Time

	packages       []*agentv1.Package
	updates        []*agentv1.PendingUpdate
	rebootRequired bool
	services       map[string]*agentv1.Service
	Policy         *agentv1.EffectivePolicy
	reboot         func()
}

// SetReboot sets the function called after a simulated reboot command (the runner reconnects).
func (h *Host) SetReboot(fn func()) {
	h.mu.Lock()
	h.reboot = fn
	h.mu.Unlock()
}

// NewHost creates a deterministic simulated host (seed decides its shape).
func NewHost(name string, seed uint64, profile agentv1.PolicyProfile) *Host {
	rnd := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	h := &Host{
		name: name, rnd: rnd, distro: rnd.IntN(len(distros)), booted: time.Now().Add(-time.Duration(rnd.IntN(90*24)) * time.Hour),
		threads: []uint32{2, 4, 8, 16, 32}[rnd.IntN(5)], memTotal: uint64(2+rnd.IntN(62)) << 30,
		diskTotal: uint64(20+rnd.IntN(480)) << 30, cpuBase: 3 + rnd.Float64()*35, mem: 20 + rnd.Float64()*55,
		disk: 25 + rnd.Float64()*55, services: map[string]*agentv1.Service{}, Policy: PolicyFor(profile),
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "machine %s %d", name, seed))
	h.machineID = hex.EncodeToString(sum[:16])
	h.ip = fmt.Sprintf("10.%d.%d.%d", 1+rnd.IntN(3), rnd.IntN(250), 2+rnd.IntN(250))
	h.newBoot()
	for _, p := range basePackages {
		h.packages = append(h.packages, &agentv1.Package{
			Name: p.name, Version: p.version, Architecture: "amd64", Section: p.section,
			Summary: p.name + " package", InstalledSizeBytes: uint64(100+rnd.IntN(90000)) << 10,
		})
	}
	for _, p := range h.packages {
		if rnd.Float64() < 0.35 {
			h.updates = append(h.updates, &agentv1.PendingUpdate{
				Name: p.GetName(), CurrentVersion: p.GetVersion(), CandidateVersion: p.GetVersion() + ".1", Architecture: "amd64",
				Archive: distros[h.distro].codename + "-updates", Origin: "Ubuntu", Security: rnd.Float64() < 0.4,
			})
		}
	}
	h.rebootRequired = rnd.Float64() < 0.15
	for _, s := range baseServices {
		h.services[s] = &agentv1.Service{
			Name: s, Description: strings.TrimSuffix(s, ".service"), LoadState: "loaded", ActiveState: "active", SubState: "running",
			UnitFileState: "enabled", MainPid: uint32(300 + rnd.IntN(30000)), MemoryBytes: uint64(5+rnd.IntN(400)) << 20,
			ActiveSince: timestamppb.New(h.booted), Protected: strings.HasPrefix(s, "central-agent") || s == "ssh.service",
		}
	}
	return h
}

func (h *Host) newBoot() {
	sum := sha256.Sum256(fmt.Appendf(nil, "boot %s %d", h.name, h.booted.UnixNano()))
	h.bootID = hex.EncodeToString(sum[:16])
}

// Facts returns the host facts.
func (h *Host) Facts() *agentv1.HostFacts {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := distros[h.distro]
	ip := h.ip
	return &agentv1.HostFacts{
		Hostname: h.name, Fqdn: h.name + ".sim.internal", MachineId: h.machineID, BootId: h.bootID,
		Os:            &agentv1.OSInfo{Id: d.id, VersionId: d.version, Codename: d.codename, PrettyName: d.pretty, IdLike: []string{"debian"}},
		KernelRelease: d.kernel, Arch: "amd64", Virtualization: "kvm",
		Cpu:              &agentv1.CPUInfo{Model: "AMD EPYC 7763 64-Core Processor", Cores: max(h.threads/2, 1), Threads: h.threads},
		MemoryTotalBytes: h.memTotal, Timezone: "UTC",
		Addresses: []*agentv1.InterfaceAddress{{Interface: "eth0", Cidr: ip + "/24"}},
		BootedAt:  timestamppb.New(h.booted),
	}
}

func walk(r *rand.Rand, v, lo, hi, step float64) float64 {
	return math.Min(hi, math.Max(lo, v+(r.Float64()*2-1)*step))
}

// Sample produces the next metrics sample.
func (h *Host) Sample(now time.Time) *agentv1.MetricsSample {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cpu = walk(h.rnd, h.cpuBase, 0.5, 100, 8)
	if h.rnd.Float64() < 0.003 { // occasional spike
		h.cpu = 85 + h.rnd.Float64()*15
	}
	h.mem = walk(h.rnd, h.mem, 10, 97, 1.5)
	h.disk = math.Min(99, h.disk+h.rnd.Float64()*0.002)
	h.netRx = math.Max(0, walk(h.rnd, h.netRx, 0, 50e6, 2e5))
	h.netTx = math.Max(0, walk(h.rnd, h.netTx, 0, 20e6, 1e5))
	used := uint64(float64(h.memTotal) * h.mem / 100)
	diskUsed := uint64(float64(h.diskTotal) * h.disk / 100)
	load := h.cpu / 100 * float64(h.threads)
	h.lastSample = now
	return &agentv1.MetricsSample{
		Time: timestamppb.New(now), CpuPercent: float32(h.cpu), CpuIowaitPercent: float32(h.rnd.Float64() * 2),
		Load1: float32(load), Load5: float32(load * 0.9), Load15: float32(load * 0.8),
		MemoryTotalBytes: h.memTotal, MemoryUsedBytes: used, MemoryAvailableBytes: h.memTotal - used,
		MemoryCachedBytes: h.memTotal / 5, SwapTotalBytes: 2 << 30, SwapUsedBytes: uint64(h.rnd.IntN(64)) << 20,
		Filesystems: []*agentv1.FilesystemUsage{
			{Mountpoint: "/", Device: "/dev/vda1", Fstype: "ext4", TotalBytes: h.diskTotal, UsedBytes: diskUsed},
			{Mountpoint: "/boot", Device: "/dev/vda15", Fstype: "vfat", TotalBytes: 512 << 20, UsedBytes: 120 << 20},
		},
		Disks: []*agentv1.DiskIO{{
			Device: "vda", ReadBytesPerSecond: h.rnd.Float64() * 5e6, WriteBytesPerSecond: h.rnd.Float64() * 8e6,
			UtilizationPercent: float32(h.rnd.Float64() * 20),
		}},
		Network:      []*agentv1.NetIO{{Interface: "eth0", RxBytesPerSecond: h.netRx, TxBytesPerSecond: h.netTx}},
		ProcessCount: uint32(120 + h.rnd.IntN(200)), UptimeSeconds: uint64(now.Sub(h.booted).Seconds()),
	}
}

func contentHash(m proto.Message) string {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Inventory returns every inventory report.
func (h *Host) Inventory() []*agentv1.InventoryReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := timestamppb.Now()
	pk := &agentv1.PackageInventory{Packages: h.packages}
	up := &agentv1.UpdateInventory{Updates: h.updates, RebootRequired: h.rebootRequired, ListsUpdatedAt: now, UnattendedUpgradesEnabled: true}
	svc := &agentv1.ServiceInventory{}
	for _, name := range slices.Sorted(maps.Keys(h.services)) {
		svc.Services = append(svc.Services, h.services[name])
	}
	users := h.userInventory()
	netw := h.networkState()
	stor := h.storageState()
	return []*agentv1.InventoryReport{
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_PACKAGES, ContentHash: contentHash(pk), CollectedAt: now, Payload: &agentv1.InventoryReport_Packages{Packages: pk}},
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_UPDATES, ContentHash: contentHash(up), CollectedAt: now, Payload: &agentv1.InventoryReport_Updates{Updates: up}},
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_SERVICES, ContentHash: contentHash(svc), CollectedAt: now, Payload: &agentv1.InventoryReport_Services{Services: svc}},
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_USERS, ContentHash: contentHash(users), CollectedAt: now, Payload: &agentv1.InventoryReport_Users{Users: users}},
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_NETWORK, ContentHash: contentHash(netw), CollectedAt: now, Payload: &agentv1.InventoryReport_Network{Network: netw}},
		{Kind: agentv1.InventoryKind_INVENTORY_KIND_STORAGE, ContentHash: contentHash(stor), CollectedAt: now, Payload: &agentv1.InventoryReport_Storage{Storage: stor}},
	}
}

func (h *Host) userInventory() *agentv1.UserInventory {
	return &agentv1.UserInventory{
		Users: []*agentv1.LinuxUser{
			{Name: "root", Uid: 0, Gid: 0, Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}, HasPassword: true, Protected: true},
			{Name: "ubuntu", Uid: 1000, Gid: 1000, FullName: "Ubuntu", Home: "/home/ubuntu", Shell: "/bin/bash", Groups: []string{"ubuntu", "sudo"}, Sudo: true, AuthorizedKeyCount: 2},
			{Name: "deploy", Uid: 1001, Gid: 1001, FullName: "Deploy", Home: "/home/deploy", Shell: "/bin/bash", Groups: []string{"deploy", "www-data"}, AuthorizedKeyCount: 1},
			{Name: "central-agent", Uid: 998, Gid: 998, Home: "/var/lib/central-agent", Shell: "/usr/sbin/nologin", System: true, Protected: true},
		},
		Groups: []*agentv1.LinuxGroup{{Name: "sudo", Gid: 27, Members: []string{"ubuntu"}}, {Name: "www-data", Gid: 33, Members: []string{"deploy"}, System: true}},
	}
}

func (h *Host) networkState() *agentv1.NetworkState {
	return &agentv1.NetworkState{
		Interfaces: []*agentv1.NetworkInterface{{Name: "eth0", Type: "ether", MacAddress: "52:54:00:12:34:56", Mtu: 1500, OperState: "up", Addresses: []string{h.ip + "/24"}, Dhcp: true}},
		Routes:     []*agentv1.Route{{Destination: "default", Gateway: "10.1.2.1", Interface: "eth0", Protocol: "dhcp", Metric: 100}},
		DnsServers: []string{"10.1.2.1"}, Backend: agentv1.NetworkBackend_NETWORK_BACKEND_NETPLAN,
		Listening: []*agentv1.ListeningSocket{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}, {Protocol: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"}},
	}
}

func (h *Host) storageState() *agentv1.StorageState {
	return &agentv1.StorageState{
		BlockDevices: []*agentv1.BlockDevice{{Name: "vda", Type: "disk", SizeBytes: h.diskTotal + 1<<30, Model: "QEMU HARDDISK"}, {Name: "vda1", Type: "part", SizeBytes: h.diskTotal, Fstype: "ext4", Mountpoint: "/", Parent: "vda"}},
		Mounts:       []*agentv1.Mount{{Device: "/dev/vda1", Mountpoint: "/", Fstype: "ext4", Options: []string{"rw", "relatime"}, SizeBytes: h.diskTotal, UsedBytes: uint64(float64(h.diskTotal) * h.disk / 100)}},
	}
}

func output(seq *uint64, text string) *agentv1.OutputChunk {
	c := &agentv1.OutputChunk{Stream: agentv1.OutputChunk_STREAM_STDOUT, Data: []byte(text), Seq: *seq}
	*seq++
	return c
}

func succeeded(result *agentv1.CommandResult) *agentv1.CommandUpdate {
	return &agentv1.CommandUpdate{State: agentv1.CommandState_COMMAND_STATE_SUCCEEDED, ProgressPercent: 100, Result: result, FinishedAt: timestamppb.Now()}
}

func failed(code agentv1.ErrorCode, msg string) *agentv1.CommandUpdate {
	state := agentv1.CommandState_COMMAND_STATE_FAILED
	if code == agentv1.ErrorCode_ERROR_CODE_POLICY_DENIED || code == agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED {
		state = agentv1.CommandState_COMMAND_STATE_REJECTED
	}
	return &agentv1.CommandUpdate{State: state, Error: &agentv1.CommandError{Code: code, Message: msg}, FinishedAt: timestamppb.Now()}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// SendInventory sends every inventory report on conn.
func (h *Host) SendInventory(conn *Conn) {
	for _, r := range h.Inventory() {
		_ = conn.Send(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Inventory{Inventory: r}})
	}
}

// Handle executes a verified command like the agent's helper would (policy first).
func (h *Host) Handle(ctx context.Context, conn *Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
	info, err := ops.Describe(cmd.GetOperation())
	if err != nil {
		return failed(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED, err.Error())
	}
	h.mu.Lock()
	allowed := slices.Contains(h.Policy.GetAllowed(), info.Capability)
	paused := h.Policy.GetPaused()
	h.mu.Unlock()
	if paused {
		return failed(agentv1.ErrorCode_ERROR_CODE_PAUSED, "remote operations are paused by the owner")
	}
	if !allowed {
		return failed(agentv1.ErrorCode_ERROR_CODE_POLICY_DENIED, "the owner policy does not allow "+strings.ToLower(info.Capability.String()))
	}
	_ = conn.Update(&agentv1.CommandUpdate{CommandId: cmd.GetCommandId(), State: agentv1.CommandState_COMMAND_STATE_RUNNING, ProgressPercent: -1, StartedAt: timestamppb.Now()})
	switch k := cmd.GetOperation().GetKind().(type) {
	case *agentv1.Operation_PackagesRefresh:
		return h.aptLines(ctx, conn, cmd, []string{
			"Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease", "Get:2 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]",
			"Fetched 1,252 kB in 1s (1,045 kB/s)", "Reading package lists...",
		}, nil)
	case *agentv1.Operation_PackagesUpgrade:
		return h.upgrade(ctx, conn, cmd, k.PackagesUpgrade)
	case *agentv1.Operation_PackagesInstall, *agentv1.Operation_PackagesRemove, *agentv1.Operation_PackagesHold, *agentv1.Operation_PackagesAutoremove:
		return h.aptLines(ctx, conn, cmd, []string{"Reading package lists...", "Building dependency tree...", "0 upgraded, 1 newly installed, 0 to remove."}, nil)
	case *agentv1.Operation_PackagesList:
		h.mu.Lock()
		var list []*agentv1.Package
		for _, p := range h.packages {
			if q := k.PackagesList.GetQuery(); q == "" || strings.Contains(p.GetName(), q) {
				list = append(list, p)
			}
		}
		h.mu.Unlock()
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_PackagesList{PackagesList: &agentv1.PackagesListResult{Packages: list, Total: uint32(len(list))}}})
	case *agentv1.Operation_ServiceList:
		h.mu.Lock()
		res := &agentv1.ServiceListResult{}
		for _, name := range slices.Sorted(maps.Keys(h.services)) {
			res.Services = append(res.Services, h.services[name])
		}
		h.mu.Unlock()
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_ServiceList{ServiceList: res}})
	case *agentv1.Operation_ServiceStatus:
		h.mu.Lock()
		svc := h.services[k.ServiceStatus.GetUnit()]
		h.mu.Unlock()
		if svc == nil {
			return failed(agentv1.ErrorCode_ERROR_CODE_NOT_FOUND, "unit not found")
		}
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_ServiceStatus{ServiceStatus: &agentv1.ServiceStatusResult{Service: svc, FragmentPath: "/usr/lib/systemd/system/" + svc.GetName()}}})
	case *agentv1.Operation_ServiceAction:
		return h.serviceAction(k.ServiceAction)
	case *agentv1.Operation_JournalQuery:
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_JournalQuery{JournalQuery: &agentv1.JournalQueryResult{Entries: h.journal(int(min(max(k.JournalQuery.GetLimit(), 1), 200)))}}})
	case *agentv1.Operation_ProcessList:
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_ProcessList{ProcessList: h.processes()}})
	case *agentv1.Operation_ProcessSignal:
		return succeeded(nil)
	case *agentv1.Operation_Power:
		h.mu.Lock()
		hook := h.reboot
		h.mu.Unlock()
		if k.Power.GetAction() == agentv1.PowerAction_ACTION_REBOOT && hook != nil {
			go func() {
				time.Sleep(2 * time.Second)
				h.mu.Lock()
				h.booted = time.Now()
				h.rebootRequired = false
				h.newBoot()
				h.mu.Unlock()
				hook()
			}()
		}
		return succeeded(nil)
	case *agentv1.Operation_Exec:
		seq := uint64(0)
		_ = conn.Update(&agentv1.CommandUpdate{
			CommandId: cmd.GetCommandId(), State: agentv1.CommandState_COMMAND_STATE_RUNNING,
			Output: []*agentv1.OutputChunk{output(&seq, "(simulated) "+strings.Join(k.Exec.GetArgv(), " ")+"\n")},
		})
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_Exec{Exec: &agentv1.ExecResult{ExitCode: 0}}})
	case *agentv1.Operation_TerminalOpen:
		return h.terminal(ctx, conn, cmd, k.TerminalOpen)
	case *agentv1.Operation_JournalFollow:
		return h.followJournal(ctx, conn, cmd)
	case *agentv1.Operation_StorageGet:
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_Storage{Storage: h.storageState()}})
	case *agentv1.Operation_NetworkGet:
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_Network{Network: h.networkState()}})
	case *agentv1.Operation_FirewallGet:
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_Firewall{Firewall: &agentv1.FirewallState{
			Installed: true, Active: true, DefaultIncoming: "deny", DefaultOutgoing: "allow",
			Rules: []*agentv1.FirewallRule{{Number: 1, Text: "22/tcp ALLOW IN Anywhere", Action: "allow", Direction: "in", Port: "22", Protocol: "tcp"}},
		}}})
	case *agentv1.Operation_UserList:
		u := h.userInventory()
		return succeeded(&agentv1.CommandResult{Kind: &agentv1.CommandResult_UserList{UserList: &agentv1.UserListResult{Users: u.GetUsers(), Groups: u.GetGroups()}}})
	case *agentv1.Operation_InventoryRefresh:
		h.SendInventory(conn)
		return succeeded(nil)
	case *agentv1.Operation_AgentUpgrade, *agentv1.Operation_AgentUninstall:
		return succeeded(nil)
	}
	return failed(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED, info.Type+" is not simulated")
}

func (h *Host) aptLines(ctx context.Context, conn *Conn, cmd *agentv1.Command, lines []string, result *agentv1.CommandResult) *agentv1.CommandUpdate {
	var seq uint64
	for i, l := range lines {
		if !sleepCtx(ctx, 150*time.Millisecond) {
			return &agentv1.CommandUpdate{State: agentv1.CommandState_COMMAND_STATE_CANCELLED}
		}
		_ = conn.Update(&agentv1.CommandUpdate{
			CommandId: cmd.GetCommandId(), State: agentv1.CommandState_COMMAND_STATE_RUNNING, Status: l,
			ProgressPercent: int32((i + 1) * 100 / len(lines)), Output: []*agentv1.OutputChunk{output(&seq, l+"\n")},
		})
	}
	return succeeded(result)
}

func (h *Host) upgrade(ctx context.Context, conn *Conn, cmd *agentv1.Command, u *agentv1.PackagesUpgrade) *agentv1.CommandUpdate {
	h.mu.Lock()
	var todo, keep []*agentv1.PendingUpdate
	for _, p := range h.updates {
		if (len(u.GetNames()) == 0 || slices.Contains(u.GetNames(), p.GetName())) && (!u.GetSecurityOnly() || p.GetSecurity()) {
			todo = append(todo, p)
		} else {
			keep = append(keep, p)
		}
	}
	h.mu.Unlock()
	lines := []string{"Reading package lists...", "Building dependency tree...", fmt.Sprintf("%d upgraded, 0 newly installed, 0 to remove.", len(todo))}
	res := &agentv1.PackagesChangeResult{}
	for _, p := range todo {
		lines = append(lines, fmt.Sprintf("Unpacking %s (%s) over (%s) ...", p.GetName(), p.GetCandidateVersion(), p.GetCurrentVersion()),
			fmt.Sprintf("Setting up %s (%s) ...", p.GetName(), p.GetCandidateVersion()))
		res.Changes = append(res.Changes, &agentv1.PackageChange{Name: p.GetName(), OldVersion: p.GetCurrentVersion(), NewVersion: p.GetCandidateVersion(), Action: agentv1.PackageChange_ACTION_UPGRADED})
		if strings.HasPrefix(p.GetName(), "linux-image") || p.GetName() == "libc6" || p.GetName() == "systemd" {
			res.RebootRequired = true
		}
	}
	final := h.aptLines(ctx, conn, cmd, lines, &agentv1.CommandResult{Kind: &agentv1.CommandResult_PackagesChange{PackagesChange: res}})
	if final.GetState() != agentv1.CommandState_COMMAND_STATE_SUCCEEDED {
		return final
	}
	h.mu.Lock()
	h.updates = keep
	for _, p := range todo {
		for _, pk := range h.packages {
			if pk.GetName() == p.GetName() {
				pk.Version = p.GetCandidateVersion()
			}
		}
	}
	h.rebootRequired = h.rebootRequired || res.GetRebootRequired()
	h.mu.Unlock()
	h.SendInventory(conn)
	return final
}

func (h *Host) serviceAction(a *agentv1.ServiceAction) *agentv1.CommandUpdate {
	h.mu.Lock()
	defer h.mu.Unlock()
	svc := h.services[a.GetUnit()]
	if svc == nil {
		return failed(agentv1.ErrorCode_ERROR_CODE_NOT_FOUND, "unit "+a.GetUnit()+" not found")
	}
	if svc.GetProtected() && (a.GetAction() == agentv1.ServiceAction_ACTION_STOP || a.GetAction() == agentv1.ServiceAction_ACTION_DISABLE || a.GetAction() == agentv1.ServiceAction_ACTION_MASK) {
		return failed(agentv1.ErrorCode_ERROR_CODE_POLICY_DENIED, a.GetUnit()+" is protected by the owner policy")
	}
	switch a.GetAction() {
	case agentv1.ServiceAction_ACTION_STOP:
		svc.ActiveState, svc.SubState = "inactive", "dead"
	case agentv1.ServiceAction_ACTION_START, agentv1.ServiceAction_ACTION_RESTART, agentv1.ServiceAction_ACTION_RELOAD:
		svc.ActiveState, svc.SubState, svc.ActiveSince = "active", "running", timestamppb.Now()
	case agentv1.ServiceAction_ACTION_ENABLE, agentv1.ServiceAction_ACTION_UNMASK:
		svc.UnitFileState = "enabled"
	case agentv1.ServiceAction_ACTION_DISABLE:
		svc.UnitFileState = "disabled"
	case agentv1.ServiceAction_ACTION_MASK:
		svc.UnitFileState = "masked"
	case agentv1.ServiceAction_ACTION_UNSPECIFIED:
	}
	return succeeded(nil)
}

var journalLines = []struct{ unit, msg string }{
	{"nginx.service", `10.1.2.9 - - "GET /healthz HTTP/1.1" 200 2`},
	{"ssh.service", "Accepted publickey for deploy from 10.1.2.50 port 51234 ssh2"},
	{"cron.service", "(root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)"},
	{"systemd-resolved.service", "Clock change detected. Flushing caches."},
	{"unattended-upgrades.service", "No packages found that can be upgraded unattended"},
	{"kernel", "EXT4-fs (vda1): re-mounted. Quota mode: none."},
}

func (h *Host) journal(n int) []*agentv1.JournalEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	out := make([]*agentv1.JournalEntry, 0, n)
	for i := range n {
		l := journalLines[h.rnd.IntN(len(journalLines))]
		out = append(out, &agentv1.JournalEntry{
			Time: timestamppb.New(now.Add(-time.Duration(n-i) * 7 * time.Second)), Priority: 6, Unit: l.unit,
			Identifier: strings.TrimSuffix(l.unit, ".service"), Pid: uint32(100 + h.rnd.IntN(9000)), Message: l.msg, Hostname: h.name,
			Cursor: fmt.Sprintf("s=%s;i=%x", h.bootID[:8], now.UnixNano()+int64(i)),
		})
	}
	return out
}

func (h *Host) processes() *agentv1.ProcessListResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	names := []string{"systemd", "sshd", "nginx", "postgres", "cron", "central-agent", "journald", "rsyslogd", "bash"}
	res := &agentv1.ProcessListResult{Total: uint32(len(names))}
	for i, n := range names {
		res.Processes = append(res.Processes, &agentv1.Process{
			Pid: uint32(1 + i*137), Ppid: 1, User: "root", Name: n, CommandLine: "/usr/sbin/" + n, State: "S",
			CpuPercent: h.rnd.Float64() * 5, RssBytes: uint64(4+h.rnd.IntN(300)) << 20, Threads: uint32(1 + h.rnd.IntN(8)),
			StartedAt: timestamppb.New(h.booted),
		})
	}
	return res
}

// terminal runs a tiny fake shell: echo, prompt, a few commands, "exit".
func (h *Host) terminal(ctx context.Context, conn *Conn, cmd *agentv1.Command, t *agentv1.TerminalOpen) *agentv1.CommandUpdate {
	s, err := conn.Attach(ctx, cmd)
	if err != nil {
		return failed(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "attach failed: "+err.Error())
	}
	user := t.GetRunAs()
	if user == "" {
		user = h.Policy.GetRunAs().GetDefaultUser()
	}
	prompt := fmt.Sprintf("\x1b[1;32m%s@%s\x1b[0m:\x1b[1;34m~\x1b[0m$ ", user, h.name)
	d := distros[h.distro]
	send := func(text string) {
		_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Data{Data: []byte(text)}})
	}
	send(fmt.Sprintf("Welcome to %s (GNU/Linux %s x86_64)\r\n\r\n  This is a simulated host (central-sim).\r\n\r\n%s", d.pretty, d.kernel, prompt))
	var line []byte
	for {
		f, err := s.Receive()
		if err != nil || f.GetClose() != nil {
			return succeeded(nil)
		}
		for _, b := range f.GetData() {
			switch b {
			case '\r', '\n':
				c := strings.TrimSpace(string(line))
				line = line[:0]
				send("\r\n")
				switch {
				case c == "exit" || c == "logout":
					s.Close(0)
					return succeeded(nil)
				case c == "":
				case c == "uptime":
					send(fmt.Sprintf(" %s up %d days, load average: 0.42, 0.37, 0.30\r\n", time.Now().Format("15:04:05"), int(time.Since(h.booted).Hours()/24)))
				case c == "hostname":
					send(h.name + "\r\n")
				case c == "whoami":
					send(user + "\r\n")
				case strings.HasPrefix(c, "echo "):
					send(strings.TrimPrefix(c, "echo ") + "\r\n")
				default:
					send(strings.Fields(c)[0] + ": command simulated (central-sim)\r\n")
				}
				send(prompt)
			case 0x7f, 0x08: // backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					send("\b \b")
				}
			case 0x03: // Ctrl+C
				line = line[:0]
				send("^C\r\n" + prompt)
			case 0x04: // Ctrl+D
				s.Close(0)
				return succeeded(nil)
			default:
				if b >= 0x20 {
					line = append(line, b)
					send(string([]byte{b}))
				}
			}
		}
	}
}

func (h *Host) followJournal(ctx context.Context, conn *Conn, cmd *agentv1.Command) *agentv1.CommandUpdate {
	s, err := conn.Attach(ctx, cmd)
	if err != nil {
		return failed(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "attach failed: "+err.Error())
	}
	backlog := int(min(max(cmd.GetOperation().GetJournalFollow().GetBacklog(), 1), 100))
	_ = s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Journal{Journal: &agentv1.JournalEntries{Entries: h.journal(backlog)}}})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if f, err := s.Receive(); err != nil || f.GetClose() != nil {
				return
			}
		}
	}()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-closed:
			return succeeded(nil)
		case <-ctx.Done():
			return succeeded(nil)
		case <-tick.C:
			if s.Send(&agentv1.SessionFrame{Frame: &agentv1.SessionFrame_Journal{Journal: &agentv1.JournalEntries{Entries: h.journal(1)}}}) != nil {
				return succeeded(nil)
			}
		}
	}
}
