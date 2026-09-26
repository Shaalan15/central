// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package enrollment implements agent enrollment: tokens, requests, pairing codes, risk flags
// and the approve/deny decisions. Transports (the agent listener and the admin API) call into
// it after their own authentication and rate limiting.
//
// Layers of protection, in order:
//  1. The enrollment key embeds the agent CA pin, so agents only send the secret to the real
//     Central (the agent checks the pin before sending anything).
//  2. Token checks: constant-time secret comparison, expiry, max uses (each request consumes a
//     use), revocation, allowed source CIDRs and hostname pattern.
//  3. Blocked public keys and a cap on pending requests per organization.
//  4. A human approver must type the pairing code printed on the host, which is derived from
//     the agent's public key, so approving a request made by someone else is not possible.
//  5. Risk flags highlight clones, reinstalls, unsupported systems and suspicious sources.
package enrollment

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/Shaalan15/central/gen/go/central/agent/v1"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/bus"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/fleet"
	"github.com/Shaalan15/central/server/internal/pki"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/validate"
)

// Formats and limits.
const (
	KeyPrefix            = "cek1."
	ProtocolVersion      = 1
	RequestTTL           = 24 * time.Hour
	MaxPendingPerOrg     = 500
	MaxWait              = 60 * time.Second
	DefaultWait          = 30 * time.Second
	PollInterval         = 5 * time.Second
	MaxPairingFailures   = 10
	manyRequestsFromIP   = 5
	tokenSecretPurpose   = "enrollment_token"
	pollSecretPurpose    = "enrollment_poll"
	pairingPrefix        = "central-pairing-v1\x00"
	maxTokenUses         = 10_000
	defaultTokenLifetime = 24 * time.Hour
	maxTokenLifetime     = 30 * 24 * time.Hour
	maxAutoLifetime      = 7 * 24 * time.Hour
	maxCIDRs             = 32
)

// Risk flag severities (stored names).
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Supported operating systems for Phase 1 (os-release ID → VERSION_ID).
var supportedOS = map[string][]string{
	"ubuntu": {"22.04", "24.04", "26.04"},
	"debian": {"12", "13"},
}

var (
	tokenIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15}$`)
	secretRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	fqdnRe     = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$`)
	machineRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	osIDRe     = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z.+~-]{1,64}$`)
	archRe     = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
)

// Service implements enrollment.
type Service struct {
	Holder *store.Holder
	PKI    *pki.Authority
	Fleet  *fleet.Index
	Bus    bus.Bus
	Audit  *audit.Recorder
	Log    *slog.Logger
	// MinAgentVersion flags older agents as outdated ("" disables the check).
	MinAgentVersion string

	now func() time.Time
	// Striped locks serialize read-modify-write cycles per token (use counts, revocation) and per
	// request (decisions) without serializing unrelated enrollments.
	tokenLocks   [64]sync.Mutex
	requestLocks [64]sync.Mutex
}

func stripe(key string) int {
	h := uint32(2166136261)
	for i := range len(key) {
		h = (h ^ uint32(key[i])) * 16777619
	}
	return int(h % 64)
}

func (s *Service) lockToken(id string) func() {
	m := &s.tokenLocks[stripe(id)]
	m.Lock()
	return m.Unlock
}

func (s *Service) lockRequest(id string) func() {
	m := &s.requestLocks[stripe(id)]
	m.Lock()
	return m.Unlock
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) st() (*store.Store, error) {
	st := s.Holder.Get()
	if st == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("central is not ready"))
	}
	return st, nil
}

func (s *Service) internal(err error) error {
	s.Log.Error("enrollment: internal error", "error", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

func invalidArg(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// ---- Tokens ----

// TokenSpec defines a new enrollment token.
type TokenSpec struct {
	Name            string
	ApprovalMode    string
	MaxUses         int
	ExpiresIn       time.Duration
	AllowedCIDRs    []string
	HostnamePattern string
	DefaultTags     []string
	DefaultGroupID  string
}

// ValidTokenID reports whether s has the token ID format.
func ValidTokenID(s string) bool { return tokenIDRe.MatchString(s) }

func newTokenID() string {
	for {
		id := crypto.RandomToken(12)
		if tokenIDRe.MatchString(id) {
			return id
		}
	}
}

// FormatKey builds an enrollment key.
func FormatKey(tokenID, secret, pin string) string {
	return KeyPrefix + tokenID + "." + secret + "." + pin
}

// ParseKey splits an enrollment key.
func ParseKey(key string) (tokenID, secret, pin string, err error) {
	rest, ok := strings.CutPrefix(key, KeyPrefix)
	parts := strings.Split(rest, ".")
	if !ok || len(parts) != 3 || !tokenIDRe.MatchString(parts[0]) || !secretRe.MatchString(parts[1]) || !secretRe.MatchString(parts[2]) {
		return "", "", "", errors.New("malformed enrollment key")
	}
	return parts[0], parts[1], parts[2], nil
}

// CreateToken validates spec and creates a token. It returns the enrollment key (shown once).
func (s *Service) CreateToken(ctx context.Context, orgID string, actor store.PrincipalRef, spec TokenSpec) (*store.EnrollmentToken, string, error) {
	st, err := s.st()
	if err != nil {
		return nil, "", err
	}
	name, err := validate.DisplayText("name", spec.Name, 100)
	if err != nil {
		return nil, "", invalidArg("%v", err)
	}
	mode := spec.ApprovalMode
	if mode == "" {
		mode = store.ApprovalManual
	}
	if mode != store.ApprovalManual && mode != store.ApprovalAuto {
		return nil, "", invalidArg("invalid approval mode")
	}
	uses := spec.MaxUses
	if uses == 0 {
		if mode == store.ApprovalAuto {
			return nil, "", invalidArg("auto-approval tokens need an explicit max_uses")
		}
		uses = 1
	}
	if uses < 1 || uses > maxTokenUses {
		return nil, "", invalidArg("max_uses must be between 1 and %d", maxTokenUses)
	}
	life := spec.ExpiresIn
	if life == 0 {
		life = defaultTokenLifetime
	}
	limit := maxTokenLifetime
	if mode == store.ApprovalAuto {
		limit = maxAutoLifetime
	}
	if life < time.Minute || life > limit {
		return nil, "", invalidArg("the token lifetime must be between 1 minute and %s", limit)
	}
	if len(spec.AllowedCIDRs) > maxCIDRs {
		return nil, "", invalidArg("at most %d allowed CIDRs", maxCIDRs)
	}
	cidrs := make([]string, 0, len(spec.AllowedCIDRs))
	for _, c := range spec.AllowedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, "", invalidArg("invalid CIDR %q", c)
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	if pat := spec.HostnamePattern; pat != "" {
		if len(pat) > 253 || !utf8.ValidString(pat) {
			return nil, "", invalidArg("invalid hostname pattern")
		}
		if _, err := path.Match(pat, ""); err != nil {
			return nil, "", invalidArg("invalid hostname pattern: %v", err)
		}
	}
	tags, err := validate.Tags(spec.DefaultTags)
	if err != nil {
		return nil, "", invalidArg("%v", err)
	}
	if spec.DefaultGroupID != "" {
		if _, err := st.AgentGroups.Get(ctx, store.Tenant(orgID), spec.DefaultGroupID); err != nil {
			return nil, "", invalidArg("the default group does not exist")
		}
	}
	pin := s.PKI.Pin()
	now := s.clock().UTC()
	secret := crypto.RandomToken(32)
	t := &store.EnrollmentToken{
		ID: newTokenID(), OrgID: orgID, Name: name, SecretHash: crypto.HashToken(tokenSecretPurpose, secret),
		ApprovalMode: mode, MaxUses: uses, AllowedCIDRs: cidrs, HostnamePattern: spec.HostnamePattern,
		DefaultTags: tags, DefaultGroupID: spec.DefaultGroupID, CreatedBy: actor.ID, CreatedAt: now,
		ExpiresAt: now.Add(life),
	}
	if err := st.EnrollmentTokens.Create(ctx, store.Tenant(orgID), t); err != nil {
		return nil, "", s.internal(err)
	}
	_ = s.Audit.Record(ctx, audit.Event{
		OrgID: orgID, Action: "enrollment.token_created", TargetType: "enrollment_token", TargetID: t.ID, TargetDisplay: name,
		Details: map[string]string{"approval": mode, "max_uses": strconv.Itoa(uses), "expires_at": t.ExpiresAt.Format(time.RFC3339)},
	})
	return t, FormatKey(t.ID, secret, pin), nil
}

// Token states.
const (
	TokenActive    = "active"
	TokenExpired   = "expired"
	TokenExhausted = "exhausted"
	TokenRevoked   = "revoked"
)

// TokenState derives a token's state.
func TokenState(t *store.EnrollmentToken, now time.Time) string {
	switch {
	case !t.RevokedAt.IsZero():
		return TokenRevoked
	case !now.Before(t.ExpiresAt):
		return TokenExpired
	case t.Uses >= t.MaxUses:
		return TokenExhausted
	}
	return TokenActive
}

// RevokeToken stops a token from accepting enrollments.
func (s *Service) RevokeToken(ctx context.Context, orgID, tokenID string) (*store.EnrollmentToken, error) {
	st, err := s.st()
	if err != nil {
		return nil, err
	}
	defer s.lockToken(tokenID)()
	return s.revokeTokenLocked(ctx, st, orgID, tokenID)
}

func (s *Service) revokeTokenLocked(ctx context.Context, st *store.Store, orgID, tokenID string) (*store.EnrollmentToken, error) {
	t, err := st.EnrollmentTokens.Get(ctx, store.Tenant(orgID), tokenID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
	}
	if err != nil {
		return nil, s.internal(err)
	}
	if t.RevokedAt.IsZero() {
		t.RevokedAt = s.clock().UTC()
		if err := st.EnrollmentTokens.Update(ctx, store.Tenant(orgID), t); err != nil {
			return nil, s.internal(err)
		}
		_ = s.Audit.Record(ctx, audit.Event{
			OrgID: orgID, Action: "enrollment.token_revoked", TargetType: "enrollment_token", TargetID: t.ID, TargetDisplay: t.Name,
		})
	}
	return t, nil
}

// ---- Requests ----

// PairingCode derives the code both sides display ("XXXX-XXXX").
func PairingCode(spkiDER []byte, enrollmentID string, nonce []byte) string {
	h := sha256.New()
	h.Write([]byte(pairingPrefix))
	h.Write(spkiDER)
	h.Write([]byte(enrollmentID))
	h.Write(nonce)
	enc := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	code := enc.EncodeToString(h.Sum(nil))[:8]
	return code[:4] + "-" + code[4:]
}

// NormalizePairingCode applies Crockford decoding rules to a typed code (case, dashes, spaces,
// O→0, I/L→1).
func NormalizePairingCode(s string) string {
	s = strings.ToUpper(s)
	s = strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(s)
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

// SubmitInput is an agent's Enroll call.
type SubmitInput struct {
	TokenID, TokenSecret string
	CSRDER               []byte
	Facts                *agentv1.HostFacts
	AgentVersion         string
	ProtocolVersion      uint32
	SourceIP             netip.Addr
}

// SubmitResult is returned to the agent.
type SubmitResult struct {
	Request    *store.EnrollmentRequest
	PollSecret string
}

var errInvalidKey = connect.NewError(connect.CodePermissionDenied, errors.New("invalid enrollment key"))

// Submit creates an enrollment request.
func (s *Service) Submit(ctx context.Context, in SubmitInput) (*SubmitResult, error) {
	st, err := s.st()
	if err != nil {
		return nil, err
	}
	if !tokenIDRe.MatchString(in.TokenID) || !secretRe.MatchString(in.TokenSecret) {
		return nil, errInvalidKey
	}
	if in.ProtocolVersion != ProtocolVersion {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("unsupported agent protocol version %d (Central speaks %d)", in.ProtocolVersion, ProtocolVersion))
	}
	csr, spkiHash, err := pki.ParseCSR(in.CSRDER)
	if err != nil {
		return nil, invalidArg("%v", err)
	}
	facts, err := sanitizeFacts(in.Facts)
	if err != nil {
		return nil, invalidArg("%v", err)
	}
	version := in.AgentVersion
	if !versionRe.MatchString(version) {
		return nil, invalidArg("invalid agent version")
	}

	defer s.lockToken(in.TokenID)()
	// The token is looked up across organizations: its secret establishes the tenant.
	tok, err := st.EnrollmentTokens.Get(ctx, store.System(), in.TokenID)
	if errors.Is(err, store.ErrNotFound) {
		_ = crypto.EqualHashes(crypto.HashToken(tokenSecretPurpose, in.TokenSecret), strings.Repeat("0", 64)) // equal timing
		return nil, errInvalidKey
	}
	if err != nil {
		return nil, s.internal(err)
	}
	if !crypto.EqualHashes(crypto.HashToken(tokenSecretPurpose, in.TokenSecret), tok.SecretHash) {
		return nil, errInvalidKey
	}
	now := s.clock().UTC()
	orgID := tok.OrgID
	scope := store.Tenant(orgID)
	reject := func(code connect.Code, reason string) error {
		_ = s.Audit.Record(ctx, audit.Event{
			OrgID: orgID, Actor: store.PrincipalRef{Kind: store.PrincipalAgent, Display: facts.GetHostname()},
			Action: "enrollment.rejected", TargetType: "enrollment_token", TargetID: tok.ID, TargetDisplay: tok.Name,
			Result: store.AuditDenied, SourceIP: in.SourceIP.String(), Details: map[string]string{"reason": reason},
		})
		return connect.NewError(code, errors.New(reason))
	}
	if state := TokenState(tok, now); state != TokenActive {
		return nil, reject(connect.CodePermissionDenied, "the enrollment key is "+state)
	}
	if len(tok.AllowedCIDRs) > 0 && !inCIDRs(in.SourceIP, tok.AllowedCIDRs) {
		return nil, reject(connect.CodePermissionDenied, "this enrollment key does not allow enrollment from "+in.SourceIP.String())
	}
	if tok.HostnamePattern != "" {
		if ok, _ := path.Match(tok.HostnamePattern, facts.GetHostname()); !ok {
			return nil, reject(connect.CodePermissionDenied, "the hostname does not match the enrollment key's hostname pattern")
		}
	}
	if _, err := st.BlockedKeys.Get(ctx, scope, store.DeriveID(orgID, spkiHash)); err == nil {
		return nil, reject(connect.CodePermissionDenied, "this agent key has been blocked")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(err)
	}
	pendingCount, err := st.EnrollmentRequests.Count(ctx, scope, store.Eq("status", store.EnrollmentPending).
		And("expires_at", store.OpGt, store.Millis(now)))
	if err != nil {
		return nil, s.internal(err)
	}
	if pendingCount >= MaxPendingPerOrg {
		return nil, reject(connect.CodeResourceExhausted, "too many pending enrollment requests; approve or deny some first")
	}

	// A new request from the same key supersedes an older pending one (agent restarted).
	superseded, _, err := st.EnrollmentRequests.Find(ctx, scope, store.Eq("public_key", spkiHash).And("status", store.OpEq, store.EnrollmentPending))
	if err != nil {
		return nil, s.internal(err)
	}
	for _, old := range superseded {
		old.Status, old.DecidedAt, old.DecisionNote = store.EnrollmentExpired, now, "superseded by a newer request from the same key"
		if err := st.EnrollmentRequests.Update(ctx, scope, old); err != nil {
			return nil, s.internal(err)
		}
		s.Fleet.AdjustPending(orgID, -1)
		s.Bus.Publish(bus.EnrollmentTopic(old.ID), old.Status)
	}

	tok.Uses++
	tok.LastUsedAt = now
	if err := st.EnrollmentTokens.Update(ctx, scope, tok); err != nil {
		return nil, s.internal(err)
	}

	factsBytes, _ := proto.Marshal(facts)
	id := store.NewID()
	nonce := crypto.RandomBytes(16)
	pollSecret := crypto.RandomToken(32)
	req := &store.EnrollmentRequest{
		ID: id, OrgID: orgID, TokenID: tok.ID, Status: store.EnrollmentPending,
		PollSecretHash: crypto.HashToken(pollSecretPurpose, pollSecret), ServerNonce: nonce,
		PairingCode: PairingCode(csr.RawSubjectPublicKeyInfo, id, nonce), CSRDER: in.CSRDER, PublicKeySHA256: spkiHash,
		Hostname: facts.GetHostname(), MachineID: facts.GetMachineId(), FactsProto: factsBytes, AgentVersion: version,
		SourceIP: in.SourceIP.String(), CreatedAt: now, ExpiresAt: now.Add(RequestTTL),
	}
	req.RiskFlags, req.ReplacesAgentID, err = s.assessRisk(ctx, st, req, facts, in.SourceIP)
	if err != nil {
		return nil, s.internal(err)
	}
	if err := st.EnrollmentRequests.Create(ctx, scope, req); err != nil {
		return nil, s.internal(err)
	}
	s.Fleet.AdjustPending(orgID, 1)
	actor := store.PrincipalRef{Kind: store.PrincipalAgent, ID: id, Display: facts.GetHostname()}
	_ = s.Audit.Record(ctx, audit.Event{
		OrgID: orgID, Actor: actor, Action: "enrollment.requested", TargetType: "enrollment_request", TargetID: id,
		TargetDisplay: facts.GetHostname(), SourceIP: in.SourceIP.String(),
		Details: map[string]string{"token_id": tok.ID, "risk_flags": flagCodes(req.RiskFlags)},
	})

	if tok.ApprovalMode == store.ApprovalAuto && maxSeverity(req.RiskFlags) < 2 {
		system := store.PrincipalRef{Kind: store.PrincipalSystem, ID: "auto-approval", Display: "auto-approval (token " + tok.Name + ")"}
		approved, err := s.approve(ctx, st, req, tok, system, ApproveInput{Note: "approved automatically by the enrollment token"})
		if err != nil {
			return nil, err
		}
		req = approved
	}
	return &SubmitResult{Request: req, PollSecret: pollSecret}, nil
}

func inCIDRs(ip netip.Addr, cidrs []string) bool {
	ip = ip.Unmap()
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func flagCodes(flags []store.RiskFlag) string {
	codes := make([]string, 0, len(flags))
	for _, f := range flags {
		codes = append(codes, f.Code)
	}
	return strings.Join(codes, ",")
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

func maxSeverity(flags []store.RiskFlag) int {
	m := 0
	for _, f := range flags {
		m = max(m, severityRank(f.Severity))
	}
	return m
}

func truncateString(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// sanitizeFacts validates identity facts strictly and truncates descriptive ones.
func sanitizeFacts(in *agentv1.HostFacts) (*agentv1.HostFacts, error) {
	if in == nil {
		return nil, errors.New("host facts are required")
	}
	f := proto.CloneOf(in)
	if !hostnameRe.MatchString(f.GetHostname()) {
		return nil, errors.New("invalid hostname")
	}
	if f.GetFqdn() != "" && (len(f.GetFqdn()) > 253 || !fqdnRe.MatchString(f.GetFqdn())) {
		return nil, errors.New("invalid fqdn")
	}
	if !machineRe.MatchString(f.GetMachineId()) {
		return nil, errors.New("invalid machine-id (expected 32 lowercase hex characters)")
	}
	if f.GetBootId() != "" && len(f.GetBootId()) > 64 {
		return nil, errors.New("invalid boot id")
	}
	if f.GetArch() != "" && !archRe.MatchString(f.GetArch()) {
		return nil, errors.New("invalid architecture")
	}
	if os := f.GetOs(); os != nil {
		if !osIDRe.MatchString(os.GetId()) {
			return nil, errors.New("invalid os id")
		}
		os.VersionId = truncateString(os.GetVersionId(), 32)
		os.Codename = truncateString(os.GetCodename(), 32)
		os.PrettyName = truncateString(os.GetPrettyName(), 128)
		if len(os.GetIdLike()) > 8 {
			os.IdLike = os.GetIdLike()[:8]
		}
		for i, v := range os.GetIdLike() {
			os.IdLike[i] = truncateString(v, 32)
		}
	} else {
		return nil, errors.New("os information is required")
	}
	f.KernelRelease = truncateString(f.GetKernelRelease(), 128)
	f.Virtualization = truncateString(f.GetVirtualization(), 32)
	f.Timezone = truncateString(f.GetTimezone(), 64)
	if c := f.GetCpu(); c != nil {
		c.Model = truncateString(c.GetModel(), 128)
	}
	addrs := f.GetAddresses()
	if len(addrs) > 64 {
		addrs = addrs[:64]
	}
	f.Addresses = nil
	for _, a := range addrs {
		if _, err := netip.ParsePrefix(a.GetCidr()); err != nil {
			continue
		}
		f.Addresses = append(f.Addresses, &agentv1.InterfaceAddress{Interface: truncateString(a.GetInterface(), 32), Cidr: a.GetCidr()})
	}
	return f, nil
}

// SanitizeFacts is sanitizeFacts for the agent stream (Hello).
func SanitizeFacts(in *agentv1.HostFacts) (*agentv1.HostFacts, error) { return sanitizeFacts(in) }

func (s *Service) assessRisk(ctx context.Context, st *store.Store, req *store.EnrollmentRequest, f *agentv1.HostFacts, src netip.Addr) ([]store.RiskFlag, string, error) {
	var flags []store.RiskFlag
	add := func(code, sev, msg string) {
		flags = append(flags, store.RiskFlag{Code: code, Severity: sev, Message: msg})
	}
	scope := store.Tenant(req.OrgID)
	replaces := ""
	same, _, err := st.Agents.Find(ctx, scope, store.Eq("machine_id", req.MachineID).And("lifecycle", store.OpEq, store.AgentActive))
	if err != nil {
		return nil, "", err
	}
	if len(same) > 0 {
		replaces = same[0].ID
		add("duplicate_machine_id", SeverityWarning, fmt.Sprintf(
			"an active agent (%s) already has this machine-id: this is a reinstall or a cloned machine; approving revokes the existing agent",
			same[0].Name))
	}
	for _, v := range s.Fleet.All(req.OrgID, func(v *fleet.View) bool { return v.Active() }) {
		if strings.EqualFold(v.Agent.Hostname, req.Hostname) && v.Agent.MachineID != req.MachineID {
			add("duplicate_hostname", SeverityInfo, "another active agent ("+v.Agent.Name+") has the same hostname")
			break
		}
	}
	os := f.GetOs()
	if versions, ok := supportedOS[os.GetId()]; !ok || !slices.Contains(versions, os.GetVersionId()) {
		add("unsupported_os", SeverityWarning, fmt.Sprintf("%s %s is not a supported system (Ubuntu 22.04/24.04/26.04 LTS, Debian 12/13)",
			os.GetId(), os.GetVersionId()))
	}
	if s.MinAgentVersion != "" && compareVersions(req.AgentVersion, s.MinAgentVersion) < 0 {
		add("outdated_agent", SeverityWarning, "agent "+req.AgentVersion+" is older than the minimum supported version "+s.MinAgentVersion)
	}
	fromIP, err := st.EnrollmentRequests.Count(ctx, scope, store.Eq("source_ip", req.SourceIP).
		And("status", store.OpEq, store.EnrollmentPending))
	if err != nil {
		return nil, "", err
	}
	if fromIP >= manyRequestsFromIP {
		add("many_requests_from_ip", SeverityWarning, fmt.Sprintf("%d other pending requests come from %s", fromIP, req.SourceIP))
	}
	onHost := false
	for _, a := range f.GetAddresses() {
		if p, err := netip.ParsePrefix(a.GetCidr()); err == nil && p.Addr() == src.Unmap() {
			onHost = true
		}
	}
	if !onHost {
		add("source_ip_not_on_host", SeverityInfo, "the request came from "+src.String()+
			", which is not one of the host's addresses (normal behind NAT or a proxy)")
	}
	return flags, replaces, nil
}

// compareVersions compares dotted numeric versions ("0.10.2" > "0.9"); pre-release suffixes
// are ignored.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	v, _, _ = strings.Cut(v, "+")
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// StatusResult is the agent-visible state of a request.
type StatusResult struct {
	Request     *store.EnrollmentRequest
	Credentials *agentv1.AgentCredentials
}

var errNoRequest = connect.NewError(connect.CodeNotFound, errors.New("enrollment request not found"))

// Status returns a request's state, waiting up to wait for a decision while it is pending.
func (s *Service) Status(ctx context.Context, id, pollSecret string, wait time.Duration) (*StatusResult, error) {
	st, err := s.st()
	if err != nil {
		return nil, err
	}
	if !store.ValidID(id) || !secretRe.MatchString(pollSecret) {
		return nil, errNoRequest
	}
	wait = min(max(wait, 0), MaxWait)
	sub := s.Bus.Subscribe(bus.EnrollmentTopic(id), 4)
	defer sub.Close()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		// The request is looked up across organizations: the poll secret establishes access.
		req, err := st.EnrollmentRequests.Get(ctx, store.System(), id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errNoRequest
		}
		if err != nil {
			return nil, s.internal(err)
		}
		if !crypto.EqualHashes(crypto.HashToken(pollSecretPurpose, pollSecret), req.PollSecretHash) {
			return nil, errNoRequest
		}
		if req.Status == store.EnrollmentPending && !s.clock().Before(req.ExpiresAt) {
			if req, err = s.expire(ctx, st, req); err != nil {
				return nil, err
			}
		}
		if req.Status != store.EnrollmentPending {
			return s.statusResult(req), nil
		}
		select {
		case <-sub.C:
		case <-deadline.C:
			return s.statusResult(req), nil
		case <-ctx.Done():
			return s.statusResult(req), nil
		}
	}
}

func (s *Service) statusResult(req *store.EnrollmentRequest) *StatusResult {
	out := &StatusResult{Request: req}
	if req.Status == store.EnrollmentApproved && len(req.CertificateDER) > 0 {
		key := s.PKI.ActiveSigningKey()
		out.Credentials = &agentv1.AgentCredentials{
			AgentId: req.AgentID, OrgId: req.OrgID, CertificateDer: req.CertificateDER,
			CaCertificatesDer:  [][]byte{s.PKI.CACertificate().Raw},
			CommandSigningKeys: []*agentv1.CommandSigningKey{SigningKeyProto(key)},
		}
	}
	return out
}

func (s *Service) expire(ctx context.Context, st *store.Store, req *store.EnrollmentRequest) (*store.EnrollmentRequest, error) {
	req.Status, req.DecidedAt, req.DecisionNote = store.EnrollmentExpired, s.clock().UTC(), "no decision before the request expired"
	if err := st.EnrollmentRequests.Update(ctx, store.Tenant(req.OrgID), req); err != nil {
		return nil, s.internal(err)
	}
	s.Fleet.AdjustPending(req.OrgID, -1)
	return req, nil
}

// ExpireStale marks overdue pending requests as expired (housekeeping).
func (s *Service) ExpireStale(ctx context.Context) error {
	st := s.Holder.Get()
	if st == nil {
		return nil
	}
	now := s.clock()
	stale, _, err := st.EnrollmentRequests.Find(ctx, store.System(), store.Eq("status", store.EnrollmentPending).
		And("expires_at", store.OpLte, store.Millis(now)).Page(store.MaxLimit, ""))
	if err != nil {
		return err
	}
	for _, r := range stale {
		if _, err := s.expire(ctx, st, r); err != nil {
			return err
		}
		s.Bus.Publish(bus.EnrollmentTopic(r.ID), r.Status)
	}
	return nil
}

// ApproveInput carries the approver's choices.
type ApproveInput struct {
	PairingCode string
	Name        string
	Tags        []string
	GroupID     string
	Note        string
}

func (s *Service) pendingRequest(ctx context.Context, st *store.Store, orgID, id string) (*store.EnrollmentRequest, error) {
	if !store.ValidID(id) {
		return nil, errNoRequest
	}
	req, err := st.EnrollmentRequests.Get(ctx, store.Tenant(orgID), id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNoRequest
	}
	if err != nil {
		return nil, s.internal(err)
	}
	if req.Status == store.EnrollmentPending && !s.clock().Before(req.ExpiresAt) {
		if req, err = s.expire(ctx, st, req); err != nil {
			return nil, err
		}
	}
	if req.Status != store.EnrollmentPending {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the request is "+req.Status+", not pending"))
	}
	return req, nil
}

// Approve approves a pending request after checking the pairing code.
func (s *Service) Approve(ctx context.Context, orgID, id string, actor store.PrincipalRef, in ApproveInput) (*store.EnrollmentRequest, error) {
	st, err := s.st()
	if err != nil {
		return nil, err
	}
	defer s.lockRequest(id)()
	req, err := s.pendingRequest(ctx, st, orgID, id)
	if err != nil {
		return nil, err
	}
	typed := NormalizePairingCode(in.PairingCode)
	if subtle.ConstantTimeCompare([]byte(typed), []byte(req.PairingCode)) != 1 {
		req.PairingFailures++
		note := ""
		if req.PairingFailures >= MaxPairingFailures {
			req.Status, req.DecidedAt, req.DecisionNote = store.EnrollmentDenied, s.clock().UTC(), "denied after too many wrong pairing codes"
			note = "; the request was denied"
			s.Fleet.AdjustPending(orgID, -1)
		}
		if err := st.EnrollmentRequests.Update(ctx, store.Tenant(orgID), req); err != nil {
			return nil, s.internal(err)
		}
		if req.Status == store.EnrollmentDenied {
			s.Bus.Publish(bus.EnrollmentTopic(req.ID), req.Status)
		}
		_ = s.Audit.Record(ctx, audit.Event{
			OrgID: orgID, Action: "enrollment.pairing_mismatch", TargetType: "enrollment_request", TargetID: req.ID,
			TargetDisplay: req.Hostname, Result: store.AuditFailure,
		})
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the pairing code does not match the code shown on the host"+note))
	}
	tok, err := st.EnrollmentTokens.Get(ctx, store.Tenant(orgID), req.TokenID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(err)
	}
	return s.approve(ctx, st, req, tok, actor, in)
}

func (s *Service) approve(ctx context.Context, st *store.Store, req *store.EnrollmentRequest, tok *store.EnrollmentToken, actor store.PrincipalRef, in ApproveInput) (*store.EnrollmentRequest, error) {
	orgID := req.OrgID
	scope := store.Tenant(orgID)
	name := in.Name
	if name == "" {
		name = req.Hostname
	}
	name, err := validate.DisplayText("name", name, 100)
	if err != nil {
		return nil, invalidArg("%v", err)
	}
	tags, group := in.Tags, in.GroupID
	if tags == nil && tok != nil {
		tags = tok.DefaultTags
	}
	if tags, err = validate.Tags(tags); err != nil {
		return nil, invalidArg("%v", err)
	}
	if group == "" && tok != nil {
		group = tok.DefaultGroupID
	}
	if group != "" {
		if _, err := st.AgentGroups.Get(ctx, scope, group); err != nil {
			if in.GroupID != "" {
				return nil, invalidArg("the group does not exist")
			}
			group = "" // the token's default group was deleted
		}
	}
	note, err := validate.OptionalText("note", in.Note, 500)
	if err != nil {
		return nil, invalidArg("%v", err)
	}
	csr, spki, err := pki.ParseCSR(req.CSRDER)
	if err != nil || spki != req.PublicKeySHA256 {
		return nil, s.internal(fmt.Errorf("stored CSR invalid: %w", err))
	}
	agentID := store.NewID()
	cert, err := s.PKI.IssueAgentCertificate(csr, orgID, agentID)
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.clock().UTC()
	facts := &agentv1.HostFacts{}
	_ = proto.Unmarshal(req.FactsProto, facts)
	agent := &store.Agent{
		ID: agentID, OrgID: orgID, Name: name, Hostname: req.Hostname, MachineID: req.MachineID,
		Lifecycle: store.AgentActive, Tags: tags, GroupID: group, PublicKeySHA256: req.PublicKeySHA256,
		CertSerial: pki.SerialString(cert), CertNotAfter: cert.NotAfter, EnrolledAt: now, ApprovedBy: actor.ID,
		ApprovedByName: actor.Display, EnrollmentTokenID: req.TokenID, FactsProto: req.FactsProto,
		AgentVersion: req.AgentVersion, LastIP: req.SourceIP, UpdatedAt: now,
	}
	if err := s.Fleet.Create(ctx, agent); err != nil {
		return nil, s.internal(err)
	}
	if req.ReplacesAgentID != "" {
		if _, err := s.Fleet.Revoke(ctx, orgID, req.ReplacesAgentID, "replaced by a new enrollment of the same machine"); err != nil &&
			!errors.Is(err, fleet.ErrRevoked) && !errors.Is(err, fleet.ErrNotFound) {
			s.Log.Warn("enrollment: revoking the replaced agent failed", "agent", req.ReplacesAgentID, "error", err)
		}
	}
	req.Status, req.DecidedAt, req.DecidedBy, req.DecidedByName = store.EnrollmentApproved, now, actor.ID, actor.Display
	req.DecisionNote, req.AgentID, req.CertificateDER = note, agentID, cert.Raw
	if err := st.EnrollmentRequests.Update(ctx, scope, req); err != nil {
		return nil, s.internal(err)
	}
	s.Fleet.AdjustPending(orgID, -1)
	s.Bus.Publish(bus.EnrollmentTopic(req.ID), req.Status)
	_ = s.Audit.Record(ctx, audit.Event{
		OrgID: orgID, Actor: actor, Action: "agent.approved", TargetType: "agent", TargetID: agentID, TargetDisplay: name,
		Details: map[string]string{
			"enrollment_request": req.ID, "token_id": req.TokenID, "risk_flags": flagCodes(req.RiskFlags),
			"replaces_agent": req.ReplacesAgentID, "certificate_serial": agent.CertSerial,
		},
	})
	return req, nil
}

// DenyInput carries the denial options.
type DenyInput struct {
	Reason      string
	BlockKey    bool
	RevokeToken bool
}

// Deny denies a pending request.
func (s *Service) Deny(ctx context.Context, orgID, id string, actor store.PrincipalRef, in DenyInput) (*store.EnrollmentRequest, error) {
	st, err := s.st()
	if err != nil {
		return nil, err
	}
	reason, err := validate.OptionalText("reason", in.Reason, 500)
	if err != nil {
		return nil, invalidArg("%v", err)
	}
	defer s.lockRequest(id)()
	req, err := s.pendingRequest(ctx, st, orgID, id)
	if err != nil {
		return nil, err
	}
	scope := store.Tenant(orgID)
	now := s.clock().UTC()
	if in.BlockKey {
		if err := st.BlockedKeys.Upsert(ctx, scope, &store.BlockedKey{
			ID: store.DeriveID(orgID, req.PublicKeySHA256), OrgID: orgID, PublicKeySHA256: req.PublicKeySHA256,
			Reason: reason, CreatedBy: actor.ID, CreatedAt: now,
		}); err != nil {
			return nil, s.internal(err)
		}
	}
	if in.RevokeToken {
		unlock := s.lockToken(req.TokenID)
		_, err := s.revokeTokenLocked(ctx, st, orgID, req.TokenID)
		unlock()
		if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
			return nil, err
		}
	}
	req.Status, req.DecidedAt, req.DecidedBy, req.DecidedByName, req.DecisionNote = store.EnrollmentDenied, now, actor.ID, actor.Display, reason
	if err := st.EnrollmentRequests.Update(ctx, scope, req); err != nil {
		return nil, s.internal(err)
	}
	s.Fleet.AdjustPending(orgID, -1)
	s.Bus.Publish(bus.EnrollmentTopic(req.ID), req.Status)
	_ = s.Audit.Record(ctx, audit.Event{
		OrgID: orgID, Actor: actor, Action: "enrollment.denied", TargetType: "enrollment_request", TargetID: req.ID,
		TargetDisplay: req.Hostname, Details: map[string]string{
			"reason": reason, "block_key": strconv.FormatBool(in.BlockKey), "revoke_token": strconv.FormatBool(in.RevokeToken),
		},
	})
	return req, nil
}

// SigningKeyProto converts the active signing key.
func SigningKeyProto(k pki.SigningKey) *agentv1.CommandSigningKey {
	return &agentv1.CommandSigningKey{KeyId: k.ID, PublicKey: k.PublicKey, NotAfter: timestamppb.New(k.NotAfter)}
}
