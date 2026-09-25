// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"time"
)

// Entities persisted by Central. Field names are stable JSON keys: renaming one is a data
// migration. Secret material is never stored in plaintext: fields ending in "Sealed" hold
// values encrypted with the master key (crypto.Keyring), fields ending in "Hash" hold one-way
// hashes.

// Org is a tenant.
type Org struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Settings  OrgSettings `json:"settings"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// OrgSettings are per-tenant policies (durations in seconds).
type OrgSettings struct {
	MetricsIntervalSec         int  `json:"metrics_interval_sec"`
	SessionIdleTimeoutSec      int  `json:"session_idle_timeout_sec"`
	SessionMaxLifetimeSec      int  `json:"session_max_lifetime_sec"`
	StepUpWindowSec            int  `json:"step_up_window_sec"`
	MassActionConfirmThreshold int  `json:"mass_action_confirm_threshold"`
	AuditRetentionDays         int  `json:"audit_retention_days"`
	MetricsRetentionDays       int  `json:"metrics_retention_days"`
	RecordingRetentionDays     int  `json:"recording_retention_days"`
	RecordTerminalSessions     bool `json:"record_terminal_sessions"`
}

// DefaultOrgSettings returns secure defaults.
func DefaultOrgSettings() OrgSettings {
	return OrgSettings{
		MetricsIntervalSec:         15,
		SessionIdleTimeoutSec:      30 * 60,
		SessionMaxLifetimeSec:      12 * 3600,
		StepUpWindowSec:            10 * 60,
		MassActionConfirmThreshold: 10,
		AuditRetentionDays:         365,
		MetricsRetentionDays:       30,
		RecordingRetentionDays:     90,
		RecordTerminalSessions:     true,
	}
}

// EntityID implements Entity.
func (o *Org) EntityID() string { return o.ID }

// EntityOrgID implements Entity.
func (o *Org) EntityOrgID() string { return "" }

// User is a Central account (global: one account can belong to several orgs).
type User struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	DisplayName       string    `json:"display_name"`
	PasswordHash      string    `json:"password_hash"`
	Disabled          bool      `json:"disabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastLoginAt       time.Time `json:"last_login_at"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	// FailedLogins counts consecutive failures; LockedUntil throttles brute force.
	FailedLogins int       `json:"failed_logins"`
	LockedUntil  time.Time `json:"locked_until"`
	// WebAuthnID is the random user handle for passkeys.
	WebAuthnID []byte `json:"webauthn_id"`
}

// EntityID implements Entity.
func (u *User) EntityID() string { return u.ID }

// EntityOrgID implements Entity.
func (u *User) EntityOrgID() string { return "" }

// AgentScopeSpec restricts a role binding to some agents. Empty means all agents.
type AgentScopeSpec struct {
	AllAgents bool     `json:"all_agents"`
	GroupIDs  []string `json:"group_ids,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// IsAll reports whether the scope covers every agent.
func (s AgentScopeSpec) IsAll() bool {
	return s.AllAgents || (len(s.GroupIDs) == 0 && len(s.Tags) == 0)
}

// RoleBinding grants a role within an org.
type RoleBinding struct {
	RoleID string         `json:"role_id"`
	Scope  AgentScopeSpec `json:"scope"`
}

// Membership links a user to an org. ID = DeriveID(org, user).
type Membership struct {
	ID           string        `json:"id"`
	OrgID        string        `json:"org_id"`
	UserID       string        `json:"user_id"`
	RoleBindings []RoleBinding `json:"role_bindings"`
	JoinedAt     time.Time     `json:"joined_at"`
}

// EntityID implements Entity.
func (m *Membership) EntityID() string { return m.ID }

// EntityOrgID implements Entity.
func (m *Membership) EntityOrgID() string { return m.OrgID }

// Role is a custom role (built-in roles live in code).
type Role struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (r *Role) EntityID() string { return r.ID }

// EntityOrgID implements Entity.
func (r *Role) EntityOrgID() string { return r.OrgID }

// MFA credential types.
const (
	MFATypeTOTP    = "totp"
	MFATypePasskey = "passkey"
)

// MFACredential is a second factor.
type MFACredential struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	// TOTPSecretSealed is the base32 TOTP secret sealed with the master key.
	TOTPSecretSealed string `json:"totp_secret_sealed,omitempty"`
	// TOTPLastStep prevents reuse of a code within its time step.
	TOTPLastStep int64 `json:"totp_last_step,omitempty"`
	// PasskeyCredential is the go-webauthn Credential as JSON (public key material only).
	PasskeyCredential []byte `json:"passkey_credential,omitempty"`
	// PasskeyCredentialID is the raw credential ID (for lookups during assertion).
	PasskeyCredentialID []byte    `json:"passkey_credential_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	LastUsedAt          time.Time `json:"last_used_at"`
}

// EntityID implements Entity.
func (m *MFACredential) EntityID() string { return m.ID }

// EntityOrgID implements Entity.
func (m *MFACredential) EntityOrgID() string { return "" }

// RecoveryCode is one single-use MFA recovery code (hashed).
type RecoveryCode struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CodeHash  string    `json:"code_hash"`
	CreatedAt time.Time `json:"created_at"`
	UsedAt    time.Time `json:"used_at"`
}

// EntityID implements Entity.
func (r *RecoveryCode) EntityID() string { return r.ID }

// EntityOrgID implements Entity.
func (r *RecoveryCode) EntityOrgID() string { return "" }

// Session stages (mirror api.v1.SessionStage).
const (
	SessionStageMFARequired   = "mfa_required"
	SessionStageMFAEnrollment = "mfa_enrollment"
	SessionStageFull          = "full"
)

// Session is a browser session. ID = first 32 hex chars of the token hash; TokenHash holds the
// full hash for constant-time comparison. The raw token only ever exists in the cookie.
type Session struct {
	ID            string    `json:"id"`
	TokenHash     string    `json:"token_hash"`
	UserID        string    `json:"user_id"`
	ActiveOrgID   string    `json:"active_org_id"`
	Stage         string    `json:"stage"`
	CSRFToken     string    `json:"csrf_token"`
	CreatedAt     time.Time `json:"created_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	StepUpAt      time.Time `json:"step_up_at"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	// Pending MFA ceremonies (short-lived): sealed TOTP enrollment secret, WebAuthn session.
	PendingTOTPSealed string    `json:"pending_totp_sealed,omitempty"`
	PendingTOTPID     string    `json:"pending_totp_id,omitempty"`
	PendingWebAuthn   []byte    `json:"pending_webauthn,omitempty"`
	PendingUntil      time.Time `json:"pending_until"`
}

// EntityID implements Entity.
func (s *Session) EntityID() string { return s.ID }

// EntityOrgID implements Entity.
func (s *Session) EntityOrgID() string { return "" }

// APIKey is an automation credential. ID is the public key ID embedded in the token.
type APIKey struct {
	ID          string      `json:"id"`
	OrgID       string      `json:"org_id"`
	Name        string      `json:"name"`
	Prefix      string      `json:"prefix"`
	SecretHash  string      `json:"secret_hash"`
	RoleBinding RoleBinding `json:"role_binding"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	LastUsedAt  time.Time   `json:"last_used_at"`
	RevokedAt   time.Time   `json:"revoked_at"`
}

// EntityID implements Entity.
func (k *APIKey) EntityID() string { return k.ID }

// EntityOrgID implements Entity.
func (k *APIKey) EntityOrgID() string { return k.OrgID }

// Invite is a pending invitation.
type Invite struct {
	ID           string        `json:"id"`
	OrgID        string        `json:"org_id"`
	Email        string        `json:"email"`
	TokenHash    string        `json:"token_hash"`
	RoleBindings []RoleBinding `json:"role_bindings"`
	CreatedBy    string        `json:"created_by"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	AcceptedAt   time.Time     `json:"accepted_at"`
	RevokedAt    time.Time     `json:"revoked_at"`
}

// EntityID implements Entity.
func (i *Invite) EntityID() string { return i.ID }

// EntityOrgID implements Entity.
func (i *Invite) EntityOrgID() string { return i.OrgID }

// Enrollment approval modes.
const (
	ApprovalManual = "manual"
	ApprovalAuto   = "auto"
)

// EnrollmentToken authorizes agents to request enrollment. ID is the public token ID.
type EnrollmentToken struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	Name            string    `json:"name"`
	SecretHash      string    `json:"secret_hash"`
	ApprovalMode    string    `json:"approval_mode"`
	MaxUses         int       `json:"max_uses"`
	Uses            int       `json:"uses"`
	AllowedCIDRs    []string  `json:"allowed_cidrs,omitempty"`
	HostnamePattern string    `json:"hostname_pattern,omitempty"`
	DefaultTags     []string  `json:"default_tags,omitempty"`
	DefaultGroupID  string    `json:"default_group_id,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	LastUsedAt      time.Time `json:"last_used_at"`
	RevokedAt       time.Time `json:"revoked_at"`
}

// EntityID implements Entity.
func (t *EnrollmentToken) EntityID() string { return t.ID }

// EntityOrgID implements Entity.
func (t *EnrollmentToken) EntityOrgID() string { return t.OrgID }

// Enrollment request statuses.
const (
	EnrollmentPending  = "pending"
	EnrollmentApproved = "approved"
	EnrollmentDenied   = "denied"
	EnrollmentExpired  = "expired"
)

// RiskFlag mirrors api.v1.RiskFlag.
type RiskFlag struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// EnrollmentRequest is an agent asking to join.
type EnrollmentRequest struct {
	ID              string     `json:"id"`
	OrgID           string     `json:"org_id"`
	TokenID         string     `json:"token_id"`
	Status          string     `json:"status"`
	PollSecretHash  string     `json:"poll_secret_hash"`
	ServerNonce     []byte     `json:"server_nonce"`
	PairingCode     string     `json:"pairing_code"`
	CSRDER          []byte     `json:"csr_der"`
	PublicKeySHA256 string     `json:"public_key_sha256"`
	Hostname        string     `json:"hostname"`
	MachineID       string     `json:"machine_id"`
	FactsProto      []byte     `json:"facts_proto"`
	AgentVersion    string     `json:"agent_version"`
	SourceIP        string     `json:"source_ip"`
	RiskFlags       []RiskFlag `json:"risk_flags,omitempty"`
	ReplacesAgentID string     `json:"replaces_agent_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	DecidedAt       time.Time  `json:"decided_at"`
	DecidedBy       string     `json:"decided_by,omitempty"`
	DecidedByName   string     `json:"decided_by_name,omitempty"`
	DecisionNote    string     `json:"decision_note,omitempty"`
	AgentID         string     `json:"agent_id,omitempty"`
	// Issued credentials, kept until the agent collects them (then cleared).
	CertificateDER []byte `json:"certificate_der,omitempty"`
}

// EntityID implements Entity.
func (e *EnrollmentRequest) EntityID() string { return e.ID }

// EntityOrgID implements Entity.
func (e *EnrollmentRequest) EntityOrgID() string { return e.OrgID }

// BlockedKey prevents a public key from enrolling again. ID = DeriveID(org, sha).
type BlockedKey struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
	Reason          string    `json:"reason"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

// EntityID implements Entity.
func (b *BlockedKey) EntityID() string { return b.ID }

// EntityOrgID implements Entity.
func (b *BlockedKey) EntityOrgID() string { return b.OrgID }

// Agent lifecycle values.
const (
	AgentActive  = "active"
	AgentRevoked = "revoked"
)

// Agent is an enrolled machine.
type Agent struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Name              string    `json:"name"`
	Hostname          string    `json:"hostname"`
	MachineID         string    `json:"machine_id"`
	Lifecycle         string    `json:"lifecycle"`
	Tags              []string  `json:"tags,omitempty"`
	GroupID           string    `json:"group_id,omitempty"`
	PublicKeySHA256   string    `json:"public_key_sha256"`
	CertSerial        string    `json:"cert_serial"`
	CertNotAfter      time.Time `json:"cert_not_after"`
	EnrolledAt        time.Time `json:"enrolled_at"`
	ApprovedBy        string    `json:"approved_by,omitempty"`
	ApprovedByName    string    `json:"approved_by_name,omitempty"`
	EnrollmentTokenID string    `json:"enrollment_token_id,omitempty"`
	FactsProto        []byte    `json:"facts_proto,omitempty"`
	PolicyProto       []byte    `json:"policy_proto,omitempty"`
	AgentVersion      string    `json:"agent_version"`
	Features          []string  `json:"features,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	LastIP            string    `json:"last_ip"`
	RevokedAt         time.Time `json:"revoked_at"`
	RevokedReason     string    `json:"revoked_reason,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (a *Agent) EntityID() string { return a.ID }

// EntityOrgID implements Entity.
func (a *Agent) EntityOrgID() string { return a.OrgID }

// AgentGroup organizes agents.
type AgentGroup struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"org_id"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	MetricsIntervalSec int       `json:"metrics_interval_sec"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (g *AgentGroup) EntityID() string { return g.ID }

// EntityOrgID implements Entity.
func (g *AgentGroup) EntityOrgID() string { return g.OrgID }

// Inventory is the latest report of one kind for one agent. ID = DeriveID(agent, kind).
type Inventory struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	AgentID     string `json:"agent_id"`
	Kind        string `json:"kind"`
	ContentHash string `json:"content_hash"`
	// ReportProto is the serialized central.agent.v1.InventoryReport.
	ReportProto []byte    `json:"report_proto"`
	CollectedAt time.Time `json:"collected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (i *Inventory) EntityID() string { return i.ID }

// EntityOrgID implements Entity.
func (i *Inventory) EntityOrgID() string { return i.OrgID }

// Metrics chunk resolutions.
const (
	ResolutionMinute = "minute"
	ResolutionHour   = "hour"
)

// MetricsChunk packs a window of rollup points for one agent: one hour of minute points, or
// one day of hour points. ID = DeriveID(agent, resolution, bucket start).
type MetricsChunk struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	AgentID     string    `json:"agent_id"`
	Resolution  string    `json:"resolution"`
	BucketStart time.Time `json:"bucket_start"`
	// Points is the gzip-compressed packed point array (see metrics package).
	Points    []byte    `json:"points"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (m *MetricsChunk) EntityID() string { return m.ID }

// EntityOrgID implements Entity.
func (m *MetricsChunk) EntityOrgID() string { return m.OrgID }

// Principal kinds for actor references.
const (
	PrincipalUser   = "user"
	PrincipalAPIKey = "api_key"
	PrincipalAgent  = "agent"
	PrincipalSystem = "system"
)

// PrincipalRef identifies an actor at the time of an action.
type PrincipalRef struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Display string `json:"display"`
}

// Command states (mirror agent.v1.CommandState names in lowercase).
const (
	CommandQueued    = "queued"
	CommandSent      = "sent"
	CommandAccepted  = "accepted"
	CommandRunning   = "running"
	CommandSucceeded = "succeeded"
	CommandFailed    = "failed"
	CommandRejected  = "rejected"
	CommandCancelled = "cancelled"
	CommandTimedOut  = "timed_out"
	CommandExpired   = "expired"
)

// Command is Central's record of a command sent to an agent.
type Command struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	AgentID       string `json:"agent_id"`
	JobID         string `json:"job_id,omitempty"`
	OperationType string `json:"operation_type"`
	// OperationProto is the redacted central.agent.v1.Operation.
	OperationProto  []byte       `json:"operation_proto"`
	State           string       `json:"state"`
	ProgressPercent int          `json:"progress_percent"`
	Status          string       `json:"status,omitempty"`
	ErrorCode       string       `json:"error_code,omitempty"`
	ErrorMessage    string       `json:"error_message,omitempty"`
	ResultProto     []byte       `json:"result_proto,omitempty"`
	Issuer          PrincipalRef `json:"issuer"`
	SourceIP        string       `json:"source_ip,omitempty"`
	OutputTruncated bool         `json:"output_truncated"`
	// OutputTail is the last part of the output (for history views).
	OutputTail []byte    `json:"output_tail,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// EntityID implements Entity.
func (c *Command) EntityID() string { return c.ID }

// EntityOrgID implements Entity.
func (c *Command) EntityOrgID() string { return c.OrgID }

// Terminal reports whether the command state is final.
func (c *Command) Terminal() bool {
	switch c.State {
	case CommandSucceeded, CommandFailed, CommandRejected, CommandCancelled, CommandTimedOut, CommandExpired:
		return true
	}
	return false
}

// Job states.
const (
	JobPending         = "pending"
	JobRunning         = "running"
	JobSucceeded       = "succeeded"
	JobPartiallyFailed = "partially_failed"
	JobAborted         = "aborted"
	JobCancelled       = "cancelled"
)

// TargetSelectorSpec mirrors api.v1.TargetSelector.
type TargetSelectorSpec struct {
	AgentIDs   []string `json:"agent_ids,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	GroupIDs   []string `json:"group_ids,omitempty"`
	AllAgents  bool     `json:"all_agents"`
	OnlineOnly bool     `json:"online_only"`
}

// RolloutSpec mirrors api.v1.RolloutStrategy.
type RolloutSpec struct {
	BatchSize         int `json:"batch_size"`
	MaxConcurrency    int `json:"max_concurrency"`
	MaxFailurePercent int `json:"max_failure_percent"`
	BatchDelaySec     int `json:"batch_delay_sec"`
}

// JobCounts aggregates execution states.
type JobCounts struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Rejected  int `json:"rejected"`
	Skipped   int `json:"skipped"`
}

// Job is a fleet-wide operation.
type Job struct {
	ID             string             `json:"id"`
	OrgID          string             `json:"org_id"`
	Name           string             `json:"name"`
	OperationType  string             `json:"operation_type"`
	OperationProto []byte             `json:"operation_proto"`
	Selector       TargetSelectorSpec `json:"selector"`
	Rollout        RolloutSpec        `json:"rollout"`
	State          string             `json:"state"`
	Counts         JobCounts          `json:"counts"`
	CreatedBy      PrincipalRef       `json:"created_by"`
	CommandTTLSec  int                `json:"command_ttl_sec"`
	CreatedAt      time.Time          `json:"created_at"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at"`
}

// EntityID implements Entity.
func (j *Job) EntityID() string { return j.ID }

// EntityOrgID implements Entity.
func (j *Job) EntityOrgID() string { return j.OrgID }

// JobExecution is one agent's part of a job. ID = DeriveID(job, agent).
type JobExecution struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	JobID        string    `json:"job_id"`
	AgentID      string    `json:"agent_id"`
	AgentName    string    `json:"agent_name"`
	CommandID    string    `json:"command_id,omitempty"`
	State        string    `json:"state"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	Batch        int       `json:"batch"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
}

// EntityID implements Entity.
func (e *JobExecution) EntityID() string { return e.ID }

// EntityOrgID implements Entity.
func (e *JobExecution) EntityOrgID() string { return e.OrgID }

// Audit results.
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
	AuditDenied  = "denied"
)

// AuditEvent is one entry in an org's hash chain.
type AuditEvent struct {
	ID            string            `json:"id"`
	OrgID         string            `json:"org_id"`
	Seq           int64             `json:"seq"`
	Time          time.Time         `json:"time"`
	Actor         PrincipalRef      `json:"actor"`
	Action        string            `json:"action"`
	TargetType    string            `json:"target_type,omitempty"`
	TargetID      string            `json:"target_id,omitempty"`
	TargetDisplay string            `json:"target_display,omitempty"`
	Result        string            `json:"result"`
	SourceIP      string            `json:"source_ip,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	Hash          string            `json:"hash"`
	PrevHash      string            `json:"prev_hash"`
}

// EntityID implements Entity.
func (a *AuditEvent) EntityID() string { return a.ID }

// EntityOrgID implements Entity.
func (a *AuditEvent) EntityOrgID() string { return a.OrgID }

// PKI material kinds.
const (
	PKIAgentCA       = "agent_ca"
	PKICommandSigner = "command_signer"
)

// PKIItem is a CA certificate/key or a signing key (keys sealed with the master key).
type PKIItem struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	CertPEM   string    `json:"cert_pem,omitempty"`
	PublicKey []byte    `json:"public_key,omitempty"`
	KeySealed string    `json:"key_sealed"`
	Active    bool      `json:"active"`
	Version   int64     `json:"version"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CreatedAt time.Time `json:"created_at"`
}

// EntityID implements Entity.
func (p *PKIItem) EntityID() string { return p.ID }

// EntityOrgID implements Entity.
func (p *PKIItem) EntityOrgID() string { return "" }

// Setting is a system-level key/value pair. ID is the key.
type Setting struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID implements Entity.
func (s *Setting) EntityID() string { return s.ID }

// EntityOrgID implements Entity.
func (s *Setting) EntityOrgID() string { return "" }
