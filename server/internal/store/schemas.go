// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// SchemaVersion is bumped whenever schemas change in a way drivers must migrate.
const SchemaVersion = 1

// NewID returns a new time-ordered unique ID (UUIDv7, 32 lowercase hex chars).
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic("store: uuid: " + err.Error())
	}
	return strings.ReplaceAll(id.String(), "-", "")
}

// DeriveID returns a deterministic ID for a composite key (32 hex chars).
func DeriveID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Millis converts a time to the int64 representation used by indexed time fields.
func Millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func str(name string, size int) Field { return Field{Name: name, Type: FieldString, Size: size} }
func num(name string) Field           { return Field{Name: name, Type: FieldInt} }
func boolean(name string) Field       { return Field{Name: name, Type: FieldBool} }

func idx(name string, unique bool, fields ...string) Index {
	return Index{Name: name, Fields: fields, Unique: unique}
}

// Schemas for every collection.
var (
	OrgSchema = Schema[*Org]{
		SchemaInfo: SchemaInfo{Name: "orgs"},
		New:        func() *Org { return &Org{} },
	}
	UserSchema = Schema[*User]{
		SchemaInfo: SchemaInfo{
			Name:    "users",
			Fields:  []Field{str("email", 320), str("webauthn_id", 64)},
			Indexes: []Index{idx("email_unique", true, "email"), idx("webauthn", false, "webauthn_id")},
		},
		New: func() *User { return &User{} },
		IndexOf: func(u *User) map[string]any {
			return map[string]any{"email": u.Email, "webauthn_id": hex.EncodeToString(u.WebAuthnID)}
		},
	}
	MembershipSchema = Schema[*Membership]{
		SchemaInfo: SchemaInfo{
			Name: "memberships", Tenant: true,
			Fields:  []Field{str("user_id", 36)},
			Indexes: []Index{idx("user", false, "user_id")},
		},
		New:     func() *Membership { return &Membership{} },
		IndexOf: func(m *Membership) map[string]any { return map[string]any{"user_id": m.UserID} },
	}
	RoleSchema = Schema[*Role]{
		SchemaInfo: SchemaInfo{Name: "roles", Tenant: true},
		New:        func() *Role { return &Role{} },
	}
	MFASchema = Schema[*MFACredential]{
		SchemaInfo: SchemaInfo{
			Name:    "mfa_credentials",
			Fields:  []Field{str("user_id", 36), str("type", 16)},
			Indexes: []Index{idx("user", false, "user_id")},
		},
		New: func() *MFACredential { return &MFACredential{} },
		IndexOf: func(m *MFACredential) map[string]any {
			return map[string]any{"user_id": m.UserID, "type": m.Type}
		},
	}
	RecoveryCodeSchema = Schema[*RecoveryCode]{
		SchemaInfo: SchemaInfo{
			Name:    "recovery_codes",
			Fields:  []Field{str("user_id", 36), num("used_at")},
			Indexes: []Index{idx("user", false, "user_id")},
		},
		New: func() *RecoveryCode { return &RecoveryCode{} },
		IndexOf: func(r *RecoveryCode) map[string]any {
			return map[string]any{"user_id": r.UserID, "used_at": Millis(r.UsedAt)}
		},
	}
	SessionSchema = Schema[*Session]{
		SchemaInfo: SchemaInfo{
			Name:    "sessions",
			Fields:  []Field{str("user_id", 36), num("expires_at")},
			Indexes: []Index{idx("user", false, "user_id"), idx("expiry", false, "expires_at")},
		},
		New: func() *Session { return &Session{} },
		IndexOf: func(s *Session) map[string]any {
			return map[string]any{"user_id": s.UserID, "expires_at": Millis(s.ExpiresAt)}
		},
	}
	APIKeySchema = Schema[*APIKey]{
		SchemaInfo: SchemaInfo{Name: "api_keys", Tenant: true},
		New:        func() *APIKey { return &APIKey{} },
	}
	InviteSchema = Schema[*Invite]{
		SchemaInfo: SchemaInfo{
			Name: "invites", Tenant: true,
			Fields:  []Field{str("email", 320)},
			Indexes: []Index{idx("email", false, "email")},
		},
		New:     func() *Invite { return &Invite{} },
		IndexOf: func(i *Invite) map[string]any { return map[string]any{"email": i.Email} },
	}
	EnrollmentTokenSchema = Schema[*EnrollmentToken]{
		SchemaInfo: SchemaInfo{Name: "enrollment_tokens", Tenant: true},
		New:        func() *EnrollmentToken { return &EnrollmentToken{} },
	}
	EnrollmentRequestSchema = Schema[*EnrollmentRequest]{
		SchemaInfo: SchemaInfo{
			Name: "enrollment_requests", Tenant: true,
			Fields: []Field{
				str("status", 16), str("source_ip", 64), str("public_key", 64), num("created_at"), num("expires_at"),
			},
			Indexes: []Index{
				idx("status_created", false, "status", "created_at"), idx("source_ip", false, "source_ip"),
				idx("public_key", false, "public_key"), idx("expiry", false, "expires_at"),
			},
		},
		New: func() *EnrollmentRequest { return &EnrollmentRequest{} },
		IndexOf: func(e *EnrollmentRequest) map[string]any {
			return map[string]any{
				"status": e.Status, "source_ip": e.SourceIP, "public_key": e.PublicKeySHA256,
				"created_at": Millis(e.CreatedAt), "expires_at": Millis(e.ExpiresAt),
			}
		},
	}
	BlockedKeySchema = Schema[*BlockedKey]{
		SchemaInfo: SchemaInfo{Name: "blocked_keys", Tenant: true},
		New:        func() *BlockedKey { return &BlockedKey{} },
	}
	AgentSchema = Schema[*Agent]{
		SchemaInfo: SchemaInfo{
			Name: "agents", Tenant: true,
			Fields:  []Field{str("machine_id", 64), str("lifecycle", 16)},
			Indexes: []Index{idx("machine", false, "machine_id")},
		},
		New: func() *Agent { return &Agent{} },
		IndexOf: func(a *Agent) map[string]any {
			return map[string]any{"machine_id": a.MachineID, "lifecycle": a.Lifecycle}
		},
	}
	AgentGroupSchema = Schema[*AgentGroup]{
		SchemaInfo: SchemaInfo{Name: "agent_groups", Tenant: true},
		New:        func() *AgentGroup { return &AgentGroup{} },
	}
	InventorySchema = Schema[*Inventory]{
		SchemaInfo: SchemaInfo{
			Name: "agent_inventory", Tenant: true,
			Fields:  []Field{str("agent_id", 36), str("kind", 16)},
			Indexes: []Index{idx("agent", false, "agent_id")},
		},
		New: func() *Inventory { return &Inventory{} },
		IndexOf: func(i *Inventory) map[string]any {
			return map[string]any{"agent_id": i.AgentID, "kind": i.Kind}
		},
	}
	MetricsChunkSchema = Schema[*MetricsChunk]{
		SchemaInfo: SchemaInfo{
			Name: "metrics_chunks", Tenant: true,
			Fields: []Field{str("agent_id", 36), str("resolution", 8), num("bucket_start")},
			Indexes: []Index{
				idx("agent_bucket", false, "agent_id", "resolution", "bucket_start"),
				idx("bucket", false, "bucket_start"),
			},
		},
		New: func() *MetricsChunk { return &MetricsChunk{} },
		IndexOf: func(m *MetricsChunk) map[string]any {
			return map[string]any{
				"agent_id": m.AgentID, "resolution": m.Resolution, "bucket_start": Millis(m.BucketStart),
			}
		},
	}
	CommandSchema = Schema[*Command]{
		SchemaInfo: SchemaInfo{
			Name: "commands", Tenant: true,
			Fields: []Field{
				str("agent_id", 36), str("job_id", 36), str("state", 16), num("created_at"), num("expires_at"),
			},
			Indexes: []Index{
				idx("agent", false, "agent_id", "created_at"), idx("job", false, "job_id"),
				idx("created", false, "created_at"), idx("state", false, "state"),
			},
		},
		New: func() *Command { return &Command{} },
		IndexOf: func(c *Command) map[string]any {
			return map[string]any{
				"agent_id": c.AgentID, "job_id": c.JobID, "state": c.State, "created_at": Millis(c.CreatedAt),
				"expires_at": Millis(c.ExpiresAt),
			}
		},
	}
	JobSchema = Schema[*Job]{
		SchemaInfo: SchemaInfo{
			Name: "jobs", Tenant: true,
			Fields:  []Field{str("state", 24), num("created_at")},
			Indexes: []Index{idx("created", false, "created_at"), idx("state", false, "state")},
		},
		New: func() *Job { return &Job{} },
		IndexOf: func(j *Job) map[string]any {
			return map[string]any{"state": j.State, "created_at": Millis(j.CreatedAt)}
		},
	}
	JobExecutionSchema = Schema[*JobExecution]{
		SchemaInfo: SchemaInfo{
			Name: "job_executions", Tenant: true,
			Fields:  []Field{str("job_id", 36), str("agent_id", 36), str("state", 16), num("batch")},
			Indexes: []Index{idx("job", false, "job_id", "batch")},
		},
		New: func() *JobExecution { return &JobExecution{} },
		IndexOf: func(e *JobExecution) map[string]any {
			return map[string]any{"job_id": e.JobID, "agent_id": e.AgentID, "state": e.State, "batch": int64(e.Batch)}
		},
	}
	AuditSchema = Schema[*AuditEvent]{
		SchemaInfo: SchemaInfo{
			Name: "audit_events", Tenant: true,
			Fields: []Field{
				num("seq"), num("time"), str("actor_id", 36), str("action", 64),
				str("target_id", 64), str("result", 16),
			},
			Indexes: []Index{
				idx("seq", true, "org_id", "seq"), idx("time", false, "time"),
				idx("actor", false, "actor_id"), idx("action", false, "action"), idx("target", false, "target_id"),
			},
		},
		New: func() *AuditEvent { return &AuditEvent{} },
		IndexOf: func(a *AuditEvent) map[string]any {
			return map[string]any{
				"seq": a.Seq, "time": Millis(a.Time), "actor_id": a.Actor.ID, "action": a.Action,
				"target_id": a.TargetID, "result": a.Result,
			}
		},
	}
	RecordingSchema = Schema[*Recording]{
		SchemaInfo: SchemaInfo{
			Name: "recordings", Tenant: true,
			Fields:  []Field{str("agent_id", 36), num("started_at")},
			Indexes: []Index{idx("agent", false, "agent_id", "started_at"), idx("started", false, "started_at")},
		},
		New: func() *Recording { return &Recording{} },
		IndexOf: func(r *Recording) map[string]any {
			return map[string]any{"agent_id": r.AgentID, "started_at": Millis(r.StartedAt)}
		},
	}
	RecordingChunkSchema = Schema[*RecordingChunk]{
		SchemaInfo: SchemaInfo{
			Name: "recording_chunks", Tenant: true,
			Fields:  []Field{str("recording_id", 36), num("seq")},
			Indexes: []Index{idx("recording", false, "recording_id", "seq")},
		},
		New: func() *RecordingChunk { return &RecordingChunk{} },
		IndexOf: func(c *RecordingChunk) map[string]any {
			return map[string]any{"recording_id": c.RecordingID, "seq": int64(c.Seq)}
		},
	}
	PKISchema = Schema[*PKIItem]{
		SchemaInfo: SchemaInfo{
			Name:   "pki",
			Fields: []Field{str("kind", 32), boolean("active")},
		},
		New: func() *PKIItem { return &PKIItem{} },
		IndexOf: func(p *PKIItem) map[string]any {
			return map[string]any{"kind": p.Kind, "active": p.Active}
		},
	}
	SettingSchema = Schema[*Setting]{
		SchemaInfo: SchemaInfo{Name: "settings"},
		New:        func() *Setting { return &Setting{} },
	}
)

// AllSchemas lists every collection (for migrations).
func AllSchemas() []SchemaInfo {
	return []SchemaInfo{
		OrgSchema.SchemaInfo, UserSchema.SchemaInfo, MembershipSchema.SchemaInfo, RoleSchema.SchemaInfo,
		MFASchema.SchemaInfo, RecoveryCodeSchema.SchemaInfo, SessionSchema.SchemaInfo, APIKeySchema.SchemaInfo,
		InviteSchema.SchemaInfo, EnrollmentTokenSchema.SchemaInfo, EnrollmentRequestSchema.SchemaInfo,
		BlockedKeySchema.SchemaInfo, AgentSchema.SchemaInfo, AgentGroupSchema.SchemaInfo,
		InventorySchema.SchemaInfo, MetricsChunkSchema.SchemaInfo, CommandSchema.SchemaInfo,
		JobSchema.SchemaInfo, JobExecutionSchema.SchemaInfo, AuditSchema.SchemaInfo,
		RecordingSchema.SchemaInfo, RecordingChunkSchema.SchemaInfo, PKISchema.SchemaInfo, SettingSchema.SchemaInfo,
	}
}

// Store bundles every typed collection over one driver.
type Store struct {
	driver Driver

	Orgs               *Collection[*Org]
	Users              *Collection[*User]
	Memberships        *Collection[*Membership]
	Roles              *Collection[*Role]
	MFA                *Collection[*MFACredential]
	RecoveryCodes      *Collection[*RecoveryCode]
	Sessions           *Collection[*Session]
	APIKeys            *Collection[*APIKey]
	Invites            *Collection[*Invite]
	EnrollmentTokens   *Collection[*EnrollmentToken]
	EnrollmentRequests *Collection[*EnrollmentRequest]
	BlockedKeys        *Collection[*BlockedKey]
	Agents             *Collection[*Agent]
	AgentGroups        *Collection[*AgentGroup]
	Inventory          *Collection[*Inventory]
	MetricsChunks      *Collection[*MetricsChunk]
	Commands           *Collection[*Command]
	Jobs               *Collection[*Job]
	JobExecutions      *Collection[*JobExecution]
	Audit              *Collection[*AuditEvent]
	Recordings         *Collection[*Recording]
	RecordingChunks    *Collection[*RecordingChunk]
	PKI                *Collection[*PKIItem]
	Settings           *Collection[*Setting]
}

// Open binds all collections to a driver. Call Migrate before first use.
func Open(d Driver) *Store {
	return &Store{
		driver:             d,
		Orgs:               NewCollection(d, OrgSchema),
		Users:              NewCollection(d, UserSchema),
		Memberships:        NewCollection(d, MembershipSchema),
		Roles:              NewCollection(d, RoleSchema),
		MFA:                NewCollection(d, MFASchema),
		RecoveryCodes:      NewCollection(d, RecoveryCodeSchema),
		Sessions:           NewCollection(d, SessionSchema),
		APIKeys:            NewCollection(d, APIKeySchema),
		Invites:            NewCollection(d, InviteSchema),
		EnrollmentTokens:   NewCollection(d, EnrollmentTokenSchema),
		EnrollmentRequests: NewCollection(d, EnrollmentRequestSchema),
		BlockedKeys:        NewCollection(d, BlockedKeySchema),
		Agents:             NewCollection(d, AgentSchema),
		AgentGroups:        NewCollection(d, AgentGroupSchema),
		Inventory:          NewCollection(d, InventorySchema),
		MetricsChunks:      NewCollection(d, MetricsChunkSchema),
		Commands:           NewCollection(d, CommandSchema),
		Jobs:               NewCollection(d, JobSchema),
		JobExecutions:      NewCollection(d, JobExecutionSchema),
		Audit:              NewCollection(d, AuditSchema),
		Recordings:         NewCollection(d, RecordingSchema),
		RecordingChunks:    NewCollection(d, RecordingChunkSchema),
		PKI:                NewCollection(d, PKISchema),
		Settings:           NewCollection(d, SettingSchema),
	}
}

// Migrate brings the backend schema up to date.
func (s *Store) Migrate(ctx context.Context) error { return s.driver.Migrate(ctx, AllSchemas()) }

// Info describes the backend.
func (s *Store) Info() DriverInfo { return s.driver.Info() }

// Ping checks backend connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.driver.Ping(ctx) }

// Close releases backend resources.
func (s *Store) Close() error { return s.driver.Close() }

// GetSetting returns a system setting value ("" and ErrNotFound if unset).
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	v, err := s.Settings.Get(ctx, System(), key)
	if err != nil {
		return "", err
	}
	return v.Value, nil
}

// PutSetting stores a system setting.
func (s *Store) PutSetting(ctx context.Context, key, value string) error {
	return s.Settings.Upsert(ctx, System(), &Setting{ID: key, Value: value, UpdatedAt: time.Now().UTC()})
}

// Holder holds the active Store. It is nil until storage has been configured (fresh installs
// start without a database and get one from the setup wizard).
type Holder struct {
	p atomic.Pointer[Store]
}

// Get returns the active store or nil.
func (h *Holder) Get() *Store { return h.p.Load() }

// Set installs the active store.
func (h *Holder) Set(s *Store) { h.p.Store(s) }
