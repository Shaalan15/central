// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/scrypt"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/audit"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// AuditService implements AuditService.
type AuditService struct {
	apiv1connect.UnimplementedAuditServiceHandler
	D *Deps
}

func auditResultProto(r string) apiv1.AuditResult {
	switch r {
	case store.AuditSuccess:
		return apiv1.AuditResult_AUDIT_RESULT_SUCCESS
	case store.AuditFailure:
		return apiv1.AuditResult_AUDIT_RESULT_FAILURE
	case store.AuditDenied:
		return apiv1.AuditResult_AUDIT_RESULT_DENIED
	}
	return apiv1.AuditResult_AUDIT_RESULT_UNSPECIFIED
}

func principalProto(p store.PrincipalRef) *apiv1.PrincipalRef {
	k := apiv1.PrincipalRef_KIND_UNSPECIFIED
	switch p.Kind {
	case store.PrincipalUser:
		k = apiv1.PrincipalRef_KIND_USER
	case store.PrincipalAPIKey:
		k = apiv1.PrincipalRef_KIND_API_KEY
	case store.PrincipalAgent:
		k = apiv1.PrincipalRef_KIND_AGENT
	case store.PrincipalSystem:
		k = apiv1.PrincipalRef_KIND_SYSTEM
	}
	return &apiv1.PrincipalRef{Kind: k, Id: p.ID, Display: p.Display}
}

// ListAuditEvents implements AuditService.
func (s *AuditService) ListAuditEvents(ctx context.Context, req *connect.Request[apiv1.ListAuditEventsRequest]) (*connect.Response[apiv1.ListAuditEventsResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.AuditView)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	q := store.Query{}.Order("seq", true).Page(int(min(max(m.GetPage().GetPageSize(), 1), 500)), m.GetPage().GetPageToken())
	if m.GetPage().GetPageSize() == 0 {
		q.Limit = 50
	}
	if v := m.GetActorId(); v != "" {
		q = q.And("actor_id", store.OpEq, v)
	}
	if v := m.GetActionPrefix(); v != "" {
		q = q.And("action", store.OpPrefix, v)
	}
	if v := m.GetTargetId(); v != "" {
		q = q.And("target_id", store.OpEq, v)
	}
	if v := m.GetSince(); v != nil {
		q = q.And("time", store.OpGte, v.AsTime().UnixMilli())
	}
	if v := m.GetUntil(); v != nil {
		q = q.And("time", store.OpLte, v.AsTime().UnixMilli())
	}
	events, next, err := st.Audit.Find(ctx, store.Tenant(p.OrgID), q)
	if err != nil {
		return nil, s.D.internal(err)
	}
	out := &apiv1.ListAuditEventsResponse{Page: &apiv1.PageResponse{NextPageToken: next}}
	for _, e := range events {
		out.Events = append(out.Events, &apiv1.AuditEvent{
			Id: e.ID, Seq: uint64(max(e.Seq, 0)), Time: ts(e.Time), Actor: principalProto(e.Actor), Action: e.Action,
			TargetType: e.TargetType, TargetId: e.TargetID, TargetDisplay: e.TargetDisplay,
			Result: auditResultProto(e.Result), SourceIp: e.SourceIP, UserAgent: e.UserAgent,
			Details: e.Details, Hash: e.Hash, PrevHash: e.PrevHash,
		})
	}
	return connect.NewResponse(out), nil
}

// VerifyAuditChain implements AuditService.
func (s *AuditService) VerifyAuditChain(ctx context.Context, req *connect.Request[apiv1.VerifyAuditChainRequest]) (*connect.Response[apiv1.VerifyAuditChainResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	p, err := authz.Require(ctx, authz.AuditView)
	if err != nil {
		return nil, err
	}
	res, err := audit.VerifyChain(ctx, st, p.OrgID, int64(req.Msg.GetFromSeq()), int64(req.Msg.GetToSeq())) //nolint:gosec // client-provided bounds
	if err != nil {
		return nil, s.D.internal(err)
	}
	return connect.NewResponse(&apiv1.VerifyAuditChainResponse{
		Intact: res.Intact, EventsChecked: uint64(res.Checked), FirstBrokenSeq: uint64(max(res.FirstBrokenSeq, 0)), //nolint:gosec // non-negative
	}), nil
}

// SystemService implements SystemService.
type SystemService struct {
	apiv1connect.UnimplementedSystemServiceHandler
	D *Deps
	// Info returns PKI and connection details (filled by the app once the gateway exists).
	Extra func(*apiv1.SystemInfo)
	// PKIExport returns sealed PKI items to include in key backups.
	PKIExport func(ctx context.Context) ([]*store.PKIItem, error)
}

// GetSystemInfo implements SystemService.
func (s *SystemService) GetSystemInfo(ctx context.Context, _ *connect.Request[apiv1.GetSystemInfoRequest]) (*connect.Response[apiv1.GetSystemInfoResponse], error) {
	st, err := s.D.Store()
	if err != nil {
		return nil, err
	}
	if _, err := authz.Require(ctx, authz.SystemView); err != nil {
		return nil, err
	}
	info := st.Info()
	out := &apiv1.SystemInfo{
		Version: s.D.Version, Commit: s.D.Commit, GoVersion: runtime.Version(), StartedAt: ts(s.D.Started),
		StorageDriver: info.Name, StorageEndpoint: info.Endpoint, StorageVersion: info.Version,
		SchemaVersion: store.SchemaVersion, PublicUrl: s.D.PublicURL(ctx), AgentUrl: s.D.AgentURL(ctx),
		DevMode: s.D.Config.Dev, TlsMode: s.D.Config.HTTP.TLS.Mode,
	}
	if s.Extra != nil {
		s.Extra(out)
	}
	return connect.NewResponse(&apiv1.GetSystemInfoResponse{Info: out}), nil
}

// keyBackup is the encrypted backup file format (JSON inside a text envelope).
type keyBackup struct {
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	KDF       string    `json:"kdf"`
	N         int       `json:"n"`
	R         int       `json:"r"`
	P         int       `json:"p"`
	Salt      []byte    `json:"salt"`
	Nonce     []byte    `json:"nonce"`
	Data      []byte    `json:"data"`
}

type keyBackupPayload struct {
	MasterKey []byte           `json:"master_key"`
	KeyID     string           `json:"key_id"`
	PKI       []*store.PKIItem `json:"pki"`
}

// ExportKeyBackup implements SystemService. The master key and the (already sealed) PKI items are
// encrypted with a key derived from the passphrase (scrypt N=2^17, r=8, p=1 + AES-256-GCM).
func (s *SystemService) ExportKeyBackup(ctx context.Context, req *connect.Request[apiv1.ExportKeyBackupRequest]) (*connect.Response[apiv1.ExportKeyBackupResponse], error) {
	if _, err := s.D.Store(); err != nil {
		return nil, err
	}
	if _, err := authz.Require(ctx, authz.SystemKeyExport); err != nil {
		return nil, err
	}
	pass := req.Msg.GetPassphrase()
	if len([]rune(pass)) < 16 || len(pass) > 1024 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the passphrase must be at least 16 characters"))
	}
	mk, err := s.masterKey()
	if err != nil {
		return nil, s.D.internal(err)
	}
	payload := keyBackupPayload{MasterKey: mk, KeyID: crypto.KeyID(mk)}
	if s.PKIExport != nil {
		if payload.PKI, err = s.PKIExport(ctx); err != nil {
			return nil, s.D.internal(err)
		}
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, s.D.internal(err)
	}
	b := keyBackup{
		Format: "central-key-backup-v1", CreatedAt: time.Now().UTC(), KDF: "scrypt", N: 1 << 17, R: 8, P: 1,
		Salt: crypto.RandomBytes(16),
	}
	key, err := scrypt.Key([]byte(pass), b.Salt, b.N, b.R, b.P, 32)
	if err != nil {
		return nil, s.D.internal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	b.Nonce = crypto.RandomBytes(aead.NonceSize())
	b.Data = aead.Seal(nil, b.Nonce, plain, []byte(b.Format))
	encoded, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, s.D.internal(err)
	}
	file := "-----BEGIN CENTRAL KEY BACKUP-----\n" + base64.StdEncoding.EncodeToString(encoded) + "\n-----END CENTRAL KEY BACKUP-----\n"
	_ = s.D.Audit.Record(ctx, audit.Event{Action: "system.key_backup_exported", TargetType: "system"})
	return connect.NewResponse(&apiv1.ExportKeyBackupResponse{
		FileName: "central-keys-" + time.Now().UTC().Format("2006-01-02") + ".cbk", Backup: []byte(file),
	}), nil
}

func (s *SystemService) masterKey() ([]byte, error) {
	if s.D.Config.MasterKey != "" {
		return crypto.DecodeMasterKey(s.D.Config.MasterKey.Reveal())
	}
	data, err := os.ReadFile(s.D.Config.MasterKeyFile)
	if err != nil {
		return nil, err
	}
	return crypto.DecodeMasterKey(string(data))
}
