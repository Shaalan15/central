// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// ceremonyTTL bounds how long a WebAuthn challenge stays valid.
const ceremonyTTL = 5 * time.Minute

// Passkeys implements WebAuthn registration and assertion.
type Passkeys struct {
	holder *store.Holder
	// Origin returns the public UI origin (e.g. "https://central.example.com"); the RP ID is its
	// host. Extra origins are accepted in dev mode (Angular dev server).
	Origin       func(context.Context) string
	ExtraOrigins []string

	mu         sync.Mutex
	ceremonies map[string]pendingCeremony
}

type pendingCeremony struct {
	data    webauthn.SessionData
	expires time.Time
}

// NewPasskeys returns a passkey service.
func NewPasskeys(holder *store.Holder, origin func(context.Context) string, extraOrigins []string) *Passkeys {
	return &Passkeys{holder: holder, Origin: origin, ExtraOrigins: extraOrigins, ceremonies: map[string]pendingCeremony{}}
}

func (p *Passkeys) webauthn(ctx context.Context) (*webauthn.WebAuthn, error) {
	origin := p.Origin(ctx)
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("auth: passkeys need the public URL to be configured")
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Central",
		RPOrigins:     append([]string{u.Scheme + "://" + u.Host}, p.ExtraOrigins...),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
}

// waUser adapts a Central user to webauthn.User.
type waUser struct {
	u     *store.User
	creds []*store.MFACredential
}

func (w *waUser) WebAuthnID() []byte          { return w.u.WebAuthnID }
func (w *waUser) WebAuthnName() string        { return w.u.Email }
func (w *waUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.creds))
	for _, c := range w.creds {
		var cred webauthn.Credential
		if err := json.Unmarshal(c.PasskeyCredential, &cred); err == nil {
			out = append(out, cred)
		}
	}
	return out
}

func (p *Passkeys) loadUser(ctx context.Context, u *store.User) (*waUser, error) {
	st := p.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	creds, err := st.MFA.All(ctx, store.System(), store.Eq("user_id", u.ID).And("type", store.OpEq, store.MFATypePasskey))
	if err != nil {
		return nil, err
	}
	return &waUser{u: u, creds: creds}, nil
}

// BeginRegistration returns creation options and the ceremony state to keep server-side.
func (p *Passkeys) BeginRegistration(ctx context.Context, u *store.User) (optionsJSON string, state []byte, err error) {
	wa, err := p.webauthn(ctx)
	if err != nil {
		return "", nil, err
	}
	user, err := p.loadUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range user.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return "", nil, fmt.Errorf("auth: begin registration: %w", err)
	}
	return marshalCeremony(creation, session)
}

// FinishRegistration validates the attestation and returns the credential to store.
func (p *Passkeys) FinishRegistration(ctx context.Context, u *store.User, state []byte, credentialJSON string) (*store.MFACredential, error) {
	wa, err := p.webauthn(ctx)
	if err != nil {
		return nil, err
	}
	session, err := unmarshalSession(state)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(credentialJSON))
	if err != nil {
		return nil, fmt.Errorf("auth: invalid passkey response: %w", err)
	}
	user, err := p.loadUser(ctx, u)
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("auth: passkey registration failed: %w", err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &store.MFACredential{
		ID: store.NewID(), UserID: u.ID, Type: store.MFATypePasskey,
		PasskeyCredential: raw, PasskeyCredentialID: cred.ID, CreatedAt: now,
	}, nil
}

// BeginLogin starts an assertion for a known user (MFA and step-up).
func (p *Passkeys) BeginLogin(ctx context.Context, u *store.User) (optionsJSON string, state []byte, err error) {
	wa, err := p.webauthn(ctx)
	if err != nil {
		return "", nil, err
	}
	user, err := p.loadUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	if len(user.creds) == 0 {
		return "", nil, errors.New("auth: no passkeys registered")
	}
	assertion, session, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, fmt.Errorf("auth: begin login: %w", err)
	}
	return marshalCeremony(assertion, session)
}

// FinishLogin validates an assertion for a known user and updates the credential's counter.
func (p *Passkeys) FinishLogin(ctx context.Context, u *store.User, state []byte, credentialJSON string) error {
	wa, err := p.webauthn(ctx)
	if err != nil {
		return err
	}
	session, err := unmarshalSession(state)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(credentialJSON))
	if err != nil {
		return fmt.Errorf("auth: invalid passkey response: %w", err)
	}
	user, err := p.loadUser(ctx, u)
	if err != nil {
		return err
	}
	cred, err := wa.ValidateLogin(user, *session, parsed)
	if err != nil {
		return fmt.Errorf("auth: passkey verification failed: %w", err)
	}
	return p.recordUse(ctx, user, cred)
}

// BeginDiscoverable starts a passwordless login; the returned ceremony ID goes into a cookie.
func (p *Passkeys) BeginDiscoverable(ctx context.Context) (optionsJSON, ceremonyID string, err error) {
	wa, err := p.webauthn(ctx)
	if err != nil {
		return "", "", err
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", "", fmt.Errorf("auth: begin discoverable login: %w", err)
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return "", "", err
	}
	id := crypto.RandomToken(24)
	p.mu.Lock()
	now := time.Now()
	for k, c := range p.ceremonies {
		if now.After(c.expires) {
			delete(p.ceremonies, k)
		}
	}
	if len(p.ceremonies) > 10_000 {
		p.mu.Unlock()
		return "", "", errors.New("auth: too many pending passkey logins")
	}
	p.ceremonies[id] = pendingCeremony{data: *session, expires: now.Add(ceremonyTTL)}
	p.mu.Unlock()
	return string(opts), id, nil
}

// FinishDiscoverable validates a passwordless assertion and returns the user.
func (p *Passkeys) FinishDiscoverable(ctx context.Context, ceremonyID, credentialJSON string) (*store.User, error) {
	p.mu.Lock()
	c, ok := p.ceremonies[ceremonyID]
	delete(p.ceremonies, ceremonyID) // single use
	p.mu.Unlock()
	if !ok || time.Now().After(c.expires) {
		return nil, errors.New("auth: passkey login expired; try again")
	}
	wa, err := p.webauthn(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(credentialJSON))
	if err != nil {
		return nil, fmt.Errorf("auth: invalid passkey response: %w", err)
	}
	st := p.holder.Get()
	if st == nil {
		return nil, store.ErrUnavailable
	}
	var found *waUser
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) == 0 || len(userHandle) > 64 {
			return nil, errors.New("auth: unknown passkey")
		}
		u, err := st.Users.FindOne(ctx, store.System(), store.Eq("webauthn_id", hex.EncodeToString(userHandle)))
		if err != nil {
			return nil, errors.New("auth: unknown passkey")
		}
		wu, err := p.loadUser(ctx, u)
		if err != nil {
			return nil, err
		}
		found = wu
		return wu, nil
	}
	_, cred, err := wa.ValidatePasskeyLogin(handler, c.data, parsed)
	if err != nil || found == nil {
		return nil, errors.New("auth: passkey verification failed")
	}
	if err := p.recordUse(ctx, found, cred); err != nil {
		return nil, err
	}
	return found.u, nil
}

func (p *Passkeys) recordUse(ctx context.Context, user *waUser, cred *webauthn.Credential) error {
	if cred.Authenticator.CloneWarning {
		return errors.New("auth: passkey signature counter went backwards (possible cloned authenticator)")
	}
	st := p.holder.Get()
	for _, c := range user.creds {
		if string(c.PasskeyCredentialID) != string(cred.ID) {
			continue
		}
		raw, err := json.Marshal(cred)
		if err != nil {
			return err
		}
		c.PasskeyCredential = raw
		c.LastUsedAt = time.Now().UTC()
		return st.MFA.Update(ctx, store.System(), c)
	}
	return errors.New("auth: credential not found")
}

type ceremonyState struct {
	Session webauthn.SessionData `json:"session"`
	Expires time.Time            `json:"expires"`
}

func marshalCeremony(options any, session *webauthn.SessionData) (string, []byte, error) {
	opts, err := json.Marshal(options)
	if err != nil {
		return "", nil, err
	}
	state, err := json.Marshal(ceremonyState{Session: *session, Expires: time.Now().Add(ceremonyTTL)})
	if err != nil {
		return "", nil, err
	}
	return string(opts), state, nil
}

func unmarshalSession(state []byte) (*webauthn.SessionData, error) {
	var cs ceremonyState
	if err := json.Unmarshal(state, &cs); err != nil || len(state) == 0 {
		return nil, errors.New("auth: no passkey ceremony in progress")
	}
	if time.Now().After(cs.Expires) {
		return nil, errors.New("auth: passkey ceremony expired; try again")
	}
	return &cs.Session, nil
}
