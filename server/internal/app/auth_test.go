// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	apiv1 "github.com/Shaalan15/central/gen/go/central/api/v1"
	"github.com/Shaalan15/central/gen/go/central/api/v1/apiv1connect"
	"github.com/Shaalan15/central/server/internal/authz"
	"github.com/Shaalan15/central/server/internal/store"
)

const ownerPassword = "tidy-lantern-orbit-42"

// browser is a cookie-carrying client that sends the CSRF token like the UI does.
type browser struct {
	t     *testing.T
	base  string
	hc    *http.Client
	csrf  string
	auth  apiv1connect.AuthServiceClient
	org   apiv1connect.OrganizationServiceClient
	mem   apiv1connect.MemberServiceClient
	keys  apiv1connect.ApiKeyServiceClient
	audit apiv1connect.AuditServiceClient
}

func newBrowser(t *testing.T, base string) *browser {
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, base: base, hc: &http.Client{Jar: jar}}
	opt := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if b.csrf != "" {
				req.Header().Set("X-CSRF-Token", b.csrf)
			}
			return next(ctx, req)
		}
	}))
	b.auth = apiv1connect.NewAuthServiceClient(b.hc, base+"/api", opt)
	b.org = apiv1connect.NewOrganizationServiceClient(b.hc, base+"/api", opt)
	b.mem = apiv1connect.NewMemberServiceClient(b.hc, base+"/api", opt)
	b.keys = apiv1connect.NewApiKeyServiceClient(b.hc, base+"/api", opt)
	b.audit = apiv1connect.NewAuditServiceClient(b.hc, base+"/api", opt)
	return b
}

func (b *browser) refreshCSRF() *apiv1.GetSessionResponse {
	b.t.Helper()
	res, err := b.auth.GetSession(context.Background(), connect.NewRequest(&apiv1.GetSessionRequest{}))
	if err != nil {
		b.t.Fatalf("GetSession: %v", err)
	}
	b.csrf = res.Msg.GetCsrfToken()
	return res.Msg
}

func (b *browser) login(email, password string) (*apiv1.LoginResponse, error) {
	res, err := b.auth.Login(context.Background(), connect.NewRequest(&apiv1.LoginRequest{Email: email, Password: password}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func reason(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Meta().Get(authz.ReasonHeader)
	}
	return ""
}

// completeSetup runs the dev wizard and returns the env.
func completeSetup(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.client.BeginSetup(ctx, connect.NewRequest(&apiv1.BeginSetupRequest{SetupToken: env.token})); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.SaveEndpoints(ctx, connect.NewRequest(&apiv1.SaveEndpointsRequest{
		PublicUrl: env.srv.URL, AgentUrl: "https://localhost:9443",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.CreateOwner(ctx, connect.NewRequest(&apiv1.CreateOwnerRequest{
		Email: "owner@example.com", DisplayName: "Olivia Owner", OrganizationName: "Acme Ops", Password: ownerPassword,
	})); err != nil {
		t.Fatal(err)
	}
	return env
}

// enrollTOTP signs in a fresh user and enrolls TOTP, returning the browser and secret.
func enrollTOTP(t *testing.T, env *testEnv, email, password string) (*browser, string) {
	t.Helper()
	ctx := context.Background()
	b := newBrowser(t, env.srv.URL)
	lr, err := b.login(email, password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if lr.GetStage() != apiv1.SessionStage_SESSION_STAGE_MFA_ENROLLMENT {
		t.Fatalf("first login stage = %v", lr.GetStage())
	}
	b.refreshCSRF()
	begin, err := b.auth.BeginTotpEnrollment(ctx, connect.NewRequest(&apiv1.BeginTotpEnrollmentRequest{}))
	if err != nil {
		t.Fatalf("BeginTotpEnrollment: %v", err)
	}
	if !strings.HasPrefix(begin.Msg.GetOtpauthUri(), "otpauth://totp/Central:") {
		t.Fatalf("uri = %s", begin.Msg.GetOtpauthUri())
	}
	conf, err := b.auth.ConfirmTotpEnrollment(ctx, connect.NewRequest(&apiv1.ConfirmTotpEnrollmentRequest{
		EnrollmentId: begin.Msg.GetEnrollmentId(), Code: totpCode(t, begin.Msg.GetSecret(), time.Now()), Name: "Phone",
	}))
	if err != nil {
		t.Fatalf("ConfirmTotpEnrollment: %v", err)
	}
	if conf.Msg.GetStage() != apiv1.SessionStage_SESSION_STAGE_FULL || len(conf.Msg.GetRecoveryCodes()) != 10 {
		t.Fatalf("confirm = %v", conf.Msg)
	}
	b.refreshCSRF()
	return b, begin.Msg.GetSecret()
}

func TestAuthFlow(t *testing.T) {
	env := completeSetup(t)
	ctx := context.Background()

	// Wrong password: generic error; unknown user: same error.
	anon := newBrowser(t, env.srv.URL)
	if _, err := anon.login("owner@example.com", "wrong-password-xyz"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := anon.login("nobody@example.com", "wrong-password-xyz"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("unknown user: %v", err)
	}
	// Unauthenticated calls are rejected.
	if _, err := anon.org.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous GetOrganization: %v", err)
	}

	// First sign-in: MFA enrollment is mandatory; nothing else is reachable.
	b := newBrowser(t, env.srv.URL)
	if _, err := b.login("OWNER@example.com", ownerPassword); err != nil {
		t.Fatal(err)
	}
	sess := b.refreshCSRF()
	if sess.GetStage() != apiv1.SessionStage_SESSION_STAGE_MFA_ENROLLMENT || len(sess.GetPermissions()) != 0 {
		t.Fatalf("partial session = %v", sess)
	}
	if _, err := b.org.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("partial session reached GetOrganization: %v", err)
	}
	// CSRF: the same call without the header is refused.
	saved := b.csrf
	b.csrf = ""
	if _, err := b.auth.BeginTotpEnrollment(ctx, connect.NewRequest(&apiv1.BeginTotpEnrollmentRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("missing CSRF accepted: %v", err)
	}
	b.csrf = "forged"
	if _, err := b.auth.BeginTotpEnrollment(ctx, connect.NewRequest(&apiv1.BeginTotpEnrollmentRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("forged CSRF accepted: %v", err)
	}
	b.csrf = saved
	oldCookies := b.hc.Jar.Cookies(mustURL(env.srv.URL))

	begin, err := b.auth.BeginTotpEnrollment(ctx, connect.NewRequest(&apiv1.BeginTotpEnrollmentRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	secret := begin.Msg.GetSecret()
	if _, err := b.auth.ConfirmTotpEnrollment(ctx, connect.NewRequest(&apiv1.ConfirmTotpEnrollmentRequest{
		EnrollmentId: begin.Msg.GetEnrollmentId(), Code: "000000",
	})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("wrong enrollment code: %v", err)
	}
	conf, err := b.auth.ConfirmTotpEnrollment(ctx, connect.NewRequest(&apiv1.ConfirmTotpEnrollmentRequest{
		EnrollmentId: begin.Msg.GetEnrollmentId(), Code: totpCode(t, secret, time.Now()),
	}))
	if err != nil {
		t.Fatal(err)
	}
	recovery := conf.Msg.GetRecoveryCodes()
	full := b.refreshCSRF()
	if full.GetStage() != apiv1.SessionStage_SESSION_STAGE_FULL || full.GetActiveOrganization().GetName() != "Acme Ops" {
		t.Fatalf("full session = %v", full)
	}
	if !contains(full.GetPermissions(), authz.SystemKeyExport) || full.GetStepUpValidUntil() == nil {
		t.Fatalf("owner permissions/step-up missing: %v", full.GetPermissions())
	}
	// The pre-MFA session token was rotated away (fixation protection).
	stale := newBrowser(t, env.srv.URL)
	stale.hc.Jar.SetCookies(mustURL(env.srv.URL), oldCookies)
	if _, err := stale.auth.GetSession(ctx, connect.NewRequest(&apiv1.GetSessionRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("old session still valid: %v", err)
	}
	if _, err := b.org.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); err != nil {
		t.Fatalf("full session GetOrganization: %v", err)
	}

	// Second sign-in requires the TOTP; the enrollment code cannot be replayed.
	b2 := newBrowser(t, env.srv.URL)
	lr, err := b2.login("owner@example.com", ownerPassword)
	if err != nil || lr.GetStage() != apiv1.SessionStage_SESSION_STAGE_MFA_REQUIRED {
		t.Fatalf("second login: %v %v", lr, err)
	}
	b2.refreshCSRF()
	// Replay exactly the step used at enrollment (time.Now() could already be in the next step).
	used := lastTOTPStep(t, env)
	if _, err := b2.auth.VerifyTotp(ctx, connect.NewRequest(&apiv1.VerifyTotpRequest{Code: totpCode(t, secret, time.Unix(used*30, 0))})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("replayed TOTP accepted: %v", err)
	}
	if _, err := b2.auth.VerifyTotp(ctx, connect.NewRequest(&apiv1.VerifyTotpRequest{Code: totpCode(t, secret, time.Unix((used+1)*30, 0))})); err != nil {
		t.Fatalf("next-step TOTP: %v", err)
	}

	// Recovery codes work once.
	b3 := newBrowser(t, env.srv.URL)
	if _, err := b3.login("owner@example.com", ownerPassword); err != nil {
		t.Fatal(err)
	}
	b3.refreshCSRF()
	rc, err := b3.auth.UseRecoveryCode(ctx, connect.NewRequest(&apiv1.UseRecoveryCodeRequest{Code: strings.ToLower(recovery[0])}))
	if err != nil || rc.Msg.GetRemainingCodes() != 9 {
		t.Fatalf("recovery code: %v %v", rc, err)
	}
	b4 := newBrowser(t, env.srv.URL)
	_, _ = b4.login("owner@example.com", ownerPassword)
	b4.refreshCSRF()
	if _, err := b4.auth.UseRecoveryCode(ctx, connect.NewRequest(&apiv1.UseRecoveryCodeRequest{Code: recovery[0]})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("reused recovery code accepted: %v", err)
	}

	// Step-up: fresh MFA allows sensitive actions; an expired step-up is refused with a reason.
	inv, err := b.mem.InviteMember(ctx, connect.NewRequest(&apiv1.InviteMemberRequest{
		Email: "oscar@example.com", RoleBindings: []*apiv1.RoleBinding{{RoleId: authz.RoleOperator}},
	}))
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	expireStepUp(t, env)
	if _, err := b.mem.InviteMember(ctx, connect.NewRequest(&apiv1.InviteMemberRequest{
		Email: "x@example.com", RoleBindings: []*apiv1.RoleBinding{{RoleId: authz.RoleViewer}},
	})); code(err) != connect.CodeFailedPrecondition || reason(err) != authz.ReasonStepUpRequired {
		t.Fatalf("expired step-up: %v (reason %q)", err, reason(err))
	}
	if _, err := b.auth.FinishStepUp(ctx, connect.NewRequest(&apiv1.FinishStepUpRequest{
		Proof: &apiv1.FinishStepUpRequest_TotpCode{TotpCode: totpCode(t, secret, time.Now().Add(-30*time.Second))},
	})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("old-step TOTP should be rejected after newer use: %v", err)
	}

	// Invite acceptance creates an operator who must also enroll MFA.
	link := inv.Msg.GetInviteUrl()
	token := link[strings.Index(link, "#")+1:]
	if _, err := anon.auth.AcceptInvite(ctx, connect.NewRequest(&apiv1.AcceptInviteRequest{InviteToken: token + "x", DisplayName: "Oscar", Password: "sturdy-copper-ladder-7"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("tampered invite accepted: %v", err)
	}
	if _, err := anon.auth.AcceptInvite(ctx, connect.NewRequest(&apiv1.AcceptInviteRequest{InviteToken: token, DisplayName: "Oscar", Password: "sturdy-copper-ladder-7"})); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if _, err := anon.auth.AcceptInvite(ctx, connect.NewRequest(&apiv1.AcceptInviteRequest{InviteToken: token, DisplayName: "Oscar", Password: "sturdy-copper-ladder-7"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("invite reused: %v", err)
	}
	op, _ := enrollTOTP(t, env, "oscar@example.com", "sturdy-copper-ladder-7")
	if _, err := op.org.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); err != nil {
		t.Fatalf("operator can view the org: %v", err)
	}
	if _, err := op.keys.ListApiKeys(ctx, connect.NewRequest(&apiv1.ListApiKeysRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator listed API keys: %v", err)
	}
	if _, err := op.audit.ListAuditEvents(ctx, connect.NewRequest(&apiv1.ListAuditEventsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator read the audit log: %v", err)
	}

	// API keys: create (owner, fresh step-up), use with Bearer, cannot touch session endpoints.
	allowTOTPReuse(t, env) // simulate the next 30-second step having arrived
	stepUp(t, b, secret, time.Now())
	key, err := b.keys.CreateApiKey(ctx, connect.NewRequest(&apiv1.CreateApiKeyRequest{
		Name: "terraform", RoleBinding: &apiv1.RoleBinding{RoleId: authz.RoleViewer},
	}))
	if err != nil {
		t.Fatalf("CreateApiKey: %v", err)
	}
	bearer := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+key.Msg.GetSecret())
			return next(ctx, req)
		}
	}))
	machineOrg := apiv1connect.NewOrganizationServiceClient(http.DefaultClient, env.srv.URL+"/api", bearer)
	if _, err := machineOrg.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); err != nil {
		t.Fatalf("API key GetOrganization: %v", err)
	}
	if _, err := machineOrg.UpdateOrganization(ctx, connect.NewRequest(&apiv1.UpdateOrganizationRequest{Name: "pwned"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer API key updated org: %v", err)
	}
	machineAuth := apiv1connect.NewAuthServiceClient(http.DefaultClient, env.srv.URL+"/api", bearer)
	if _, err := machineAuth.GetSession(ctx, connect.NewRequest(&apiv1.GetSessionRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("API key used session endpoint: %v", err)
	}
	if _, err := b.keys.RevokeApiKey(ctx, connect.NewRequest(&apiv1.RevokeApiKeyRequest{ApiKeyId: key.Msg.GetApiKey().GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := machineOrg.GetOrganization(ctx, connect.NewRequest(&apiv1.GetOrganizationRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("revoked API key accepted: %v", err)
	}

	// Removing the last owner is refused.
	if _, err := b.mem.RemoveMember(ctx, connect.NewRequest(&apiv1.RemoveMemberRequest{UserId: full.GetUser().GetId()})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("last owner removed: %v", err)
	}

	// The audit log recorded all of it, and the chain verifies.
	events, err := b.audit.ListAuditEvents(ctx, connect.NewRequest(&apiv1.ListAuditEventsRequest{Page: &apiv1.PageRequest{PageSize: 500}}))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range events.Msg.GetEvents() {
		seen[e.GetAction()] = true
		for k, v := range e.GetDetails() {
			if strings.Contains(v, ownerPassword) || strings.Contains(k, "password") {
				t.Fatalf("audit event leaks secrets: %v", e)
			}
		}
	}
	for _, a := range []string{"setup.completed", "auth.login", "auth.mfa_added", "member.invited", "member.joined", "apikey.created", "apikey.revoked", "auth.step_up"} {
		if !seen[a] {
			t.Errorf("audit log missing %s (have %v)", a, keysOf(seen))
		}
	}
	v, err := b.audit.VerifyAuditChain(ctx, connect.NewRequest(&apiv1.VerifyAuditChainRequest{}))
	if err != nil || !v.Msg.GetIntact() || v.Msg.GetEventsChecked() < 8 {
		t.Fatalf("audit chain: %v %v", v, err)
	}
}

func TestLockout(t *testing.T) {
	env := completeSetup(t)
	b := newBrowser(t, env.srv.URL)
	for range 5 {
		_, _ = b.login("owner@example.com", "definitely-wrong-1")
	}
	// Even the right password is refused while locked.
	if _, err := b.login("owner@example.com", ownerPassword); code(err) != connect.CodeResourceExhausted {
		t.Fatalf("locked account accepted: %v", err)
	}
}

func stepUp(t *testing.T, b *browser, secret string, at time.Time) {
	t.Helper()
	if _, err := b.auth.BeginStepUp(context.Background(), connect.NewRequest(&apiv1.BeginStepUpRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.auth.FinishStepUp(context.Background(), connect.NewRequest(&apiv1.FinishStepUpRequest{
		Proof: &apiv1.FinishStepUpRequest_TotpCode{TotpCode: totpCode(t, secret, at)},
	})); err != nil {
		t.Fatalf("FinishStepUp: %v", err)
	}
}

// lastTOTPStep returns the most recent time step accepted for any TOTP credential.
func lastTOTPStep(t *testing.T, env *testEnv) int64 {
	t.Helper()
	creds, err := env.app.Holder.Get().MFA.All(context.Background(), store.System(), store.Query{})
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	for _, c := range creds {
		last = max(last, c.TOTPLastStep)
	}
	return last
}

// allowTOTPReuse resets the replay guard of every TOTP credential (simulates time passing).
func allowTOTPReuse(t *testing.T, env *testEnv) {
	t.Helper()
	ctx := context.Background()
	st := env.app.Holder.Get()
	creds, err := st.MFA.All(ctx, store.System(), store.Query{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range creds {
		c.TOTPLastStep = 0
		if err := st.MFA.Update(ctx, store.System(), c); err != nil {
			t.Fatal(err)
		}
	}
}

// expireStepUp backdates every session's step-up (simulates the window passing).
func expireStepUp(t *testing.T, env *testEnv) {
	t.Helper()
	ctx := context.Background()
	st := env.app.Holder.Get()
	all, err := st.Sessions.All(ctx, store.System(), store.Query{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		s.StepUpAt = time.Now().Add(-time.Hour)
		if err := env.app.Deps.Sessions.Update(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
