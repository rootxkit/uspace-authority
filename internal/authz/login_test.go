package authz

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
)

func newCounters() *core.Counters { return &core.Counters{} }

func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	var pe *httpx.ProblemError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a problem", err)
	}
	return pe.Problem
}

// The whole sign-in, accepted: password, enrolment, TOTP, a session that
// the authenticator admits with the row's roles, then logout.
func TestSignInEnrolsAndStartsASession(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	lr, err := f.svc.Login(ctx, " ADMIN ", adminPW, ri)
	if err != nil || lr.EnrolSecret == "" || !strings.Contains(lr.EnrolURI, "otpauth://totp/") || lr.Token == "" {
		t.Fatalf("login: %+v %v", lr, err)
	}
	f.secrets["admin"] = lr.EnrolSecret
	// The secret is sealed at rest.
	m := f.st.mfa[f.admin.ID]
	if strings.Contains(string(m.SecretEnc), lr.EnrolSecret) || m.KeyID != "pii-1" || m.EnrolledAt != nil {
		t.Fatalf("stored MFA %+v", m)
	}
	// A pending enrolment shows the same secret again.
	lr2, _ := f.svc.Login(ctx, "admin", adminPW, ri)
	if lr2.EnrolSecret != lr.EnrolSecret {
		t.Fatal("a second login replaced the pending secret")
	}
	code, _ := totp.GenerateCode(lr.EnrolSecret, f.clk.Now())
	res, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri)
	if err != nil || len(res.RecoveryCodes) != RecoveryCodes || res.Token == "" {
		t.Fatalf("mfa: %+v %v", res, err)
	}
	if f.st.mfa[f.admin.ID].EnrolledAt == nil || len(f.st.mfa[f.admin.ID].RecoveryHashes) != RecoveryCodes {
		t.Fatal("enrolment not confirmed")
	}
	id, err := f.identify(res.Token)
	if err != nil || !id.Session || id.Subject != f.admin.ID || !slices.Equal(id.Roles, []string{"admin"}) || id.Realm != "console" || id.JTI != res.Session.JTI {
		t.Fatalf("identity %+v %v", id, err)
	}
	if err := f.svc.Logout(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("after logout: %v", err)
	}
	for et, n := range map[string]int{audit.EventLoginPasswordAccepted: 2, audit.EventMFAEnrolled: 1, audit.EventSessionStarted: 1, audit.EventLogout: 1} {
		if got := len(f.st.eventsOf(et)); got != n {
			t.Errorf("%s: %d events, want %d", et, got, n)
		}
	}
	// A later sign-in shows no enrolment and returns no recovery codes.
	res2 := f.signIn(t, "admin", adminPW)
	if res2.RecoveryCodes != nil {
		t.Fatal("recovery codes shown twice")
	}
}

// E-01, no enumeration: unknown user, disabled user and wrong password
// get the same problem and each spends one argon2id verification; the
// right password is accepted.
func TestLoginRefusalsAreIndistinguishable(t *testing.T) {
	f := newFixture(t, fxOpts{params: passhash.Params{MemoryKiB: 19456, Time: 2, Threads: 1}})
	ctx := context.Background()
	disabled, _ := f.svc.CreateUser(ctx, NewUser{Username: "gone", Password: adminPW, Realm: "console"}, adminActor)
	if _, err := f.svc.SetStatus(ctx, disabled.ID, StatusDisabled, adminActor); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"unknown_user":   {"nobody", adminPW},
		"wrong_password": {"admin", "wrong password!!"},
		"user_disabled":  {"gone", adminPW},
	}
	var first *httpx.Problem
	timings := map[string][]time.Duration{}
	for range 5 {
		for reason, c := range cases {
			start := time.Now()
			_, err := f.svc.Login(ctx, c[0], c[1], ri)
			timings[reason] = append(timings[reason], time.Since(start))
			p := problemOf(t, err)
			if p.Status != http.StatusUnauthorized || p.Slug() != SlugInvalidCredentials {
				t.Fatalf("%s: %+v", reason, p)
			}
			if first == nil {
				first = p
			} else if p.Detail != first.Detail || p.Title != first.Title {
				t.Fatalf("%s answers %q, another refusal %q", reason, p.Detail, first.Detail)
			}
		}
	}
	median := func(d []time.Duration) time.Duration {
		s := slices.Clone(d)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[len(s)/2]
	}
	ref := median(timings["wrong_password"])
	for reason, d := range timings {
		if m := median(d); m < ref/3 || m > ref*3 {
			t.Errorf("%s median %s, wrong password %s: the timing tells them apart (%v)", reason, m, ref, d)
		}
	}
	reasons := map[string]bool{}
	for _, e := range f.st.eventsOf(audit.EventLoginRefused) {
		reasons[e.Payload.(map[string]any)["reason"].(string)] = true
	}
	for r := range cases {
		if !reasons[r] {
			t.Errorf("no login_refused event with reason %s", r)
		}
	}
	if _, err := f.svc.Login(ctx, "admin", adminPW, ri); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
}

func TestLoginWithoutAStoredPasswordIsRefused(t *testing.T) {
	f := newFixture(t, fxOpts{})
	delete(f.st.passwords, f.admin.ID)
	if _, err := f.svc.Login(context.Background(), "admin", adminPW, ri); problemOf(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal("accepted without a stored password")
	}
	f.st.failReads = true
	if _, err := f.svc.Login(context.Background(), "admin", adminPW, ri); err == nil || errors.As(err, new(*httpx.ProblemError)) {
		t.Fatalf("a store outage is not a refusal of credentials: %v", err)
	}
}

// S-15: per address and per username limits, each beside its accepted
// twin, and bounded maps (E-10).
func TestLoginRateLimits(t *testing.T) {
	f := newFixture(t, fxOpts{ipBurst: 3, userBurst: 2, maxKeys: 4})
	ctx := context.Background()
	for range 2 {
		if _, err := f.svc.Login(ctx, "admin", adminPW, ri); err != nil {
			t.Fatal(err)
		}
	}
	var rl *RateLimitedError
	if _, err := f.svc.Login(ctx, "admin", adminPW, ri); !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.Problem.Status != 429 {
		t.Fatalf("per username: %v", err)
	}
	other := ri
	other.RemoteIP = "192.0.2.99"
	if _, err := f.svc.Login(ctx, "nobody", "x", other); errors.As(err, &rl) {
		t.Fatal("another username from another address was limited")
	}
	// The address of ri has spent 3 (two accepted, one refused).
	if _, err := f.svc.Login(ctx, "someone-else", "x", ri); !errors.As(err, &rl) {
		t.Fatalf("per address: %v", err)
	}
	for i := range 20 {
		f.svc.UserLimiter.Allow(limiterKey("user" + string(rune('a'+i))))
		f.svc.IPLimiter.Allow("ip:198.51.100." + string(rune('0'+i%10)))
	}
	if f.svc.UserLimiter.Len() > 4 || f.svc.IPLimiter.Len() > 4 {
		t.Fatalf("limiters hold %d and %d keys, bound 4", f.svc.UserLimiter.Len(), f.svc.IPLimiter.Len())
	}
	reasons := map[string]bool{}
	for _, e := range f.st.eventsOf(audit.EventLoginRefused) {
		reasons[e.Payload.(map[string]any)["reason"].(string)] = true
	}
	if !reasons["rate_limited_username"] || !reasons["rate_limited_address"] {
		t.Fatalf("rate-limit refusals not recorded: %v", reasons)
	}
	if limiterKey(strings.Repeat("x", 300)) != "u:"+strings.Repeat("x", 64) {
		t.Fatal("limiter key not bounded")
	}
}

// MFA refusals beside acceptance: a wrong code, a code reused in its
// step, a challenge used, expired or exhausted, a recovery code before
// enrolment, a malformed request; the right code is accepted, and a
// recovery code once.
func TestMFARefusalsBesideAcceptance(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	first := f.signIn(t, "admin", adminPW)
	secret := f.secrets["admin"]

	refused := func(name, wantReason string, err error) {
		t.Helper()
		if p := problemOf(t, err); p.Slug() != SlugMFARefused {
			t.Errorf("%s: %+v", name, p)
		}
		evs := f.st.eventsOf(audit.EventMFARefused)
		if got := evs[len(evs)-1].Payload.(map[string]any)["reason"]; got != wantReason {
			t.Errorf("%s: recorded reason %v, want %s", name, got, wantReason)
		}
	}
	// The code of the step just used is refused in a new challenge.
	lr, _ := f.svc.Login(ctx, "admin", adminPW, ri)
	code, _ := totp.GenerateCode(secret, f.clk.Now())
	_, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri)
	refused("replayed code", "wrong_code", err)
	_, err = f.svc.VerifyMFA(ctx, lr.Token, "123456", "", ri)
	refused("wrong code", "wrong_code", err)
	f.clk.Advance(TOTPPeriod)
	code, _ = totp.GenerateCode(secret, f.clk.Now())
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri); err != nil {
		t.Fatalf("the next step's code, within the attempt bound: %v", err)
	}

	lr, _ = f.svc.Login(ctx, "admin", adminPW, ri)
	for range 3 {
		_, _ = f.svc.VerifyMFA(ctx, lr.Token, "000000", "", ri)
	}
	f.clk.Advance(TOTPPeriod)
	code, _ = totp.GenerateCode(secret, f.clk.Now())
	_, err = f.svc.VerifyMFA(ctx, lr.Token, code, "", ri)
	refused("exhausted", "challenge_exhausted", err)

	lr, _ = f.svc.Login(ctx, "admin", adminPW, ri)
	f.clk.Advance(6 * time.Minute)
	code, _ = totp.GenerateCode(secret, f.clk.Now())
	_, err = f.svc.VerifyMFA(ctx, lr.Token, code, "", ri)
	refused("expired", "challenge_expired", err)

	_, err = f.svc.VerifyMFA(ctx, "no-such-challenge", "123456", "", ri)
	refused("unknown", "challenge_unknown", err)
	_, err = f.svc.VerifyMFA(ctx, "x", "123456", "abcd", ri)
	refused("both", "malformed", err)
	_, err = f.svc.VerifyMFA(ctx, "x", "", "", ri)
	refused("neither", "malformed", err)

	// A recovery code works once.
	lr, _ = f.svc.Login(ctx, "admin", adminPW, ri)
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, "", strings.ToUpper(first.RecoveryCodes[3]), ri); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	_, err = f.svc.VerifyMFA(ctx, lr.Token, "", first.RecoveryCodes[4], ri)
	refused("used challenge", "challenge_used", err)
	lr, _ = f.svc.Login(ctx, "admin", adminPW, ri)
	_, err = f.svc.VerifyMFA(ctx, lr.Token, "", first.RecoveryCodes[3], ri)
	refused("recovery code reused", "wrong_recovery_code", err)
	if n := len(f.st.mfa[f.admin.ID].RecoveryHashes); n != RecoveryCodes-1 {
		t.Fatalf("%d recovery codes left", n)
	}

	// Before enrolment a recovery code is refused.
	u, _ := f.svc.CreateUser(ctx, NewUser{Username: "new-user", Password: adminPW, Realm: "console", Roles: []string{"viewer"}}, adminActor)
	_ = u
	lr, _ = f.svc.Login(ctx, "new-user", adminPW, ri)
	_, err = f.svc.VerifyMFA(ctx, lr.Token, "", first.RecoveryCodes[5], ri)
	refused("recovery before enrolment", "recovery_before_enrolment", err)
}

func TestMFARefusedForADisabledOrResetAccount(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	f.signIn(t, "admin", adminPW)
	second, _ := f.svc.CreateUser(ctx, NewUser{Username: "second", Password: adminPW, Realm: "console", Roles: []string{"admin"}}, adminActor)
	f.signIn(t, "second", adminPW)

	lr, _ := f.svc.Login(ctx, "second", adminPW, ri)
	if _, err := f.svc.SetStatus(ctx, second.ID, StatusDisabled, adminActor); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(TOTPPeriod)
	code, _ := totp.GenerateCode(f.secrets["second"], f.clk.Now())
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri); problemOf(t, err).Slug() != SlugMFARefused {
		t.Fatal("a disabled account finished its sign-in")
	}
	if _, err := f.svc.SetStatus(ctx, second.ID, StatusActive, adminActor); err != nil {
		t.Fatal(err)
	}
	lr, _ = f.svc.Login(ctx, "second", adminPW, ri)
	if _, err := f.svc.ResetMFA(ctx, second.ID, adminActor); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(TOTPPeriod)
	code, _ = totp.GenerateCode(f.secrets["second"], f.clk.Now())
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri); problemOf(t, err).Slug() != SlugMFARefused {
		t.Fatal("a reset account finished its sign-in with the old secret")
	}
	// It enrols again with a new secret.
	lr, _ = f.svc.Login(ctx, "second", adminPW, ri)
	if lr.EnrolSecret == "" || lr.EnrolSecret == f.secrets["second"] {
		t.Fatal("no new enrolment after a reset")
	}
}

// Table A idle 30 min: a session used within the idle timeout lives on,
// one idle longer is ended for good; expiry at 12 h; revocation.
func TestSessionIdleExpiryAndRevocation(t *testing.T) {
	f := newFixture(t, fxOpts{})
	res := f.signIn(t, "admin", adminPW)
	f.clk.Advance(29 * time.Minute)
	if _, err := f.identify(res.Token); err != nil {
		t.Fatalf("within the idle timeout: %v", err)
	}
	f.clk.Advance(29 * time.Minute)
	if _, err := f.identify(res.Token); err != nil {
		t.Fatalf("used again within the idle timeout: %v", err)
	}
	f.clk.Advance(31 * time.Minute)
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) || !strings.Contains(err.Error(), "idle") {
		t.Fatalf("idle: %v", err)
	}
	f.clk.Advance(-31 * time.Minute)
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("an idle-ended session came back")
	}

	// 12 h: the verifier refuses the token itself.
	res = f.signIn(t, "admin", adminPW)
	for range 25 {
		f.clk.Advance(29 * time.Minute)
		_, _ = f.identify(res.Token)
	}
	if _, err := f.identify(res.Token); err == nil || !strings.Contains(err.Error(), "exp") {
		t.Fatalf("after 12 h: %v", err)
	}

	res = f.signIn(t, "admin", adminPW)
	n, err := f.svc.RevokeSessions(context.Background(), f.admin.ID, adminActor)
	if err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("revoked: %v", err)
	}
	if ev := f.st.eventsOf(audit.EventSessionRevoked); len(ev) != 1 {
		t.Fatalf("revocation events %d", len(ev))
	}
}

func TestSessionRowMustMatchTheToken(t *testing.T) {
	f := newFixture(t, fxOpts{})
	res := f.signIn(t, "admin", adminPW)
	s := f.st.sessions[res.Session.JTI]
	s.UserID = "someone-else"
	f.st.sessions[res.Session.JTI] = s
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("another account's row: %v", err)
	}
	delete(f.st.sessions, res.Session.JTI)
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("no row: %v", err)
	}
	res = f.signIn(t, "admin", adminPW)
	f.st.failReads = true
	if _, err := f.identify(res.Token); err == nil || errors.Is(err, ErrSessionRefused) {
		t.Fatalf("store outage: %v", err)
	}
}

// E-10: live sessions per account are bounded (the oldest is revoked),
// and the sweep deletes expired rows.
func TestSessionsAreBounded(t *testing.T) {
	f := newFixture(t, fxOpts{maxSessions: 2})
	var tokens []string
	for range 3 {
		tokens = append(tokens, f.signIn(t, "admin", adminPW).Token)
	}
	if _, err := f.identify(tokens[0]); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("the oldest session survived the limit")
	}
	for _, tok := range tokens[1:] {
		if _, err := f.identify(tok); err != nil {
			t.Fatalf("a newer session ended: %v", err)
		}
	}
	if len(f.st.sessions) != 3 {
		t.Fatalf("%d rows", len(f.st.sessions))
	}
	f.clk.Advance(12*time.Hour + SweepRetention + time.Minute)
	s, c, err := f.svc.Sweep(context.Background())
	if err != nil || s != 3 || c == 0 || len(f.st.sessions) != 0 || len(f.st.challenges) != 0 {
		t.Fatalf("sweep %d %d %v left %d %d", s, c, err, len(f.st.sessions), len(f.st.challenges))
	}
	if s, _, _ := f.svc.Sweep(context.Background()); s != 0 {
		t.Fatal("a second sweep deleted again")
	}
}

func TestRunSweepStopsWithItsContext(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.RunSweep(ctx, time.Millisecond); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSweep did not stop")
	}
}

// Concurrency under -race: parallel sign-ins of several accounts.
func TestParallelSignIns(t *testing.T) {
	f := newFixture(t, fxOpts{maxSessions: 100})
	ctx := context.Background()
	for i := range 4 {
		name := "user-" + string(rune('a'+i))
		_, _ = f.svc.CreateUser(ctx, NewUser{Username: name, Password: adminPW, Realm: "console", Roles: []string{"viewer"}}, adminActor)
		f.signIn(t, name, adminPW)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		name := "user-" + string(rune('a'+i%4))
		wg.Go(func() {
			if _, err := f.svc.Login(ctx, name, adminPW, ri); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestRefusalStandsWhenItsEventCannotBeWritten(t *testing.T) {
	f := newFixture(t, fxOpts{})
	f.st.failRecord = true
	if _, err := f.svc.Login(context.Background(), "admin", "wrong password!!", ri); problemOf(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal("not refused")
	}
	if f.svc.Counters.Get(CounterRefusalNotSaved) != 1 {
		t.Fatalf("counters %v", f.svc.Counters.Snapshot())
	}
	// And an accepted password whose event cannot be written opens no
	// challenge.
	if _, err := f.svc.Login(context.Background(), "admin", adminPW, ri); err == nil {
		t.Fatal("a challenge without its event")
	}
	if len(f.st.challenges) != 0 {
		t.Fatal("the challenge survived the rolled-back transaction")
	}
}

func FuzzLogin(f *testing.F) {
	fx := newFixture(f, fxOpts{})
	f.Add("admin", "wrong")
	f.Add("\x00", strings.Repeat("p", 2000))
	f.Add("ADMIN ", adminPW)
	f.Fuzz(func(t *testing.T, user, pw string) {
		_, err := fx.svc.Login(context.Background(), user, pw, ri)
		if err == nil && (NormalizeUsername(user) != "admin" || pw != adminPW) {
			t.Fatalf("signed in %q with %q", user, pw)
		}
	})
}

func FuzzVerifyMFA(f *testing.F) {
	fx := newFixture(f, fxOpts{})
	f.Add("token", "123456", "")
	f.Add("", "", "aaaa-bbbb-cccc-dddd")
	f.Fuzz(func(t *testing.T, challenge, code, recovery string) {
		if _, err := fx.svc.VerifyMFA(context.Background(), challenge, code, recovery, ri); err == nil {
			t.Fatal("a session from fuzzed input")
		}
	})
}
