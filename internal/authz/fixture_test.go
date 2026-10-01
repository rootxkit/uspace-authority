package authz

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const (
	testIssuer = "https://authority.example.test"
	ownHost    = "authority.example.test"
	adminPW    = "correct horse battery staple"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	st      *memStore
	clk     *clock
	svc     *Service
	keys    *tokens.Keys
	v       *Verifier
	a       *Authenticator
	admin   User
	secrets map[string]string // username -> TOTP secret
}

type fxOpts struct {
	params      passhash.Params
	ipBurst     int
	userBurst   int
	maxSessions int
	maxKeys     int
}

var cheapParams = passhash.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func testKeys(t testing.TB, now time.Time, idx ...int) *tokens.Keys {
	t.Helper()
	var files []tokens.KeyFile
	for _, i := range idx {
		f, err := tokens.NewKeyFile("k.pem", tokentest.Key(t, i))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	k, err := tokens.NewKeys(testIssuer, 24*time.Hour, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	from := now.Add(-time.Hour)
	if err := k.Apply([]tokens.KeyRow{{KID: files[0].KID, Purpose: tokens.PurposeToken, PublicJWK: files[0].PublicJWK, ActiveFrom: &from}}); err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixture(t testing.TB, o fxOpts) *fixture {
	t.Helper()
	if o.params == (passhash.Params{}) {
		o.params = cheapParams
	}
	for _, p := range []*int{&o.ipBurst, &o.userBurst} {
		if *p == 0 {
			*p = 1000
		}
	}
	if o.maxSessions == 0 {
		o.maxSessions = 5
	}
	if o.maxKeys == 0 {
		o.maxKeys = 100
	}
	h, err := passhash.New(o.params)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := pii.NewSealer("pii-1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 5, 0, time.UTC)}
	f := &fixture{st: newMemStore(), clk: clk, keys: testKeys(t, clk.Now(), 0), secrets: map[string]string{}}
	f.svc = &Service{
		Store: f.st, Hasher: h, Sealer: sealer, Keys: f.keys, Counters: newCounters(),
		IPLimiter:   httpx.NewRateLimiter(1, o.ipBurst, o.maxKeys, nil),
		UserLimiter: httpx.NewRateLimiter(1, o.userBurst, o.maxKeys, nil),
		Config: Config{OwnHost: ownHost, SessionTTL: 12 * time.Hour, IdleTimeout: 30 * time.Minute, MaxSessions: o.maxSessions,
			ChallengeTTL: 5 * time.Minute, MaxAttempts: 3, PasswordMinLen: 12, TOTPIssuer: "uspace-authority", Now: clk.Now},
	}
	f.v, err = NewVerifier(context.Background(), VerifierConfig{SelfIssuer: testIssuer, SelfKeys: f.keys.TokenKeys,
		Audiences: []string{ownHost, "authority"}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	f.a = &Authenticator{Verifier: f.v, Sessions: f.svc, SelfIssuer: testIssuer}
	f.admin, err = f.svc.CreateUser(context.Background(), NewUser{Username: "admin", Password: adminPW, Roles: []string{"admin"}, Realm: "console"},
		audit.SystemActor("test"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var ri = apiserver.RequestInfo{RemoteIP: "192.0.2.10", UserAgent: "test"}

// signIn runs both steps for username and returns the session. The
// clock moves to the next TOTP step first, so a code is never reused.
func (f *fixture) signIn(t testing.TB, username, password string) MFAResult {
	t.Helper()
	ctx := context.Background()
	lr, err := f.svc.Login(ctx, username, password, ri)
	if err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	if lr.EnrolSecret != "" {
		f.secrets[NormalizeUsername(username)] = lr.EnrolSecret
	}
	f.clk.Advance(TOTPPeriod)
	code, err := totp.GenerateCode(f.secrets[NormalizeUsername(username)], f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri)
	if err != nil {
		t.Fatalf("mfa %s: %v", username, err)
	}
	return res
}

func (f *fixture) identify(token string) (apiserver.Identity, error) {
	return f.a.IdentifyToken(context.Background(), token)
}

var adminActor = audit.Actor{Type: audit.ActorUser, ID: "admin-0", Realm: "console"}
