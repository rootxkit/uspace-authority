package tokens

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const testIssuer = "https://authority.example.test"

// clock is a settable test clock.
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

var cheapParams = passhash.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func cheapHasher(t testing.TB) *passhash.Hasher {
	t.Helper()
	h, err := passhash.New(cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type fixture struct {
	st    *memStore
	clock *clock
	parts *Parts
	dir   string
}

type fixtureOpts struct {
	keys        int  // token key files (default 1)
	publication bool // a publication key (shared key 9)
	twoPerson   bool
	burst       int
	replayMax   int
}

func newFixture(t testing.TB, o fixtureOpts) *fixture {
	t.Helper()
	if o.keys == 0 {
		o.keys = 1
	}
	if o.burst == 0 {
		o.burst = 1000
	}
	if o.replayMax == 0 {
		o.replayMax = 1000
	}
	dir := t.TempDir()
	files := make([]string, 0, o.keys)
	for i := range o.keys {
		files = append(files, tokentest.WriteKey(t, dir, i))
	}
	s := Setup{
		Issuer: testIssuer, SigningKeyFiles: files, TTL: time.Hour, RetireGrace: 24 * time.Hour,
		TwoPerson: o.twoPerson, ConfirmWindow: 10 * time.Minute, RatePerMin: 60, RateBurst: o.burst,
		RateMaxClients: 100, ReplayMax: o.replayMax, Hasher: cheapHasher(t),
	}
	if o.publication {
		s.PublicationKeyFile = tokentest.WriteKey(t, dir, 9)
	}
	f := &fixture{st: newMemStore(), clock: &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}, dir: dir}
	s.Store, s.Now = f.st, f.clock.Now
	parts, err := Assemble(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	f.parts = parts
	return f
}

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: "console"}

// register creates a client_secret_post client and returns its secret.
func (f *fixture) register(t testing.TB, id string, scopes, audiences []string) string {
	t.Helper()
	_, secret, err := f.parts.Registry.Create(context.Background(), ClientInput{
		ID: id, Scopes: scopes, Audiences: audiences, AuthMethod: MethodSecretPost,
	}, admin)
	if err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
	return secret
}

func (f *fixture) token(req TokenRequest) (TokenResponse, *OAuthError) {
	return f.parts.Service.Token(context.Background(), req)
}

func secretReq(id, secret, scope, audience string) TokenRequest {
	return TokenRequest{
		GrantType: GrantClientCredentials, ClientID: id, ClientSecret: secret, HasSecret: true,
		Scope: scope, Audience: audience, HasAudience: audience != "",
	}
}

// verifier is a second party's core verifier of this issuer's tokens,
// built from the published JWKS at the fixture's clock, accepting
// audiences.
func (f *fixture) verifier(t *testing.T, audiences ...string) *auth.Verifier {
	t.Helper()
	set, err := f.parts.Keys.JWKS(f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through JSON, as a peer would receive it.
	raw, _ := json.Marshal(set)
	pub, err := jwk.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers:             map[string]auth.IssuerConfig{testIssuer: {Keys: pub}},
		Audiences:           audiences,
		StrictSessionClaims: true,
		Now:                 f.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// claimsOf decodes a token payload (no verification) for shape checks.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := b64(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func headerOf(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := b64(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func tokentestKey(t testing.TB, i int) *rsa.PrivateKey { return tokentest.Key(t, i) }
