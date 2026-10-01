package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// E-01 pairs of Identify: no header, two headers, another scheme, an
// unverifiable token; a session and a machine token are accepted.
func TestIdentifyBearer(t *testing.T) {
	f := newFixture(t, fxOpts{})
	res := f.signIn(t, "admin", adminPW)
	id, err := f.a.Identify(bearer(res.Token))
	if err != nil || !id.Session || id.ActorType != "user" {
		t.Fatalf("session: %+v %v", id, err)
	}
	machine, err := f.keys.Issue("cisp-01", ownHost, []string{"registry.validate"}, time.Hour, f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, err = f.a.Identify(bearer(machine.Token))
	if err != nil || id.Session || id.ActorType != "client" || id.Subject != "cisp-01" || id.Scopes[0] != "registry.validate" {
		t.Fatalf("machine: %+v %v", id, err)
	}
	two := bearer(res.Token)
	two.Header.Add("Authorization", "Bearer "+res.Token)
	basic := bearer("")
	basic.Header.Set("Authorization", "Basic YTpi")
	empty := bearer("")
	empty.Header.Set("Authorization", "Bearer   ")
	for name, r := range map[string]*http.Request{
		"no header": bearer(""), "two headers": two, "basic": basic, "empty": empty, "garbage": bearer("a.b.c"),
	} {
		if _, err := f.a.Identify(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The refusal never echoes the token.
	if _, err := f.a.Identify(bearer(res.Token + "x")); err == nil || strings.Contains(err.Error(), res.Token) {
		t.Fatalf("tampered: %v", err)
	}
}

// A token claiming scope "session" is a session only when it is this
// issuer's, carries no other scope, names a known realm and has a live
// row; each beside the accepted session above.
func TestSessionClaimsAreChecked(t *testing.T) {
	f := newFixture(t, fxOpts{})
	res := f.signIn(t, "admin", adminPW)
	now := f.clk.Now()
	// A machine token from this issuer that claims session plus another
	// scope.
	mixed, _ := f.keys.Issue(f.admin.ID, ownHost, []string{"session", "cis.read"}, time.Hour, now)
	if _, err := f.identify(mixed.Token); err == nil || !strings.Contains(err.Error(), "alone") {
		t.Fatalf("session plus a scope: %v", err)
	}
	// A session-shaped token of another realm.
	portal, _ := f.keys.SignSession(tokens.SessionClaims{Subject: f.admin.ID, Audience: ownHost, Realm: "portal", JTI: res.Session.JTI,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, err := f.identify(portal); err == nil || !strings.Contains(err.Error(), "realm") {
		t.Fatalf("realm portal: %v", err)
	}
	// A session-shaped token without a row.
	ghost, _ := f.keys.SignSession(tokens.SessionClaims{Subject: f.admin.ID, Audience: ownHost, Realm: "console", JTI: "0123456789abcdef0123456789abcdef",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, err := f.identify(ghost); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("no row: %v", err)
	}
	// A session of another issuer (a peer signing scope "session").
	peerKeys := testKeys(t, now, 1)
	peerSet, _ := peerKeys.TokenKeys(now)
	pv, err := NewVerifier(context.Background(), VerifierConfig{SelfIssuer: testIssuer, SelfKeys: f.keys.TokenKeys, Audiences: []string{ownHost},
		Peers: map[string]Peer{"https://peer.example.test": {Keys: peerSet}}, Now: f.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	a := &Authenticator{Verifier: pv, Sessions: f.svc, SelfIssuer: testIssuer}
	other, err := tokens.NewKeys("https://peer.example.test", time.Hour, []tokens.KeyFile{mustKeyFile(t, 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	from := now.Add(-time.Minute)
	_ = other.Apply([]tokens.KeyRow{{KID: mustKeyFile(t, 1).KID, Purpose: tokens.PurposeToken, PublicJWK: mustKeyFile(t, 1).PublicJWK, ActiveFrom: &from}})
	foreign, _ := other.SignSession(tokens.SessionClaims{Subject: f.admin.ID, Audience: ownHost, Realm: "console", JTI: res.Session.JTI,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, err := a.IdentifyToken(context.Background(), foreign); err == nil || !strings.Contains(err.Error(), "another issuer") {
		t.Fatalf("foreign session: %v", err)
	}
	// The peer's machine token is accepted through the same wiring.
	pm, _ := other.Issue("cisp-01", ownHost, []string{"cis.read"}, time.Hour, now)
	if id, err := a.IdentifyToken(context.Background(), pm.Token); err != nil || id.Issuer != "https://peer.example.test" {
		t.Fatalf("peer machine token: %+v %v", id, err)
	}
	if _, err := f.identify(res.Token); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
}

func mustKeyFile(t *testing.T, i int) tokens.KeyFile {
	t.Helper()
	kf, err := tokens.NewKeyFile("k.pem", tokentest.Key(t, i))
	if err != nil {
		t.Fatal(err)
	}
	return kf
}

// M22: the WebSocket upgrade carries the cookie and an allowed Origin;
// a machine token in the cookie (scope other than session) is refused.
func TestFromCookie(t *testing.T) {
	f := newFixture(t, fxOpts{})
	res := f.signIn(t, "admin", adminPW)
	origins := []string{"https://authority.example.test"}
	req := func(origin, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/picture/ws", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: CookieSession, Value: cookie})
		}
		return r
	}
	if id, err := f.a.FromCookie(req(origins[0], res.Token), origins); err != nil || !id.Session {
		t.Fatalf("accepted twin: %+v %v", id, err)
	}
	machine, _ := f.keys.Issue("cisp-01", ownHost, []string{"cis.read"}, time.Hour, f.clk.Now())
	for name, r := range map[string]*http.Request{
		"no origin":      req("", res.Token),
		"other origin":   req("https://evil.example.test", res.Token),
		"no cookie":      req(origins[0], ""),
		"machine cookie": req(origins[0], machine.Token),
		"bad cookie":     req(origins[0], "x.y.z"),
	} {
		if _, err := f.a.FromCookie(r, origins); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCheckCSRF(t *testing.T) {
	r := func(method, cookie, header string) *http.Request {
		q := httptest.NewRequest(method, "/v1/x", nil)
		if cookie != "" {
			q.AddCookie(&http.Cookie{Name: CookieCSRF, Value: cookie})
		}
		if header != "" {
			q.Header.Set(HeaderCSRF, header)
		}
		return q
	}
	if err := CheckCSRF(r(http.MethodPost, "abc", "abc")); err != nil {
		t.Fatalf("matching: %v", err)
	}
	if err := CheckCSRF(r(http.MethodGet, "", "")); err != nil {
		t.Fatalf("safe method: %v", err)
	}
	for name, q := range map[string]*http.Request{
		"mismatch": r(http.MethodPost, "abc", "abd"), "no header": r(http.MethodDelete, "abc", ""), "no cookie": r(http.MethodPut, "", "abc"),
	} {
		if CheckCSRF(q) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRequirePurpose(t *testing.T) {
	mw := RequirePurpose(map[string]bool{"ReadPII": true})
	run := func(op, query string) (int, string) {
		var seen string
		h := mw(func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			seen = PurposeFrom(ctx)
			return nil, nil
		}, op)
		rec := httptest.NewRecorder()
		_, _ = h(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/v1/x"+query, nil), nil)
		return rec.Code, seen
	}
	if code, seen := run("ReadPII", "?purpose=incident+42"); code != 200 || seen != "incident 42" {
		t.Fatalf("accepted twin: %d %q", code, seen)
	}
	if code, _ := run("Other", ""); code != 200 {
		t.Fatalf("an operation without the rule: %d", code)
	}
	for _, q := range []string{"", "?purpose=", "?purpose=%20%20", "?purpose=a%00b", "?purpose=" + strings.Repeat("x", MaxPurposeLen+1)} {
		if code, _ := run("ReadPII", q); code != 400 {
			t.Errorf("%q: %d", q, code)
		}
	}
}

// The verifier wiring: a peer whose JWKS cannot be fetched at start is
// pending and its tokens refused as rejected_issuer_unavailable; Run
// fetches it later and its tokens verify (B-08, E-14).
func TestPeerIssuerIsRetried(t *testing.T) {
	now := time.Now()
	peer := testKeys(t, now, 2)
	set, _ := peer.TokenKeys(now)
	raw, _ := json.Marshal(set)
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	self := testKeys(t, now, 0)
	v, err := NewVerifier(context.Background(), VerifierConfig{
		SelfIssuer: testIssuer, SelfKeys: self.TokenKeys, Audiences: []string{ownHost},
		Peers: map[string]Peer{"https://cisp.example.test": {JWKSURL: srv.URL}}, RetryEvery: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := v.Pending(); len(p) != 1 || v.StatusAttrs()[0].Value.String() == "[]" {
		t.Fatalf("pending %v", p)
	}
	other, _ := tokens.NewKeys("https://cisp.example.test", time.Hour, []tokens.KeyFile{mustKeyFile(t, 2)}, nil)
	from := now.Add(-time.Minute)
	_ = other.Apply([]tokens.KeyRow{{KID: mustKeyFile(t, 2).KID, Purpose: tokens.PurposeToken, ActiveFrom: &from}})
	tok, _ := other.Issue("cisp-01", ownHost, []string{"cis.read"}, time.Hour, now)
	var te *auth.TokenError
	if _, err := v.Verify(context.Background(), tok.Token); !errors.As(err, &te) || te.Counter != CounterIssuerUnavailable {
		t.Fatalf("pending peer: %v", err)
	}
	up.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v.Run(ctx)
	if len(v.Pending()) != 0 {
		t.Fatal("the peer is still pending")
	}
	if cl, err := v.Verify(context.Background(), tok.Token); err != nil || cl.Issuer != "https://cisp.example.test" {
		t.Fatalf("ready peer: %v", err)
	}
	if v.Counters().Get(CounterPeerFetchFailed) == 0 || v.Counters().Get(auth.CounterAccepted) != 1 {
		t.Fatalf("counters %v", v.Counters().Snapshot())
	}
	// An unknown issuer reaches this issuer's verifier and is refused there.
	stranger, _ := tokens.NewKeys("https://stranger.example.test", time.Hour, []tokens.KeyFile{mustKeyFile(t, 2)}, nil)
	_ = stranger.Apply([]tokens.KeyRow{{KID: mustKeyFile(t, 2).KID, Purpose: tokens.PurposeToken, ActiveFrom: &from}})
	st, _ := stranger.Issue("x", ownHost, nil, time.Hour, now)
	if _, err := v.Verify(context.Background(), st.Token); !errors.As(err, &te) || te.Counter != auth.CounterRejectedIssuer {
		t.Fatalf("stranger: %v", err)
	}
}

func TestVerifierConfigRefusals(t *testing.T) {
	now := time.Now()
	k := testKeys(t, now, 0)
	empty := func(time.Time) (jwk.Set, error) { return jwk.NewSet(), nil }
	for name, c := range map[string]VerifierConfig{
		"no issuer":    {SelfKeys: k.TokenKeys, Audiences: []string{ownHost}},
		"no audiences": {SelfIssuer: testIssuer, SelfKeys: k.TokenKeys},
		"self as peer": {SelfIssuer: testIssuer, SelfKeys: k.TokenKeys, Audiences: []string{ownHost}, Peers: map[string]Peer{testIssuer: {}}},
		"no keys":      {SelfIssuer: testIssuer, SelfKeys: empty, Audiences: []string{ownHost}},
	} {
		if _, err := NewVerifier(context.Background(), c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A rotation reaches the verifier through Rebuild: a token of the new
// key is refused before and accepted after.
func TestRebuildFollowsARotation(t *testing.T) {
	now := time.Now()
	a, b := mustKeyFile(t, 0), mustKeyFile(t, 1)
	k, _ := tokens.NewKeys(testIssuer, 24*time.Hour, []tokens.KeyFile{a, b}, nil)
	from := now.Add(-time.Hour)
	_ = k.Apply([]tokens.KeyRow{{KID: a.KID, Purpose: tokens.PurposeToken, PublicJWK: a.PublicJWK, ActiveFrom: &from},
		{KID: b.KID, Purpose: tokens.PurposeToken, PublicJWK: b.PublicJWK}})
	v, err := NewVerifier(context.Background(), VerifierConfig{SelfIssuer: testIssuer, SelfKeys: k.TokenKeys, Audiences: []string{ownHost}})
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Apply([]tokens.KeyRow{{KID: a.KID, Purpose: tokens.PurposeToken, PublicJWK: a.PublicJWK, ActiveFrom: &from, RetiredAt: &now},
		{KID: b.KID, Purpose: tokens.PurposeToken, PublicJWK: b.PublicJWK, ActiveFrom: &now}})
	tok, _ := k.Issue("x", ownHost, nil, time.Hour, now)
	if _, err := v.Verify(context.Background(), tok.Token); err == nil {
		t.Fatal("the new key verified before the rebuild")
	}
	if err := v.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok.Token); err != nil {
		t.Fatalf("after the rebuild: %v", err)
	}
	broken := &Verifier{cfg: VerifierConfig{SelfIssuer: testIssuer, SelfKeys: func(time.Time) (jwk.Set, error) { return nil, errors.New("x") }}}
	if broken.Rebuild() == nil || broken.counters.Get(CounterSelfRebuildFailed) != 1 {
		t.Fatal("a failed rebuild was not reported")
	}
}

func FuzzIdentify(f *testing.F) {
	fx := newFixture(f, fxOpts{})
	f.Add("Bearer a.b.c")
	f.Add("bearer eyJhbGciOiJIUzI1NiJ9.e30.x")
	f.Add("Basic Zm9v")
	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header["Authorization"] = []string{header}
		if id, err := fx.a.Identify(r); err == nil {
			t.Fatalf("identified %+v from %q", id, header)
		}
	})
}

func FuzzParsePurpose(f *testing.F) {
	f.Add("incident 42")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, p string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		q := r.URL.Query()
		q.Set("purpose", p)
		r.URL.RawQuery = q.Encode()
		got, err := ParsePurpose(r)
		if err == nil && (got == "" || len([]rune(got)) > MaxPurposeLen) {
			t.Fatalf("%q -> %q", p, got)
		}
	})
}

var _ = apiserver.Identity{}
