package tokens

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

const cispHost = "uspace-cisp.example.test"

// The accepted path: a token for a CISP-shaped host, with exactly table
// A's machine claims, verified by core in the role of the CISP, and a
// token_issued event.
func TestTokenIssuedWithTableAClaims(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "lab-01", []string{"cis.read", "dp.observe"}, []string{cispHost})
	resp, oerr := f.token(secretReq("lab-01", secret, "cis.read", "https://"+cispHost+"/v1"))
	if oerr != nil {
		t.Fatalf("refused: %v", oerr)
	}
	if resp.ExpiresIn != 3600 || resp.Scope != "cis.read" || resp.Audience != cispHost {
		t.Fatalf("response %+v", resp)
	}
	cl := claimsOf(t, resp.AccessToken)
	keys := make([]string, 0, len(cl))
	for k := range cl {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "aud,exp,iat,iss,jti,scope,sub" {
		t.Fatalf("claims %v", keys)
	}
	if h := headerOf(t, resp.AccessToken); h["alg"] != "RS256" || h["kid"] != f.parts.Keys.ActiveKID() {
		t.Fatalf("header %v", h)
	}
	got, err := f.verifier(t, cispHost).Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("the CISP's verifier refused: %v", err)
	}
	if got.Subject != "lab-01" || got.Audience != cispHost || !slices.Equal(got.Scopes, []string{"cis.read"}) ||
		got.ExpiresAt.Sub(got.IssuedAt) != time.Hour || got.JTI == "" || got.Issuer != testIssuer {
		t.Fatalf("claims %+v", got)
	}
	evs := f.st.eventsOf(audit.EventTokenIssued)
	if len(evs) != 1 || evs[0].Actor.ID != "lab-01" || evs[0].Actor.Type != audit.ActorClient {
		t.Fatalf("events %+v", evs)
	}
	if p := evs[0].Payload.(map[string]any); p["jti"] != got.JTI || p["aud"] != cispHost {
		t.Fatalf("event payload %v", p)
	}
}

// Verifier-side refusals of an issued token, each beside its acceptance
// (E-01): aud of another host, expired, wrong issuer.
func TestIssuedTokenRefusedByTheVerifierOutsideItsTerms(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost, "uspace-ansp.example.test"})
	resp, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr != nil {
		t.Fatal(oerr)
	}
	ctx := context.Background()
	if _, err := f.verifier(t, cispHost).Verify(ctx, resp.AccessToken); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
	var te *auth.TokenError
	if _, err := f.verifier(t, "uspace-ansp.example.test").Verify(ctx, resp.AccessToken); !errors.As(err, &te) || te.Counter != auth.CounterRejectedAudience {
		t.Fatalf("aud of another host: %v", err)
	}
	// Wrong issuer: a verifier that allows another iss only.
	set, _ := f.parts.Keys.JWKS(f.clock.Now())
	v, _ := auth.NewVerifier(ctx, auth.Config{Issuers: map[string]auth.IssuerConfig{"https://other.example.test": {Keys: set}}, Audience: cispHost, Now: f.clock.Now})
	if _, err := v.Verify(ctx, resp.AccessToken); !errors.As(err, &te) || te.Counter != auth.CounterRejectedIssuer {
		t.Fatalf("wrong issuer: %v", err)
	}
	f.clock.Advance(time.Hour + time.Minute)
	if _, err := f.verifier(t, cispHost).Verify(ctx, resp.AccessToken); !errors.As(err, &te) || te.Counter != auth.CounterRejectedExpired {
		t.Fatalf("expired: %v", err)
	}
}

// HS256 confusion: a token whose header says HS256, MACed with the
// issuer's public key as the secret, is refused by the verifier; the
// RS256 token of the same claims is accepted.
func TestHS256WithThePublicKeyIsRefused(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	resp, _ := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	parts := strings.Split(resp.AccessToken, ".")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"` + f.parts.Keys.ActiveKID() + `","typ":"JWT"}`))
	pubJWK := f.parts.Keys.Files()[0].PublicJWK
	forged := hdr + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(hmacSHA256(pubJWK, []byte(hdr+"."+parts[1])))
	v := f.verifier(t, cispHost)
	var te *auth.TokenError
	if _, err := v.Verify(context.Background(), forged); !errors.As(err, &te) || te.Counter != auth.CounterRejectedAlgorithm {
		t.Fatalf("HS256 forgery: %v", err)
	}
	if _, err := v.Verify(context.Background(), resp.AccessToken); err != nil {
		t.Fatalf("RS256 twin: %v", err)
	}
}

func TestClientAuthenticationRefusalsBesideAcceptance(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	cases := []struct {
		name   string
		req    TokenRequest
		code   string
		reason string
	}{
		{"wrong secret", secretReq("cisp-01", secret+"x", "cis.read", cispHost), ErrInvalidClient, "client_secret_wrong"},
		{"unknown client", secretReq("ansp-01", secret, "cis.read", cispHost), ErrInvalidClient, "client_unknown"},
		{"no secret", TokenRequest{GrantType: GrantClientCredentials, ClientID: "cisp-01", Scope: "cis.read", Audience: cispHost, HasAudience: true}, ErrInvalidClient, "client_credentials_missing"},
		{"grant type", func() TokenRequest {
			r := secretReq("cisp-01", secret, "cis.read", cispHost)
			r.GrantType = "password"
			return r
		}(), ErrUnsupportedGrantType, "grant_type_unsupported"},
		{"no grant type", func() TokenRequest {
			r := secretReq("cisp-01", secret, "cis.read", cispHost)
			r.GrantType = ""
			return r
		}(), ErrInvalidRequest, "grant_type_missing"},
		{"two methods", func() TokenRequest {
			r := secretReq("cisp-01", secret, "cis.read", cispHost)
			r.ClientAssertionType, r.ClientAssertion = AssertionType, "x.y.z"
			return r
		}(), ErrInvalidRequest, "two_client_credentials"},
	}
	for _, c := range cases {
		_, oerr := f.token(c.req)
		if oerr == nil || oerr.Code != c.code || oerr.Reason != c.reason {
			t.Errorf("%s: %+v", c.name, oerr)
		}
	}
	// Unknown client and wrong secret answer alike (no enumeration).
	_, a := f.token(cases[0].req)
	_, b := f.token(cases[1].req)
	if a.Status != b.Status || a.Code != b.Code || a.Description != b.Description {
		t.Fatalf("unknown client %+v differs from wrong secret %+v", b, a)
	}
	if _, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost)); oerr != nil {
		t.Fatalf("accepted twin: %v", oerr)
	}
	refused := f.st.eventsOf(audit.EventTokenRefused)
	if len(refused) < len(cases) {
		t.Fatalf("%d refusal events for %d refusals", len(refused), len(cases))
	}
	for _, e := range refused {
		if e.Payload.(map[string]any)["authenticated"] != false {
			t.Errorf("an unauthenticated refusal recorded as authenticated: %v", e.Payload)
		}
	}
}

// A suspended or revoked client is refused after it authenticated; the
// active one is accepted, and after reactivation again.
func TestSuspendedAndRevokedClientsAreRefused(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	req := secretReq("cisp-01", secret, "cis.read", cispHost)
	if _, oerr := f.token(req); oerr != nil {
		t.Fatal(oerr)
	}
	for _, st := range []string{StatusSuspended, StatusRevoked} {
		if _, err := f.parts.Registry.Update(context.Background(), "cisp-01", ClientPatch{Status: &st}, admin); err != nil {
			t.Fatal(err)
		}
		_, oerr := f.token(req)
		if oerr == nil || oerr.Code != ErrInvalidClient || oerr.Reason != "client_"+st {
			t.Fatalf("%s: %+v", st, oerr)
		}
	}
	active := StatusActive
	if _, err := f.parts.Registry.Update(context.Background(), "cisp-01", ClientPatch{Status: &active}, admin); err != nil {
		t.Fatal(err)
	}
	if _, oerr := f.token(req); oerr != nil {
		t.Fatalf("reactivated: %v", oerr)
	}
	last := f.st.eventsOf(audit.EventTokenRefused)
	if p := last[len(last)-1].Payload.(map[string]any); p["authenticated"] != true || p["reason"] != "client_revoked" {
		t.Fatalf("revoked refusal event %v", p)
	}
}

// Table B at the token endpoint: every grantable row is accepted for a
// client holding it; a scope outside the table, a reserved one, a USSP
// issuer's one, a lab-only one for another client, and one not on the
// client's list are refused.
func TestScopeChecksAtTheTokenEndpoint(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	var grantable []string
	for _, s := range Catalogue() {
		if CheckGrantable(s.Name, LabClientID) == nil {
			grantable = append(grantable, s.Name)
		}
	}
	secret := f.register(t, "lab-01", grantable, []string{cispHost})
	for _, s := range grantable {
		if _, oerr := f.token(secretReq("lab-01", secret, s, cispHost)); oerr != nil {
			t.Errorf("%s refused: %v", s, oerr)
		}
	}
	if _, oerr := f.token(secretReq("lab-01", secret, strings.Join(grantable, " "), cispHost)); oerr != nil {
		t.Errorf("all at once refused: %v", oerr)
	}
	refusals := map[string]string{
		"rid.observe":          ReasonScopeUnknown,
		"cis.publish:ats_data": ReasonScopeReserved,
		"ussp.intents":         ReasonScopeForeign,
		"cis.read bogus":       ReasonScopeUnknown,
		"":                     ReasonScopeMissing,
		"cis.read\x01":         "scope_malformed",
	}
	for scope, reason := range refusals {
		_, oerr := f.token(secretReq("lab-01", secret, scope, cispHost))
		if oerr == nil || oerr.Code != ErrInvalidScope || oerr.Reason != reason {
			t.Errorf("%q: %+v", scope, oerr)
		}
	}
	other := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	for scope, reason := range map[string]string{"dp.observe": ReasonScopeLabOnly, "registry.validate": ReasonScopeNotAllowed} {
		_, oerr := f.token(secretReq("cisp-01", other, scope, cispHost))
		if oerr == nil || oerr.Reason != reason {
			t.Errorf("cisp-01 %s: %+v", scope, oerr)
		}
	}
}

// M18: national scopes need the audience on the client's list; standard
// scopes accept any host. One audience per token.
func TestAudienceRules(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "ussp-GEO1-01", []string{"registry.validate", "rid.service_provider", "utm.strategic_coordination"}, []string{"authority.example.test"})
	ok := []TokenRequest{
		secretReq("ussp-GEO1-01", secret, "registry.validate", "authority.example.test"),
		secretReq("ussp-GEO1-01", secret, "rid.service_provider", "unknown-peer.example.test"),
		secretReq("ussp-GEO1-01", secret, "utm.strategic_coordination", "https://dss.example.test:8443/dss/v1"),
		{GrantType: GrantClientCredentials, ClientID: "ussp-GEO1-01", ClientSecret: secret, HasSecret: true, Scope: "rid.service_provider",
			Resources: []string{"https://peer.example.test/uss"}},
		{GrantType: GrantClientCredentials, ClientID: "ussp-GEO1-01", ClientSecret: secret, HasSecret: true, Scope: "rid.service_provider",
			Resources: []string{"https://peer.example.test/a"}, Audience: "peer.example.test", HasAudience: true},
	}
	for i, r := range ok {
		if resp, oerr := f.token(r); oerr != nil {
			t.Errorf("accepted case %d: %v", i, oerr)
		} else if i == 2 && resp.Audience != "dss.example.test" {
			t.Errorf("a base URL reduces to its host: %q", resp.Audience)
		}
	}
	bad := []struct {
		req    TokenRequest
		reason string
	}{
		{secretReq("ussp-GEO1-01", secret, "registry.validate", "uspace-cisp.example.test"), ReasonAudienceNotAllowed},
		{secretReq("ussp-GEO1-01", secret, "registry.validate rid.service_provider", "peer.example.test"), ReasonAudienceNotAllowed},
		{secretReq("ussp-GEO1-01", secret, "rid.service_provider", ""), ReasonAudienceMissing},
		{secretReq("ussp-GEO1-01", secret, "rid.service_provider", "peer.example.test:443"), ReasonAudienceInvalid},
		{secretReq("ussp-GEO1-01", secret, "rid.service_provider", "10.0.0.1"), ReasonAudienceInvalid},
		{TokenRequest{GrantType: GrantClientCredentials, ClientID: "ussp-GEO1-01", ClientSecret: secret, HasSecret: true, Scope: "rid.service_provider",
			Resources: []string{"https://a.example.test", "https://b.example.test"}}, ReasonAudienceMultiple},
	}
	for i, b := range bad {
		_, oerr := f.token(b.req)
		if oerr == nil || oerr.Code != ErrInvalidTarget || oerr.Reason != b.reason {
			t.Errorf("refused case %d: %+v", i, oerr)
		}
	}
}

// No audit row, no token: when the token_issued event cannot be written
// the token is withheld; the same request succeeds when the log is back.
func TestTokenWithheldWhenTheIssuanceCannotBeAudited(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	f.st.failRecord = true
	resp, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr == nil || oerr.Reason != "audit_failed" || resp.AccessToken != "" {
		t.Fatalf("got %+v %+v", resp, oerr)
	}
	if f.parts.Counters.Get(CounterRefusalNotSaved) != 0 {
		t.Fatalf("counters %v", f.parts.Counters.Snapshot())
	}
	f.st.failRecord = false
	if _, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost)); oerr != nil {
		t.Fatalf("accepted twin: %v", oerr)
	}
}

// A refusal whose event cannot be written is still a refusal, counted.
func TestRefusalStandsWhenItsEventCannotBeWritten(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.st.failRecord = true
	_, oerr := f.token(secretReq("cisp-01", "nope", "cis.read", cispHost))
	if oerr == nil || f.parts.Counters.Get(CounterRefusalNotSaved) != 1 {
		t.Fatalf("got %+v %v", oerr, f.parts.Counters.Snapshot())
	}
}

func TestClientLookupOutageIsNotAnUnknownClient(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	f.st.failReads = true
	_, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr == nil || oerr.Status != http.StatusInternalServerError || oerr.Reason != "store_failed" {
		t.Fatalf("got %+v", oerr)
	}
}

// Rate limit per authenticated client (E-10 for its map in
// TestTokenRateLimiterMapIsBounded): the burst is served, the next is
// 429 with Retry-After, another client is unaffected.
func TestTokenRateLimitPerClient(t *testing.T) {
	f := newFixture(t, fixtureOpts{burst: 2})
	a := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	b := f.register(t, "ansp-01", []string{"cis.read"}, []string{cispHost})
	for range 2 {
		if _, oerr := f.token(secretReq("cisp-01", a, "cis.read", cispHost)); oerr != nil {
			t.Fatal(oerr)
		}
	}
	_, oerr := f.token(secretReq("cisp-01", a, "cis.read", cispHost))
	if oerr == nil || oerr.Status != http.StatusTooManyRequests || oerr.RetryAfter <= 0 {
		t.Fatalf("over budget: %+v", oerr)
	}
	if _, oerr := f.token(secretReq("ansp-01", b, "cis.read", cispHost)); oerr != nil {
		t.Fatalf("another client: %v", oerr)
	}
}

func TestTokenRateLimiterMapIsBounded(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	l := f.parts.Service.Limiter
	for i := range 250 {
		l.Allow("client-" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	if l.Len() > 100 {
		t.Fatalf("limiter holds %d clients, bound 100", l.Len())
	}
}

// Concurrency under -race: parallel token requests of several clients.
func TestParallelTokenRequests(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	secrets := map[string]string{}
	for _, id := range []string{"cisp-01", "ansp-01", "lab-01"} {
		secrets[id] = f.register(t, id, []string{"cis.read"}, []string{cispHost})
	}
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := range 60 {
		id := []string{"cisp-01", "ansp-01", "lab-01"}[i%3]
		wg.Go(func() {
			if _, oerr := f.token(secretReq(id, secrets[id], "cis.read", cispHost)); oerr != nil {
				errs <- oerr
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := len(f.st.eventsOf(audit.EventTokenIssued)); n != 60 {
		t.Fatalf("%d issuance events", n)
	}
}

func TestTTLIsBoundedByTableA(t *testing.T) {
	s := &Service{Config: ServiceConfig{TTL: 2 * time.Hour}}
	if s.ttl() != time.Hour {
		t.Fatalf("ttl %s", s.ttl())
	}
	s.Config.TTL = 10 * time.Minute
	if s.ttl() != 10*time.Minute {
		t.Fatalf("ttl %s", s.ttl())
	}
}

func TestClipBoundsStoredValues(t *testing.T) {
	long := strings.Repeat("é", 100)
	if c := clip(long); len(c) > 128 || !strings.HasPrefix(long, c) {
		t.Fatalf("clip %q", c)
	}
	if clip("a\xffb") != "a?b" {
		t.Fatal("invalid UTF-8 kept")
	}
}

// Fuzz the grant's untrusted fields: no panic, and nothing is ever
// issued without the right secret.
func FuzzTokenRequest(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Add("client_credentials", "cisp-01", "wrong", "cis.read", cispHost, "", "")
	f.Add("client_credentials", "cisp-01", "", "cis.read rid.observe", "https://x", AssertionType, "a.b.c")
	f.Add("", "", "", "", "", "", "")
	f.Fuzz(func(t *testing.T, grant, id, secret, scope, aud, atype, assertion string) {
		req := TokenRequest{GrantType: grant, ClientID: id, ClientSecret: secret, HasSecret: secret != "", Scope: scope,
			Audience: aud, HasAudience: aud != "", ClientAssertionType: atype, ClientAssertion: assertion}
		resp, oerr := fx.parts.Service.Token(context.Background(), req)
		if oerr == nil && (secret != fx.secret || id != "cisp-01") {
			t.Fatalf("issued %+v for %+v", resp, req)
		}
	})
}

type fuzzFixture struct {
	parts  *Parts
	secret string
}

func newFuzzFixture(f *testing.F) fuzzFixture {
	fx := newFixture(f, fixtureOpts{})
	return fuzzFixture{parts: fx.parts, secret: fx.register(f, "cisp-01", []string{"cis.read"}, []string{cispHost})}
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
