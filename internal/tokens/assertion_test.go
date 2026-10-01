package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const clientKID = "ussp-key-1"

// clientJWKS is the public JWKS of shared test key i under kid.
func clientJWKS(t testing.TB, i int, kid string) json.RawMessage {
	t.Helper()
	ring, err := auth.NewKeyRing(auth.SigningKey{KID: kid, Key: tokentest.Key(t, i)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(ring.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertion signs a client assertion with core's Issuer, as a client of
// another system would: iss = clientID, sub, aud, exp = now + ttl.
func assertion(t *testing.T, keyIdx int, kid, iss, sub, aud string, ttl time.Duration, now time.Time) string {
	t.Helper()
	is, err := auth.NewIssuer(iss, tokentest.Key(t, keyIdx), kid)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := is.Issue(sub, aud, nil, ttl, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func assertionReq(a, scope, audience string) TokenRequest {
	return TokenRequest{GrantType: GrantClientCredentials, ClientAssertionType: AssertionType, ClientAssertion: a,
		Scope: scope, Audience: audience, HasAudience: true}
}

// E-01 for private_key_jwt: the valid assertion is accepted once; a
// replay, the wrong key, another audience, a sub that is not the client,
// a lifetime over 5 min, a wrong assertion type, a client_id that
// differs, an unknown client and a secret client are refused.
func TestPrivateKeyJWTRefusalsBesideAcceptance(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()
	if _, _, err := f.parts.Registry.Create(ctx, NewClient{ID: "ussp-GEO1-01", Scopes: []string{"rid.service_provider"},
		AuthMethod: MethodPrivateKeyJWT, JWKS: clientJWKS(t, 3, clientKID)}, admin); err != nil {
		t.Fatal(err)
	}
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	_ = secret
	now := f.clock.Now()
	endpoint := testIssuer + "/oauth/token"
	good := assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", endpoint, time.Minute, now)
	resp, oerr := f.token(assertionReq(good, "rid.service_provider", "peer.example.test"))
	if oerr != nil || resp.AccessToken == "" {
		t.Fatalf("valid assertion: %v", oerr)
	}
	if _, oerr := f.token(assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", testIssuer, time.Minute, now),
		"rid.service_provider", "peer.example.test")); oerr != nil {
		t.Fatalf("aud = issuer: %v", oerr)
	}
	cases := map[string]struct {
		req    TokenRequest
		reason string
	}{
		"replayed":      {assertionReq(good, "rid.service_provider", "peer.example.test"), "client_assertion_replayed"},
		"wrong key":     {assertionReq(assertion(t, 4, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", endpoint, time.Minute, now), "rid.service_provider", "p.example.test"), "client_assertion_rejected_signature"},
		"unknown kid":   {assertionReq(assertion(t, 3, "other", "ussp-GEO1-01", "ussp-GEO1-01", endpoint, time.Minute, now), "rid.service_provider", "p.example.test"), "client_assertion_rejected_kid"},
		"aud elsewhere": {assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", "https://elsewhere.example.test/oauth/token", time.Minute, now), "rid.service_provider", "p.example.test"), "client_assertion_rejected_audience"},
		"sub differs":   {assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "cisp-01", endpoint, time.Minute, now), "rid.service_provider", "p.example.test"), "client_assertion_invalid"},
		"too long":      {assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", endpoint, 10*time.Minute, now), "rid.service_provider", "p.example.test"), "client_assertion_invalid"},
		"unknown":       {assertionReq(assertion(t, 3, clientKID, "ussp-ZZZ-01", "ussp-ZZZ-01", endpoint, time.Minute, now), "rid.service_provider", "p.example.test"), "client_unknown"},
		"secret client": {assertionReq(assertion(t, 3, clientKID, "cisp-01", "cisp-01", endpoint, time.Minute, now), "cis.read", cispHost), "client_auth_method_mismatch"},
		"unreadable":    {assertionReq("not.a.jwt", "rid.service_provider", "p.example.test"), "client_assertion_invalid"},
	}
	for name, c := range cases {
		_, oerr := f.token(c.req)
		if oerr == nil || oerr.Reason != c.reason {
			t.Errorf("%s: %+v", name, oerr)
		}
	}
	wrongType := assertionReq(good, "rid.service_provider", "p.example.test")
	wrongType.ClientAssertionType = "urn:other"
	if _, oerr := f.token(wrongType); oerr == nil || oerr.Reason != "client_assertion_type_wrong" {
		t.Errorf("assertion type: %+v", oerr)
	}
	mismatch := assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", endpoint, time.Minute, now), "rid.service_provider", "p.example.test")
	mismatch.ClientID = "cisp-01"
	if _, oerr := f.token(mismatch); oerr == nil || oerr.Reason != "client_id_mismatch" {
		t.Errorf("client_id mismatch: %+v", oerr)
	}
	// A secret presented for a private_key_jwt client is refused.
	if _, oerr := f.token(secretReq("ussp-GEO1-01", "x", "rid.service_provider", "p.example.test")); oerr == nil || oerr.Reason != "client_auth_method_mismatch" {
		t.Errorf("secret for a key client: %+v", oerr)
	}
	if n := len(f.st.eventsOf(audit.EventTokenRefused)); n < len(cases)+3 {
		t.Fatalf("%d refusal events", n)
	}
}

// E-10: the replay memory refuses rather than forgets when full of live
// ids, and drops expired ids to make room.
func TestReplayMemoryIsBounded(t *testing.T) {
	m := NewReplayMemory(3, nil)
	now := time.Now()
	exp := now.Add(time.Minute)
	for _, j := range []string{"a", "b", "c"} {
		if err := m.Use("c1", j, exp, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Use("c1", "a", exp, now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}
	if err := m.Use("c2", "a", exp, now); !errors.Is(err, ErrReplayFull) {
		t.Fatalf("over the bound: %v", err)
	}
	if m.Len() != 3 || m.counters.Get(CounterReplayFull) != 1 || m.counters.Get(CounterReplayed) != 1 {
		t.Fatalf("len %d counters %v", m.Len(), m.counters.Snapshot())
	}
	later := exp.Add(auth.DefaultMaxSkew + time.Second)
	if err := m.Use("c2", "a", later.Add(time.Minute), later); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("expired ids kept: %d", m.Len())
	}
}

// A full replay memory refuses the grant as temporarily unavailable.
func TestFullReplayMemoryRefusesTheGrant(t *testing.T) {
	f := newFixture(t, fixtureOpts{replayMax: 1})
	ctx := context.Background()
	if _, _, err := f.parts.Registry.Create(ctx, NewClient{ID: "ussp-GEO1-01", Scopes: []string{"rid.service_provider"},
		AuthMethod: MethodPrivateKeyJWT, JWKS: clientJWKS(t, 3, clientKID)}, admin); err != nil {
		t.Fatal(err)
	}
	now := f.clock.Now()
	ep := testIssuer + "/oauth/token"
	if _, oerr := f.token(assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", ep, time.Minute, now), "rid.service_provider", "p.example.test")); oerr != nil {
		t.Fatal(oerr)
	}
	_, oerr := f.token(assertionReq(assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", ep, time.Minute, now), "rid.service_provider", "p.example.test"))
	if oerr == nil || oerr.Code != ErrTemporarily || oerr.Reason != "assertion_replay_memory_full" {
		t.Fatalf("%+v", oerr)
	}
}

func TestValidateClientJWKS(t *testing.T) {
	if _, err := ValidateClientJWKS(clientJWKS(t, 3, "k1")); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
	privRaw := func() json.RawMessage {
		// The private JWK of a key: what a careless client might post.
		set := `{"keys":[` + string(privJWK(t, 3, "k1")) + `]}`
		return json.RawMessage(set)
	}()
	twoSame := json.RawMessage(`{"keys":[` + oneKey(t, 3, "k1") + `,` + oneKey(t, 4, "k1") + `]}`)
	noKID := json.RawMessage(strings.Replace(string(clientJWKS(t, 3, "k1")), `"kid":"k1",`, "", 1))
	bad := map[string]json.RawMessage{
		"empty":     nil,
		"not json":  json.RawMessage(`{`),
		"no keys":   json.RawMessage(`{"keys":[]}`),
		"private":   privRaw,
		"duplicate": twoSame,
		"no kid":    noKID,
		"symmetric": json.RawMessage(`{"keys":[{"kty":"oct","kid":"s","k":"c2VjcmV0"}]}`),
		"wrong alg": json.RawMessage(strings.Replace(string(clientJWKS(t, 3, "k1")), `"RS256"`, `"RS512"`, 1)),
		"wrong use": json.RawMessage(strings.Replace(string(clientJWKS(t, 3, "k1")), `"use":"sig"`, `"use":"enc"`, 1)),
		"short":     json.RawMessage(`{"keys":[{"kty":"RSA","kid":"s","n":"AQAB","e":"AQAB"}]}`),
		"too large": json.RawMessage(`{"keys":[` + strings.Repeat(" ", MaxClientJWKSBytes) + `]}`),
		"too many":  json.RawMessage(`{"keys":[` + strings.Repeat(oneKey(t, 3, "x")+",", MaxClientJWKSKeys) + oneKey(t, 3, "y") + `]}`),
	}
	for name, raw := range bad {
		if _, err := ValidateClientJWKS(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func oneKey(t *testing.T, i int, kid string) string {
	raw := string(clientJWKS(t, i, kid))
	return strings.TrimSuffix(strings.TrimPrefix(raw, `{"keys":[`), `]}`)
}

func privJWK(t *testing.T, i int, kid string) []byte {
	t.Helper()
	kf, err := NewKeyFile("x", tokentest.Key(t, i))
	if err != nil {
		t.Fatal(err)
	}
	k, err := importPrivate(kf, kid)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func FuzzUnverifiedIssuer(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjaXNwLTAxIn0.x")
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, a string) {
		iss := UnverifiedIssuer(a)
		if iss != "" && len(a) > auth.DefaultMaxTokenBytes {
			t.Fatalf("read an iss from an oversized assertion")
		}
	})
}

func FuzzValidateClientJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"oct","k":"AA"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		set, err := ValidateClientJWKS(raw)
		if err != nil {
			var fe *core.FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error %T is not a field error", err)
			}
			return
		}
		if set.Len() == 0 || set.Len() > MaxClientJWKSKeys {
			t.Fatalf("%d keys accepted", set.Len())
		}
	})
}

func importPrivate(kf KeyFile, kid string) ([]byte, error) {
	k, err := jwk.Import(kf.Key)
	if err != nil {
		return nil, err
	}
	if err := k.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	return json.Marshal(k)
}
