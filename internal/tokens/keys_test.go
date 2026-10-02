package tokens

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// E-01: PKCS #8 and PKCS #1 RSA keys load with the same kid; every other
// shape is refused naming the variable.
func TestLoadKeyFileAcceptsRSAPEMAndRefusesTheRest(t *testing.T) {
	key := tokentest.Key(t, 0)
	p8 := writeFile(t, "k8.pem", tokentest.PEM(t, key))
	p1 := writeFile(t, "k1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	a, err := LoadKeyFile("SIGNING_KEY_FILES", p8)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadKeyFile("SIGNING_KEY_FILES", p1)
	if err != nil {
		t.Fatal(err)
	}
	if a.KID != b.KID || len(a.KID) != 43 || a.Ref != p8 {
		t.Fatalf("kids %q %q", a.KID, b.KID)
	}
	var pub map[string]any
	if err := json.Unmarshal(a.PublicJWK, &pub); err != nil {
		t.Fatal(err)
	}
	if pub["kid"] != a.KID || pub["alg"] != "RS256" || pub["use"] != "sig" || pub["kty"] != "RSA" || pub["d"] != nil {
		t.Fatalf("public JWK %v", pub)
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	bad := map[string]string{
		"missing":   filepath.Join(t.TempDir(), "absent.pem"),
		"kms":       "kms:projects/x/keys/y",
		"empty":     writeFile(t, "e.pem", nil),
		"garbage":   writeFile(t, "g.pem", []byte("not pem")),
		"short":     writeFile(t, "s.pem", tokentest.PEM(t, small)),
		"ec":        writeFile(t, "ec.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})),
		"public":    writeFile(t, "p.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})),
		"two":       writeFile(t, "two.pem", append(tokentest.PEM(t, key), tokentest.PEM(t, key)...)),
		"encrypted": writeFile(t, "enc.pem", encrypted),
		"bad pkcs1": writeFile(t, "b1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2}})),
		"bad pkcs8": writeFile(t, "b8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}})),
		"too large": writeFile(t, "big.pem", make([]byte, MaxKeyFileBytes+1)),
	}
	for name, ref := range bad {
		_, err := LoadKeyFile("SIGNING_KEY_FILES", ref)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != "SIGNING_KEY_FILES" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParsePrivateKeyPEM(f *testing.F) {
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := ParsePrivateKeyPEM(raw)
		if err == nil && k == nil {
			t.Fatal("nil key without an error")
		}
	})
}

func TestNewKeysRefusesAmbiguousConfiguration(t *testing.T) {
	a, _ := NewKeyFile("a", tokentest.Key(t, 0))
	b, _ := NewKeyFile("b", tokentest.Key(t, 1))
	if _, err := NewKeys(testIssuer, time.Hour, nil, nil); err == nil || !strings.Contains(err.Error(), "SIGNING_KEY_FILES") {
		t.Fatalf("no files: %v", err)
	}
	if _, err := NewKeys("", time.Hour, []KeyFile{a}, nil); err == nil {
		t.Fatal("empty issuer accepted")
	}
	if _, err := NewKeys(testIssuer, time.Hour, []KeyFile{a, a}, nil); err == nil {
		t.Fatal("the same key twice accepted")
	}
	if _, err := NewKeys(testIssuer, time.Hour, []KeyFile{a}, &a); err == nil || !strings.Contains(err.Error(), "PUBLICATION_KEY_FILE") {
		t.Fatalf("one key for two purposes: %v", err)
	}
	k, err := NewKeys(testIssuer, time.Hour, []KeyFile{a, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issue("cisp-01", "h", nil, time.Minute, time.Now()); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("issue before Apply: %v", err)
	}
	if err := k.Apply(nil); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("no active row: %v", err)
	}
	now := time.Now()
	other, _ := NewKeyFile("c", tokentest.Key(t, 2))
	if err := k.Apply([]KeyRow{{KID: other.KID, Purpose: PurposeToken, ActiveFrom: &now}}); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("active kid without a file: %v", err)
	}
	if r, err := k.PublicationRing(); r != nil || err != nil {
		t.Fatalf("publication ring without a key: %v %v", r, err)
	}
}

// The session token has exactly table A's session claims and is
// verified by core with StrictSessionClaims.
func TestSessionTokenHasExactlyTableAClaims(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	now := f.clock.Now()
	tok, err := f.parts.Keys.SignSession(SessionClaims{
		Subject: "u-1", Audience: "authority.example.test", Roles: []string{"admin", "auditor"}, Realm: "console",
		JTI: "sess-1", IssuedAt: now, ExpiresAt: now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	cl := claimsOf(t, tok)
	keys := make([]string, 0, len(cl))
	for k := range cl {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "aud,exp,iat,iss,jti,realm,roles,scope,sub" {
		t.Fatalf("claims %v", keys)
	}
	h := headerOf(t, tok)
	if h["alg"] != "RS256" || h["kid"] != f.parts.Keys.ActiveKID() || h["typ"] != "JWT" || len(h) != 3 {
		t.Fatalf("header %v", h)
	}
	got, err := f.verifier(t, "authority.example.test").Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "u-1" || !slices.Equal(got.Scopes, []string{"session"}) || !slices.Equal(got.Roles, []string{"admin", "auditor"}) ||
		got.Realm != "console" || got.JTI != "sess-1" || got.ExpiresAt.Sub(got.IssuedAt) != 12*time.Hour {
		t.Fatalf("claims %+v", got)
	}
	// An empty role list is an empty array, never absent or null.
	tok, _ = f.parts.Keys.SignSession(SessionClaims{Subject: "u-2", Audience: "a", Realm: "police", JTI: "s2", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if r, ok := claimsOf(t, tok)["roles"].([]any); !ok || len(r) != 0 {
		t.Fatalf("roles %v", claimsOf(t, tok)["roles"])
	}
	for name, c := range map[string]SessionClaims{
		"sub":   {Audience: "a", Realm: "console", JTI: "j", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"aud":   {Subject: "s", Realm: "console", JTI: "j", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"jti":   {Subject: "s", Audience: "a", Realm: "console", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"realm": {Subject: "s", Audience: "a", JTI: "j", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"exp":   {Subject: "s", Audience: "a", Realm: "console", JTI: "j", IssuedAt: now, ExpiresAt: now},
	} {
		if _, err := f.parts.Keys.SignSession(c); err == nil {
			t.Errorf("%s missing: signed", name)
		}
	}
}

// M26: the JWKS lists the publication key under its own kid, a detached
// JWS made with core's SignDetached verifies against the published set,
// and the publication key never verifies a token: the issuer's own
// token key set leaves it out.
func TestPublicationKeyIsPublishedAndNeverSignsATokenHere(t *testing.T) {
	f := newFixture(t, fixtureOpts{publication: true})
	now := f.clock.Now()
	set, err := f.parts.Keys.JWKS(now)
	if err != nil {
		t.Fatal(err)
	}
	pubKID := f.parts.Keys.Publication().KID
	var kids []string
	for i := range set.Len() {
		k, _ := set.Key(i)
		kid, _ := k.KeyID()
		kids = append(kids, kid)
		if use, _ := k.KeyUsage(); use != "sig" {
			t.Errorf("%s use %q", kid, use)
		}
	}
	if !slices.Equal(kids, []string{f.parts.Keys.ActiveKID(), pubKID}) {
		t.Fatalf("JWKS kids %v", kids)
	}
	ring, err := f.parts.Keys.PublicationRing()
	if err != nil || ring == nil {
		t.Fatal(err)
	}
	body := []byte(`{"dataset":"zones","version":7}`)
	sig, err := ring.SignDetached(body, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	published, _ := jwk.Parse(raw)
	dv, err := auth.NewDetachedVerifier(context.Background(), auth.DetachedConfig{
		Publishers: map[string]auth.IssuerConfig{"authority-01": {Keys: published}}, Now: f.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := dv.Verify(context.Background(), "authority-01", sig, body); err != nil || s.KID != pubKID {
		t.Fatalf("detached signature: %+v %v", s, err)
	}
	if _, err := dv.Verify(context.Background(), "authority-01", sig, append(body, ' ')); err == nil {
		t.Fatal("a changed body verified")
	}

	// A JWT signed with the publication key: the token key set does not
	// hold it, so this issuer's own verifier refuses it.
	tokSet, _ := f.parts.Keys.TokenKeys(now)
	if _, ok := tokSet.LookupKeyID(pubKID); ok {
		t.Fatal("the token key set holds the publication key")
	}
	v, _ := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{testIssuer: {Keys: tokSet}}, Audience: "a.example.test", Now: f.clock.Now,
	})
	priv, _ := jwk.Import(f.parts.Keys.Publication().Key)
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, pubKID)
	payload, _ := json.Marshal(map[string]any{"iss": testIssuer, "aud": "a.example.test", "sub": "x", "jti": "j", "exp": now.Add(time.Hour).Unix()})
	forged, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	var te *auth.TokenError
	if _, err := v.Verify(context.Background(), string(forged)); !errors.As(err, &te) || te.Counter != auth.CounterRejectedKID {
		t.Fatalf("publication-key JWT: %v", err)
	}
	tok, _ := f.parts.Keys.Issue("x", "a.example.test", nil, time.Hour, now)
	if _, err := v.Verify(context.Background(), tok.Token); err != nil {
		t.Fatalf("token-key twin: %v", err)
	}
}

func TestKeyRowStates(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	from, retired, req := now.Add(-48*time.Hour), now.Add(-time.Hour), now
	grace := 24 * time.Hour
	cases := map[string]KeyRow{
		"candidate": {},
		"requested": {RequestedAt: &req, RequestedBy: "a"},
		"active":    {ActiveFrom: &from},
		"retiring":  {ActiveFrom: &from, RetiredAt: &retired},
		"retired":   {ActiveFrom: &from, RetiredAt: func() *time.Time { r := now.Add(-25 * time.Hour); return &r }()},
	}
	for want, r := range cases {
		if got := r.State(now, grace); got != want {
			t.Errorf("%s: %s", want, got)
		}
	}
}

func TestNextCandidateFollowsTheConfiguredOrder(t *testing.T) {
	now := time.Now()
	rows := []KeyRow{{KID: "c", Purpose: PurposeToken}, {KID: "a", Purpose: PurposeToken, ActiveFrom: &now}, {KID: "b", Purpose: PurposeToken}, {KID: "p", Purpose: PurposePublication}}
	if r, ok := NextCandidate([]string{"a", "b", "c"}, rows); !ok || r.KID != "b" {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := NextCandidate([]string{"a", "p"}, rows); ok {
		t.Fatal("a publication key is a token candidate")
	}
}

func TestNewIDIsRandomHex(t *testing.T) {
	a, _ := NewID()
	b, _ := NewID()
	if len(a) != 32 || a == b {
		t.Fatalf("%q %q", a, b)
	}
}

// The JWKS publishes the public part of a stored key only, and only
// under its own thumbprint: a row carrying private members is published
// without them; a row whose kid names another key is left out and
// counted; the honest row is published.
func TestTokenKeysPublishOnlyTheThumbprintedPublicKey(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	now := f.clock.Now()
	active := f.parts.Keys.Rows()[0]
	priv, err := importPrivate(f.parts.Keys.Files()[0], active.KID)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewKeyFile("x", tokentest.Key(t, 4))
	from := now.Add(-time.Minute)
	rows := []KeyRow{
		{KID: active.KID, Purpose: PurposeToken, PublicJWK: priv, ActiveFrom: active.ActiveFrom},
		{KID: "not-the-thumbprint-of-it-0000000", Purpose: PurposeToken, PublicJWK: other.PublicJWK, ActiveFrom: &from, RetiredAt: &now},
		{KID: other.KID, Purpose: PurposeToken, PublicJWK: []byte(`{"kty":"oct","k":"c2VjcmV0"}`), ActiveFrom: &from, RetiredAt: &now},
	}
	if err := f.parts.Keys.Apply(rows); err != nil {
		t.Fatal(err)
	}
	set, err := f.parts.Keys.TokenKeys(now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	if set.Len() != 1 || strings.Contains(string(raw), `"d"`) || strings.Contains(string(raw), `"p"`) {
		t.Fatalf("published %s", raw)
	}
	k, _ := set.Key(0)
	if kid, _ := k.KeyID(); kid != active.KID {
		t.Fatalf("kid %q", kid)
	}
	if got := f.parts.Counters.Get(CounterKeyRejected); got != 2 {
		t.Fatalf("%d rows rejected, want 2", got)
	}
	// Tokens still verify against the cleaned set.
	tok, _ := f.parts.Keys.Issue("x", cispHost, nil, time.Hour, now)
	if _, err := f.verifier(t, cispHost).Verify(context.Background(), tok.Token); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := PublicJWK([]byte("{"), "x"); err == nil {
		t.Fatal("garbage accepted")
	}
}
