package tokens

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// fakeIssuer counts requests and answers with tokens of ttl, after
// release when gate is set.
type fakeIssuer struct {
	calls  atomic.Int32
	ttl    int
	status int
	gate   chan struct{}
	seen   chan string
}

func (f *fakeIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := f.calls.Add(1)
	_ = r.ParseForm()
	if f.seen != nil {
		f.seen <- r.PostForm.Get("audience") + "|" + r.PostForm.Get("scope")
	}
	if f.gate != nil {
		<-f.gate
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = fmt.Fprint(w, `{"error":"invalid_client","error_description":"no"}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer","expires_in":%d,"scope":"x"}`, n, f.ttl)
}

func newTestClient(t *testing.T, url string, clk *clock, maxEntries int) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{TokenURL: url, ClientID: "authority-01", ClientSecret: "s", Now: clk.Now, MaxEntries: maxEntries,
		RetryInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

// One token per audience, reused until half its lifetime; from then the
// cached token is served while one refresh runs in the background, and
// the next call gets the new token (T5, E-14).
func TestClientCachesAndRefreshesAtHalfLife(t *testing.T) {
	fi := &fakeIssuer{ttl: 3600}
	srv := httptest.NewServer(fi)
	defer srv.Close()
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	c := newTestClient(t, srv.URL, clk, 0)
	ctx := context.Background()
	a, err := c.Token(ctx, "https://uspace-cisp.example.test/v1", "cis.read")
	if err != nil || a != "tok-1" {
		t.Fatalf("%q %v", a, err)
	}
	if b, _ := c.Token(ctx, "https://USPACE-CISP.example.test:443/other", "cis.read", "cis.read"); b != a || fi.calls.Load() != 1 {
		t.Fatalf("not reused: %q, %d calls", b, fi.calls.Load())
	}
	// Another audience is another token.
	if d, _ := c.Token(ctx, "https://uspace-ansp.example.test", "cis.read"); d == a || fi.calls.Load() != 2 {
		t.Fatalf("one token for two audiences: %q", d)
	}
	clk.Advance(31 * time.Minute)
	if got, _ := c.Token(ctx, "https://uspace-cisp.example.test", "cis.read"); got != a {
		t.Fatalf("past half life the cached token is served: %q", got)
	}
	waitFor(t, func() bool { return fi.calls.Load() == 3 })
	waitFor(t, func() bool {
		got, _ := c.Token(ctx, "https://uspace-cisp.example.test", "cis.read")
		return got == "tok-3"
	})
	if c.Counters().Get(CounterClientPrefetched) != 1 || c.Counters().Get(CounterClientFetched) != 3 {
		t.Fatalf("counters %v", c.Counters().Snapshot())
	}
	// Expired and the issuer refuses: the error, never a stale token.
	fi.status = http.StatusUnauthorized
	clk.Advance(2 * time.Hour)
	var te *TokenError
	if _, err := c.Token(ctx, "https://uspace-cisp.example.test", "cis.read"); !errors.As(err, &te) || te.Code != "invalid_client" {
		t.Fatalf("expired and refused: %v", err)
	}
}

// E-14: a caller that cancels is released, the request finishes for the
// others; a caller whose context is already done starts nothing.
func TestClientCancellationDoesNotFailOthers(t *testing.T) {
	fi := &fakeIssuer{ttl: 600, gate: make(chan struct{}), seen: make(chan string, 4)}
	srv := httptest.NewServer(fi)
	defer srv.Close()
	clk := &clock{t: time.Now()}
	c := newTestClient(t, srv.URL, clk, 0)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Token(done, "https://dss.example.test", "rid.display_provider"); !errors.Is(err, context.Canceled) || fi.calls.Load() != 0 {
		t.Fatalf("a done context started a request: %v", err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() {
		_, err := c.Token(ctxA, "https://dss.example.test", "rid.display_provider")
		errA <- err
	}()
	if got := <-fi.seen; got != "dss.example.test|rid.display_provider" {
		t.Fatalf("request %q", got)
	}
	var wg sync.WaitGroup
	var tokB string
	var errB error
	wg.Go(func() { tokB, errB = c.Token(context.Background(), "https://dss.example.test", "rid.display_provider") })
	cancelA()
	if err := <-errA; !errors.Is(err, context.Canceled) {
		t.Fatalf("A: %v", err)
	}
	close(fi.gate)
	wg.Wait()
	if errB != nil || tokB != "tok-1" || fi.calls.Load() != 1 {
		t.Fatalf("B: %q %v after %d calls", tokB, errB, fi.calls.Load())
	}
}

// E-10: the cache holds at most MaxEntries tokens.
func TestClientCacheIsBounded(t *testing.T) {
	fi := &fakeIssuer{ttl: 600}
	srv := httptest.NewServer(fi)
	defer srv.Close()
	c := newTestClient(t, srv.URL, &clock{t: time.Now()}, 3)
	for i := range 10 {
		if _, err := c.TokenFor(context.Background(), fmt.Sprintf("peer-%d.example.test", i), []string{"rid.service_provider"}); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 3 || c.Counters().Get(CounterClientEvicted) != 7 {
		t.Fatalf("len %d counters %v", c.Len(), c.Counters().Snapshot())
	}
}

// Against the real token endpoint: client_secret_post and
// private_key_jwt, each token verified by core for its audience.
func TestClientAgainstTheIssuer(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	srv := serve(t, f, "")
	secret := f.register(t, "authority-01", []string{"cis.publish:zones"}, []string{cispHost})
	c, err := NewClient(ClientConfig{TokenURL: srv.URL + "/oauth/token", ClientID: "authority-01", ClientSecret: secret, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background(), "https://"+cispHost, "cis.publish:zones")
	if err != nil {
		t.Fatal(err)
	}
	if cl, err := f.verifier(t, cispHost).Verify(context.Background(), tok); err != nil || cl.Subject != "authority-01" {
		t.Fatalf("verify: %v", err)
	}
	// The issuer refuses a national scope for an audience off the list.
	var te *TokenError
	if _, err := c.Token(context.Background(), "https://elsewhere.example.test", "cis.publish:zones"); !errors.As(err, &te) || te.Code != ErrInvalidTarget {
		t.Fatalf("off-list audience: %v", err)
	}

	if _, _, err := f.parts.Registry.Create(context.Background(), ClientInput{ID: "ussp-GEO1-01", Scopes: []string{"rid.service_provider"},
		AuthMethod: MethodPrivateKeyJWT, JWKS: clientJWKS(t, 3, clientKID)}, admin); err != nil {
		t.Fatal(err)
	}
	kc, err := NewClient(ClientConfig{TokenURL: testIssuer + "/oauth/token", ClientID: "ussp-GEO1-01",
		AssertionKey: &auth.SigningKey{KID: clientKID, Key: tokentest.Key(t, 3)}, Now: f.clock.Now,
		HTTPClient: &http.Client{Transport: rewrite{to: srv.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err = kc.Token(context.Background(), "https://peer.example.test/uss", "rid.service_provider")
	if err != nil {
		t.Fatal(err)
	}
	if cl, err := f.verifier(t, "peer.example.test").Verify(context.Background(), tok); err != nil || cl.Subject != "ussp-GEO1-01" {
		t.Fatalf("verify: %v", err)
	}
}

// rewrite sends every request to the test server, keeping the path: the
// assertion's aud is the issuer's real token URL.
type rewrite struct{ to string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	target, _ := http.NewRequest(req.Method, r.to+u.Path, req.Body)
	target.Header = req.Header
	return http.DefaultTransport.RoundTrip(target.WithContext(req.Context()))
}

func TestNewClientRefusals(t *testing.T) {
	key := &auth.SigningKey{KID: "k", Key: tokentest.Key(t, 3)}
	for name, c := range map[string]ClientConfig{
		"no url":    {ClientID: "lab-01", ClientSecret: "s"},
		"ftp url":   {TokenURL: "ftp://x/oauth/token", ClientID: "lab-01", ClientSecret: "s"},
		"bad id":    {TokenURL: "https://x/oauth/token", ClientID: "lab", ClientSecret: "s"},
		"both":      {TokenURL: "https://x/oauth/token", ClientID: "lab-01", ClientSecret: "s", AssertionKey: key},
		"neither":   {TokenURL: "https://x/oauth/token", ClientID: "lab-01"},
		"short key": {TokenURL: "https://x/oauth/token", ClientID: "lab-01", AssertionKey: &auth.SigningKey{KID: "k"}},
	} {
		if _, err := NewClient(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c, _ := NewClient(ClientConfig{TokenURL: "https://x/oauth/token", ClientID: "lab-01", ClientSecret: "s"})
	if _, err := c.TokenFor(context.Background(), "h", nil); err == nil {
		t.Fatal("no scope accepted")
	}
	if _, err := c.Token(context.Background(), "not a url", "cis.read"); err == nil {
		t.Fatal("a base URL without a scheme accepted")
	}
}

func TestParseTokenResponse(t *testing.T) {
	if tok, ttl, err := ParseTokenResponse(200, []byte(`{"access_token":"a.b.c","token_type":"bearer","expires_in":60}`)); err != nil || tok != "a.b.c" || ttl != time.Minute {
		t.Fatalf("accepted twin: %q %s %v", tok, ttl, err)
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"refused":    {401, `{"error":"invalid_client"}`},
		"no body":    {500, ``},
		"not json":   {200, `x`},
		"no token":   {200, `{"token_type":"Bearer","expires_in":60}`},
		"mac":        {200, `{"access_token":"a","token_type":"MAC","expires_in":60}`},
		"zero":       {200, `{"access_token":"a","token_type":"Bearer","expires_in":0}`},
		"too long":   {200, `{"access_token":"a","token_type":"Bearer","expires_in":3601}`},
		"string ttl": {200, `{"access_token":"a","token_type":"Bearer","expires_in":"60"}`},
		"float ttl":  {200, `{"access_token":"a","token_type":"Bearer","expires_in":60.5}`},
		"huge token": {200, `{"access_token":"` + strings.Repeat("a", auth.DefaultMaxTokenBytes+1) + `","token_type":"Bearer","expires_in":60}`},
	} {
		if _, _, err := ParseTokenResponse(c.status, []byte(c.body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	_, _, err := ParseTokenResponse(503, nil)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "http_503" || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
}

func FuzzParseTokenResponse(f *testing.F) {
	f.Add(200, []byte(`{"access_token":"a","token_type":"Bearer","expires_in":60}`))
	f.Add(400, []byte(`{"error":"x"}`))
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		tok, ttl, err := ParseTokenResponse(status, body)
		if err == nil && (status != 200 || tok == "" || ttl <= 0 || ttl > MaxTokenTTL) {
			t.Fatalf("accepted %d %q -> %q %s", status, body, tok, ttl)
		}
		if err != nil && tok != "" && strings.Contains(err.Error(), tok) {
			t.Fatal("the error carries the token")
		}
	})
}
