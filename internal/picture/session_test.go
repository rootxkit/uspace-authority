package picture

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

	"github.com/rootxkit/uspace-core/auth"
)

// fakeAPI is api's GET /v1/auth/session: 200 for the live sessions, 401
// for the rest, 500 when broken; it counts the calls.
type fakeAPI struct {
	srv    *httptest.Server
	calls  atomic.Int64
	broken atomic.Bool
	live   map[string]bool
	jwks   []byte
}

func newFakeAPI(t *testing.T, ti *testIssuer, live ...string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{live: map[string]bool{}}
	for _, j := range live {
		f.live[j] = true
	}
	jwks, err := json.Marshal(ti.iss.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	f.jwks = jwks
	v := ti.verifier(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.jwks)
	})
	mux.HandleFunc("GET /v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if f.broken.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		cl, err := v.Verify(r.Context(), tok)
		if err != nil || !f.live[cl.JTI] {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"https://schemas.uspace.ge/problems/unauthenticated","status":401,"detail":"the session was ended (logout)"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": cl.Subject, "roles": cl.Roles, "realm": cl.Realm, "jti": cl.JTI,
			"expires_at": cl.ExpiresAt.UTC().Format(time.RFC3339), "idle_expires_at": time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339),
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) checker(t *testing.T, ti *testIssuer) *APIChecker {
	t.Helper()
	return &APIChecker{Verifier: ti.verifier(t), URL: f.srv.URL + "/v1/auth/session", Timeout: time.Second}
}

// The session check: a live session of the console realm is admitted
// and so is one of the police realm; a revoked one, a machine token, a
// token of another audience, a malformed one and none are refused
// (ErrRefused, 4401); a broken or absent api and a verifier without keys
// are unavailable (ErrUnavailable, 1013). Each refusal beside its
// acceptance (E-01).
func TestAPICheckerAdmitsLiveSessionsOnly(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1", "police-1")
	c := api.checker(t, ti)
	ctx := context.Background()

	s, err := c.Check(ctx, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil || s.JTI != "live-1" || !s.Console() || s.ExpiresAt.IsZero() {
		t.Fatalf("live console session: %+v %v", s, err)
	}
	if s, err := c.Check(ctx, ti.session(t, RealmPolice, "police-1", time.Hour)); err != nil || s.Console() {
		t.Fatalf("police session: %+v %v", s, err)
	}
	if _, err := c.Check(ctx, ti.session(t, RealmConsole, "revoked-1", time.Hour)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "logout") {
		t.Fatalf("revoked: %v", err)
	}
	before := api.calls.Load()
	if _, err := c.Check(ctx, ti.machine(t)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "machine token") {
		t.Fatalf("machine token: %v", err)
	}
	if _, err := c.Check(ctx, "not.a.jwt"); !errors.Is(err, ErrRefused) {
		t.Fatalf("malformed: %v", err)
	}
	if _, err := c.Check(ctx, ""); !errors.Is(err, ErrRefused) {
		t.Fatalf("empty: %v", err)
	}
	if api.calls.Load() != before {
		t.Fatal("api asked about a token core refused")
	}
	other, err := ti.iss.IssueSession(auth.SessionClaims{Audience: "elsewhere.example.test", Subject: "u", Realm: RealmConsole, Roles: []string{"viewer"},
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), JTI: "live-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(ctx, other); !errors.Is(err, ErrRefused) {
		t.Fatalf("other audience: %v", err)
	}
	api.broken.Store(true)
	if _, err := c.Check(ctx, ti.session(t, RealmConsole, "live-1", time.Hour)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("api broken: %v", err)
	}
	api.srv.Close()
	if _, err := c.Check(ctx, ti.session(t, RealmConsole, "live-1", time.Hour)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("api down: %v", err)
	}
	lazy := &APIChecker{Verifier: &LazyVerifier{}, URL: "http://127.0.0.1:1/v1/auth/session"}
	if _, err := lazy.Check(ctx, ti.session(t, RealmConsole, "live-1", time.Hour)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("verifier not ready: %v", err)
	}
}

// The bearer never follows a redirect to another host: a redirect is
// unavailable, and the target is never called.
func TestSessionCheckFollowsNoRedirect(t *testing.T) {
	ti := newTestIssuer(t)
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	c := &APIChecker{Verifier: ti.verifier(t), URL: redirect.URL, Client: NoRedirectClient()}
	if _, err := c.Check(context.Background(), ti.session(t, RealmConsole, "j", time.Hour)); !errors.Is(err, ErrUnavailable) || hit.Load() {
		t.Fatalf("redirect: %v, target hit %v", err, hit.Load())
	}
}

// LazyVerifier: unready while the JWKS cannot be fetched (refusing as
// unavailable), ready once it can, then judging with core's verifier.
func TestLazyVerifierBecomesReady(t *testing.T) {
	ti := newTestIssuer(t)
	var serve atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !serve.Load() {
			http.Error(w, "no", http.StatusServiceUnavailable)
			return
		}
		raw, _ := json.Marshal(ti.iss.JWKS())
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	lv := &LazyVerifier{RetryEvery: 20 * time.Millisecond, Config: auth.Config{
		Issuers: map[string]auth.IssuerConfig{issuerURL: {JWKSURL: srv.URL}}, Audiences: []string{ownHost}, StrictSessionClaims: true,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lv.Start(ctx)
	if lv.Ready() {
		t.Fatal("ready without keys")
	}
	if _, err := lv.Verify(ctx, ti.session(t, RealmConsole, "j", time.Hour)); err == nil || lv.Counters().Get(CounterVerifierNotReady) != 1 {
		t.Fatalf("verified without keys: %v", err)
	}
	serve.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for !lv.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !lv.Ready() {
		t.Fatal("never ready")
	}
	if cl, err := lv.Verify(ctx, ti.session(t, RealmConsole, "j", time.Hour)); err != nil || cl.JTI != "j" {
		t.Fatalf("verify: %v", err)
	}
	if _, err := lv.Verify(ctx, "x.y.z"); err == nil {
		t.Fatal("garbage verified")
	}
	if lv.Counters().Get(auth.CounterAccepted) != 1 {
		t.Fatalf("counters %v", lv.Counters().Snapshot())
	}
}

// A live connection whose session is revoked is closed with 4401 at the
// next re-check; one whose session stays live is not (E-01 pair).
func TestRevokedSessionClosesTheStream(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.SessionRecheck, c.StatusInterval = 30*time.Millisecond, time.Hour })
	checker := &fakeChecker{sess: consoleSession()}
	kept := connect(t, h, consoleSession(), &fakeChecker{sess: consoleSession()})
	revoked := connect(t, h, consoleSession(), checker)
	time.Sleep(100 * time.Millisecond)
	if _, _, closed := revoked.closeCode(); closed {
		t.Fatal("closed while live")
	}
	checker.set(Session{}, refused("api: the session was ended (revoked)"))
	waitClosed(t, revoked, CloseRelogin)
	if _, _, closed := kept.closeCode(); closed {
		t.Fatal("a live session was closed")
	}
	if h.Counters().Get(CounterSessionRevokedClosed) != 1 {
		t.Fatal("not counted")
	}
}

// A session that cannot be re-checked (api down) keeps its connection
// for the grace, said on the status (session_unchecked), then is closed
// with 1013; an expired session is closed with 4401 at its exp.
func TestUncheckableSessionGraceThenClose(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) {
		c.SessionRecheck, c.SessionGrace, c.StatusInterval = 30*time.Millisecond, 300*time.Millisecond, time.Hour
	})
	checker := &fakeChecker{err: unavailable("api did not answer")}
	conn := connect(t, h, consoleSession(), checker)
	time.Sleep(100 * time.Millisecond)
	if _, _, closed := conn.closeCode(); closed {
		t.Fatal("closed within the grace")
	}
	h.Tick(time.Now())
	if st := statusOf(t, mustUntil(t, conn, SchemaStatus)); !has(st.Degraded, DegradedSessionUnchecked) {
		t.Fatalf("degraded %v", st.Degraded)
	}
	waitClosed(t, conn, CloseTryAgainLater)

	exp := consoleSession()
	exp.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	conn = connect(t, h, exp, &fakeChecker{sess: exp})
	waitClosed(t, conn, CloseRelogin)
}

func waitClosed(t *testing.T, conn *fakeConn, want interface{ String() string }) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if code, reason, closed := conn.closeCode(); closed {
			if code.String() != want.String() {
				t.Fatalf("closed %s %q, want %s", code, reason, want)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not closed with %s", want)
}
