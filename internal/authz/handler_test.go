package authz

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// serve mounts the auth and user routes as cmd/api does, identities from
// the real authenticator.
func serve(t *testing.T, f *fixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	apiserver.Mount(mux, apiserver.Server{AuthHandler: Handler{Service: f.svc}, UsersHandler: Handler{Service: f.svc}}, apiserver.Options{
		Middlewares: []apiserver.Middleware{apiserver.Authorize(f.a.Identify, apiserver.DefaultRules())},
		Keep:        apiserver.PathPrefix("/v1/"),
	})
	srv := httptest.NewServer(httpx.Baseline(mux, slog.New(slog.DiscardHandler), httpx.BaselineDeps{Counters: newCounters()}))
	t.Cleanup(srv.Close)
	return srv
}

func send(t *testing.T, method, u, bearer, body string) (int, http.Header, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, resp.Header, m
}

func TestAuthAndUserRoutesOverHTTP(t *testing.T) {
	f := newFixture(t, fxOpts{ipBurst: 30})
	srv := serve(t, f)
	code, hdr, ch := send(t, http.MethodPost, srv.URL+"/v1/auth/login", "", `{"username":"admin","password":"`+adminPW+`"}`)
	if code != 200 || hdr.Get("Cache-Control") != "no-store" || ch["enrolment"] == nil {
		t.Fatalf("login: %d %v", code, ch)
	}
	secret := ch["enrolment"].(map[string]any)["secret"].(string)
	totpCode, _ := totp.GenerateCode(secret, f.clk.Now())
	code, _, sess := send(t, http.MethodPost, srv.URL+"/v1/auth/mfa", "", `{"mfa_token":"`+ch["mfa_token"].(string)+`","code":"`+totpCode+`"}`)
	if code != 200 || sess["token_type"] != "Bearer" || sess["idle_timeout_s"] != 1800.0 || len(sess["recovery_codes"].([]any)) != 10 {
		t.Fatalf("mfa: %d %v", code, sess)
	}
	token := sess["token"].(string)
	code, _, info := send(t, http.MethodGet, srv.URL+"/v1/auth/session", token, "")
	if code != 200 || info["realm"] != "console" || info["idle_expires_at"] == nil {
		t.Fatalf("session: %d %v", code, info)
	}
	// Users.
	code, _, u := send(t, http.MethodPost, srv.URL+"/v1/users", token, `{"username":"viewer1","password":"`+adminPW+`","roles":["viewer"],"realm":"console"}`)
	if code != 201 || u["mfa_enrolled"] != false || u["password"] != nil {
		t.Fatalf("create: %d %v", code, u)
	}
	id := u["id"].(string)
	for _, c := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/v1/users", "", 200},
		{http.MethodGet, "/v1/users/" + id, "", 200},
		{http.MethodGet, "/v1/users/nobody", "", 404},
		{http.MethodPut, "/v1/users/" + id + "/roles", `{"roles":["inspector"]}`, 200},
		{http.MethodPut, "/v1/users/" + id + "/roles", `{"roles":["root"]}`, 400},
		{http.MethodPost, "/v1/users/" + id + "/disable", "", 200},
		{http.MethodPost, "/v1/users/" + id + "/enable", "", 200},
		{http.MethodPost, "/v1/users/" + id + "/mfa/reset", "", 200},
		{http.MethodPost, "/v1/users/" + id + "/sessions/revoke", "", 200},
		{http.MethodPost, "/v1/users/" + id + "/mfa/unlock", "", 200},
		{http.MethodPost, "/v1/users/nobody/mfa/unlock", "", 404},
		{http.MethodPost, "/v1/users", `{"username":"x"}`, 400},
	} {
		if code, _, body := send(t, c.method, srv.URL+c.path, token, c.body); code != c.want {
			t.Errorf("%s %s: %d %v", c.method, c.path, code, body)
		}
	}
	// A viewer session is refused on the admin routes, admitted on its own.
	f.clk.Advance(time.Minute)
	viewer := f.signIn(t, "viewer1", adminPW)
	if code, _, _ := send(t, http.MethodGet, srv.URL+"/v1/users", viewer.Token, ""); code != 403 {
		t.Fatalf("viewer on admin route: %d", code)
	}
	if code, _, _ := send(t, http.MethodGet, srv.URL+"/v1/auth/session", viewer.Token, ""); code != 200 {
		t.Fatalf("viewer on its session: %d", code)
	}
	if code, _, _ := send(t, http.MethodPost, srv.URL+"/v1/auth/logout", token, ""); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _, _ := send(t, http.MethodGet, srv.URL+"/v1/auth/session", token, ""); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
	// Refusals over HTTP: wrong password 401, missing body 400.
	if code, _, p := send(t, http.MethodPost, srv.URL+"/v1/auth/login", "", `{"username":"admin","password":"nope nope nope"}`); code != 401 ||
		p["type"] != httpx.ProblemTypeBase+SlugInvalidCredentials {
		t.Fatalf("wrong password: %d %v", code, p)
	}
	if code, _, _ := send(t, http.MethodPost, srv.URL+"/v1/auth/mfa", "", `{"mfa_token":"x","code":"123456"}`); code != 401 {
		t.Fatalf("bad challenge: %d", code)
	}
}

func TestRateLimitOverHTTPHasRetryAfter(t *testing.T) {
	f := newFixture(t, fxOpts{ipBurst: 1})
	srv := serve(t, f)
	send(t, http.MethodPost, srv.URL+"/v1/auth/login", "", `{"username":"admin","password":"x"}`)
	code, hdr, p := send(t, http.MethodPost, srv.URL+"/v1/auth/login", "", `{"username":"admin","password":"x"}`)
	if code != 429 || hdr.Get("Retry-After") == "" || p["type"] != httpx.ProblemTypeBase+httpx.SlugRateLimited {
		t.Fatalf("login: %d %v %v", code, hdr, p)
	}
	code, hdr, _ = send(t, http.MethodPost, srv.URL+"/v1/auth/mfa", "", `{"mfa_token":"x","code":"123456"}`)
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("mfa: %d", code)
	}
}

// Behind the trusted proxy (the test server's peer is 127.0.0.1) the
// sign-in limit and the audit row use the forwarded client, so two
// clients do not share a bucket; without the trust, X-Forwarded-For
// changes nothing.
func TestSignInLimitAndAuditUseTheForwardedClient(t *testing.T) {
	for _, trust := range []bool{true, false} {
		f := newFixture(t, fxOpts{ipBurst: 1})
		mux := http.NewServeMux()
		apiserver.Mount(mux, apiserver.Server{AuthHandler: Handler{Service: f.svc}}, apiserver.Options{
			Middlewares: []apiserver.Middleware{apiserver.Authorize(f.a.Identify, apiserver.DefaultRules())},
			Keep:        apiserver.PathPrefix("/v1/"),
		})
		var proxies []netip.Prefix
		if trust {
			proxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
		}
		srv := httptest.NewServer(httpx.Baseline(mux, slog.New(slog.DiscardHandler), httpx.BaselineDeps{Counters: newCounters(), TrustedProxies: proxies}))
		login := func(client string) int {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/login", strings.NewReader(`{"username":"admin","password":"wrong password!!"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "1.2.3.4, "+client)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		first, second := login("203.0.113.1"), login("203.0.113.2")
		evs := f.st.eventsOf("login_refused")
		ip := evs[0].Payload.(map[string]any)["remote_ip"]
		if trust && (first != 401 || second != 401 || ip != "203.0.113.1") {
			t.Fatalf("trusted proxy: %d %d, audited %v", first, second, ip)
		}
		if !trust && (second != 429 || (ip != "127.0.0.1" && ip != "::1")) {
			t.Fatalf("untrusted peer: %d %d, audited %v", first, second, ip)
		}
		srv.Close()
	}
}

// A check-only read of the session (?activity=false, picture-ws's
// re-check) is not activity: it leaves last_seen_at where it was, so an
// idle console's re-checks never keep it alive and the session ends at
// the idle timeout. A plain read is activity and moves last_seen_at (the
// pair).
func TestSessionCheckOnlyIsNotActivity(t *testing.T) {
	f := newFixture(t, fxOpts{})
	srv := serve(t, f)
	sess := f.signIn(t, "admin", adminPW)
	lastSeen := func() time.Time {
		t.Helper()
		s, err := f.st.Session(context.Background(), sess.Session.JTI)
		if err != nil {
			t.Fatal(err)
		}
		return s.LastSeenAt
	}
	signedIn := lastSeen()

	f.clk.Advance(5 * time.Minute)
	if code, _, info := send(t, http.MethodGet, srv.URL+"/v1/auth/session?activity=false", sess.Token, ""); code != 200 || info["jti"] != sess.Session.JTI {
		t.Fatalf("check-only: %d %v", code, info)
	}
	if got := lastSeen(); !got.Equal(signedIn) {
		t.Fatalf("a check-only read moved last_seen_at from %s to %s", signedIn, got)
	}
	if code, _, _ := send(t, http.MethodGet, srv.URL+"/v1/auth/session", sess.Token, ""); code != 200 {
		t.Fatalf("plain read: %d", code)
	}
	active := lastSeen()
	if !active.Equal(f.clk.Now()) {
		t.Fatalf("a plain read left last_seen_at at %s, want %s", active, f.clk.Now())
	}

	// Re-checks every 15 s for the idle timeout: the session stays live
	// until it, and is refused past it.
	for elapsed := time.Duration(0); elapsed < f.svc.Config.IdleTimeout; elapsed += 15 * time.Second {
		f.clk.Advance(15 * time.Second)
		code, _, _ := send(t, http.MethodGet, srv.URL+"/v1/auth/session?activity=false", sess.Token, "")
		if f.clk.Now().Sub(active) <= f.svc.Config.IdleTimeout && code != 200 {
			t.Fatalf("live session refused %s after its last activity: %d", f.clk.Now().Sub(active), code)
		}
	}
	f.clk.Advance(15 * time.Second)
	if code, _, p := send(t, http.MethodGet, srv.URL+"/v1/auth/session?activity=false", sess.Token, ""); code != 401 ||
		!strings.Contains(p["detail"].(string), "idle") {
		t.Fatalf("idle session past the timeout: %d %v", code, p)
	}
	if got := lastSeen(); !got.Equal(active) {
		t.Fatalf("check-only reads moved last_seen_at to %s", got)
	}
}
