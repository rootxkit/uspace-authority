package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// WP-13 against the real api and its sessions table: picture-ws's
// session check (uspace-core's verifier on this issuer's JWKS, then
// GET /v1/auth/session) admits the session of a console signed in
// through api, keeps the stream open while the row is live, and closes
// it with 4401 at the first re-check after the logout revoked the row;
// the same cookie is then refused at the upgrade. The relational
// database is api's alone: picture-ws reaches it only through api.
func TestIntegrationPictureSessionEndsWithItsRowInTheDatabase(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs PostgreSQL (make up)")
	}
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	const adminPW = "correct horse battery staple"
	if err := os.WriteFile(pwFile, []byte(adminPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", pwFile
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() { cancel(); <-exit })
	base := "http://" + stdout.waitFor(t, "public listener open", nil)["addr"].(string)

	var ch struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment struct {
			Secret string `json:"secret"`
		} `json:"enrolment"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/login", "", jsonCT, `{"username":"admin","password":"`+adminPW+`"}`, &ch); code != 200 {
		t.Fatalf("login: %d", code)
	}
	code6, err := totp.GenerateCode(ch.Enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var sess struct {
		Token string `json:"token"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/mfa", "", jsonCT, `{"mfa_token":"`+ch.MFAToken+`","code":"`+code6+`"}`, &sess); code != 200 || sess.Token == "" {
		t.Fatalf("mfa: %d", code)
	}

	// picture-ws's check, wired as cmd/picture-ws wires it.
	lv := &picture.LazyVerifier{Config: auth.Config{
		Issuers:   map[string]auth.IssuerConfig{"http://localhost:8080": {JWKSURL: base + "/.well-known/jwks.json"}},
		Audiences: []string{"localhost"}, StrictSessionClaims: true,
	}}
	lv.Start(ctx)
	if !lv.Ready() {
		t.Fatal("the verifier did not fetch api's JWKS")
	}
	checker := &picture.APIChecker{Verifier: lv, URL: base + "/v1/auth/session", Client: picture.NoRedirectClient(), Timeout: 2 * time.Second}
	hub := picture.NewHub(picture.Config{StatusInterval: time.Hour, SessionRecheck: 200 * time.Millisecond}, picture.Inputs{}, nil, nil)
	defer hub.Close()
	mux := http.NewServeMux()
	(&picture.Handler{Hub: hub, Sessions: checker, Origins: []string{"http://localhost:8080"}, SessionTimeout: 2 * time.Second}).Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/picture/ws"
	dial := func() *websocket.Conn {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		c, _, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{
			"Origin": {"http://localhost:8080"}, "Cookie": {picture.CookieSession + "=" + sess.Token},
		}})
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadLimit(1 << 24)
		return c
	}
	// frames reads c in the background: every frame, then the close.
	frames := func(c *websocket.Conn) (<-chan string, <-chan websocket.StatusCode) {
		fc, cc := make(chan string, 64), make(chan websocket.StatusCode, 1)
		go func() {
			for {
				_, raw, err := c.Read(ctx)
				if err != nil {
					cc <- websocket.CloseStatus(err)
					return
				}
				fc <- string(raw)
			}
		}()
		return fc, cc
	}

	c := dial()
	fc, cc := frames(c)
	for _, want := range []string{`"console/status/v1"`, `"console/snapshot/v1"`} {
		select {
		case f := <-fc:
			if !strings.Contains(f, want) {
				t.Fatalf("frame %q, want %s", f, want)
			}
		case code := <-cc:
			t.Fatalf("closed %d before %s", code, want)
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s", want)
		}
	}
	// Live: several re-checks pass and nothing closes the stream.
	select {
	case code := <-cc:
		t.Fatalf("closed %d while the session is live", code)
	case <-time.After(time.Second):
	}

	if code, _ := call(t, http.MethodPost, base+"/v1/auth/logout", sess.Token, "", "", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	ended := time.Now()
	select {
	case code := <-cc:
		if code != picture.CloseRelogin {
			t.Fatalf("closed %d after the logout, want 4401", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived its session")
	}
	t.Logf("the stream closed with 4401 %s after the logout revoked the sessions row", time.Since(ended).Round(time.Millisecond))
	_, cc2 := frames(dial())
	select {
	case code := <-cc2:
		if code != picture.CloseRelogin {
			t.Fatalf("the revoked cookie at the upgrade: %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the revoked cookie was served")
	}
}
