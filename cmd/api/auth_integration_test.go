package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// writePIIKey writes a fresh 32-byte PII key (base64) into dir.
func writePIIKey(t *testing.T, dir string) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "pii.key")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// call sends a JSON or form body with an optional bearer and decodes the
// JSON answer.
func call(t *testing.T, method, u, bearer, contentType, body string, out any) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %d %s", method, u, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, resp.Header
}

const jsonCT = "application/json"

// verifierHelperEnv selects the second-process role of this test binary.
const verifierHelperEnv = "USPACE_TEST_VERIFIER_PROCESS"

// TestVerifierProcess is not a test: run as a second process with
// verifierHelperEnv set, it is another system's verifier. It builds
// core/auth's Verifier with its own audiences and this issuer's JWKS URL
// and prints its verdict on the token as JSON.
func TestVerifierProcess(t *testing.T) {
	if os.Getenv(verifierHelperEnv) != "1" {
		t.Skip("helper process for TestIntegrationLabTokenVerifiedInASecondProcess")
	}
	out := map[string]any{}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers:             map[string]auth.IssuerConfig{os.Getenv("VERIFY_ISSUER"): {JWKSURL: os.Getenv("VERIFY_JWKS_URL")}},
		Audiences:           strings.Split(os.Getenv("VERIFY_AUDIENCES"), ","),
		StrictSessionClaims: true,
	})
	if err != nil {
		out["error"] = err.Error()
	} else if cl, err := v.Verify(context.Background(), os.Getenv("VERIFY_TOKEN")); err != nil {
		out["error"] = err.Error()
	} else {
		out["sub"], out["aud"], out["scopes"], out["iss"] = cl.Subject, cl.Audience, cl.Scopes, cl.Issuer
	}
	b, _ := json.Marshal(out)
	_, _ = os.Stdout.Write(append([]byte("VERDICT "), b...))
}

func verifyElsewhere(t *testing.T, issuer, jwksURL, audiences, token string) map[string]any {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVerifierProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), verifierHelperEnv+"=1", "VERIFY_ISSUER="+issuer, "VERIFY_JWKS_URL="+jwksURL,
		"VERIFY_AUDIENCES="+audiences, "VERIFY_TOKEN="+token)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	_, verdict, ok := strings.Cut(out.String(), "VERDICT ")
	if !ok {
		t.Fatalf("the verifier process printed no verdict:\n%s", out.String())
	}
	verdict, _, _ = strings.Cut(verdict, "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.Split(verdict, "PASS")[0])), &m); err != nil {
		t.Fatalf("verdict %q: %v", verdict, err)
	}
	return m
}

func countEvents(t *testing.T, u string) map[string]int {
	t.Helper()
	db := storetest.Open(t, u)
	rows, err := db.Query("SELECT event_type, count(*) FROM events GROUP BY event_type")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var et string
		var n int
		if err := rows.Scan(&et, &n); err != nil {
			t.Fatal(err)
		}
		out[et] = n
	}
	return out
}

func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The done-when of WP-2 through the real process: the first admin is
// bootstrapped; login -> MFA (enrolment) -> session -> logout, each step
// an events row; the session token has exactly table A's claims; a
// client lab-01 is created, its token for a uspace-cisp-shaped host is
// verified by core/auth in a second process with that system's own
// audiences, and no token is issued after the client is suspended.
func TestIntegrationLabTokenVerifiedInASecondProcess(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	const adminPW = "correct horse battery staple"
	if err := os.WriteFile(pwFile, []byte(adminPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "Admin", pwFile
	m["AUTHORITY_AUDIENCES"] = "localhost,authority"
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() { cancel(); <-exit })
	listen := stdout.waitFor(t, "public listener open", nil)
	base := "http://" + listen["addr"].(string)

	// A wrong password, then the right one.
	var problem map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/login", "", jsonCT, `{"username":"admin","password":"wrong password here"}`, &problem); code != 401 ||
		problem["type"] != "https://schemas.uspace.ge/problems/invalid_credentials" {
		t.Fatalf("wrong password: %d %v", code, problem)
	}
	var ch struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment struct {
			Secret string `json:"secret"`
			URI    string `json:"otpauth_uri"`
		} `json:"enrolment"`
	}
	code, hdr := call(t, http.MethodPost, base+"/v1/auth/login", "", jsonCT, `{"username":"ADMIN","password":"`+adminPW+`"}`, &ch)
	if code != 200 || ch.MFAToken == "" || ch.Enrolment.Secret == "" || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("login: %d %+v", code, ch)
	}
	// A wrong code, then the right one.
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/mfa", "", jsonCT, `{"mfa_token":"`+ch.MFAToken+`","code":"000000x"}`, &problem); code != 401 {
		t.Fatalf("wrong code: %d %v", code, problem)
	}
	totpCode, err := totp.GenerateCode(ch.Enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var sess struct {
		Token         string   `json:"token"`
		RecoveryCodes []string `json:"recovery_codes"`
		Session       struct {
			Sub   string   `json:"sub"`
			Roles []string `json:"roles"`
			JTI   string   `json:"jti"`
		} `json:"session"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/mfa", "", jsonCT, `{"mfa_token":"`+ch.MFAToken+`","code":"`+totpCode+`"}`, &sess); code != 200 ||
		sess.Token == "" || len(sess.RecoveryCodes) != 10 {
		t.Fatalf("mfa: %d %+v", code, sess)
	}
	cl := claimsOf(t, sess.Token)
	keys := slices.Sorted(maps.Keys(cl))
	if strings.Join(keys, ",") != "aud,exp,iat,iss,jti,realm,roles,scope,sub" || cl["aud"] != "localhost" || cl["scope"] != "session" ||
		cl["realm"] != "console" || cl["jti"] != sess.Session.JTI || cl["iss"] != "http://localhost:8080" ||
		cl["exp"].(float64)-cl["iat"].(float64) != 12*3600 {
		t.Fatalf("session claims %v", cl)
	}
	var info map[string]any
	if code, _ := call(t, http.MethodGet, base+"/v1/auth/session", sess.Token, "", "", &info); code != 200 || info["jti"] != sess.Session.JTI {
		t.Fatalf("session: %d %v", code, info)
	}

	// The lab client and its token for a CISP-shaped host.
	var created struct {
		Secret string `json:"client_secret"`
	}
	body := `{"client_id":"lab-01","scopes":["cis.read","dp.observe"],"audiences":["uspace-cisp.example.test"],"auth_method":"client_secret_post"}`
	if code, _ := call(t, http.MethodPost, base+"/v1/oauth/clients", sess.Token, jsonCT, body, &created); code != 201 || created.Secret == "" {
		t.Fatalf("create client: %d", code)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"lab-01"}, "client_secret": {created.Secret},
		"scope": {"cis.read"}, "audience": {"https://uspace-cisp.example.test"}}.Encode()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if code, _ := call(t, http.MethodPost, base+"/oauth/token", "", "application/x-www-form-urlencoded", form, &tok); code != 200 || tok.AccessToken == "" {
		t.Fatalf("token: %d", code)
	}
	jwksURL := base + "/.well-known/jwks.json"
	got := verifyElsewhere(t, "http://localhost:8080", jwksURL, "uspace-cisp.example.test,cisp", tok.AccessToken)
	if got["error"] != nil || got["sub"] != "lab-01" || got["aud"] != "uspace-cisp.example.test" {
		t.Fatalf("second process: %v", got)
	}
	// E-01: the same token is refused by a verifier of another host.
	if got := verifyElsewhere(t, "http://localhost:8080", jwksURL, "uspace-ansp.example.test", tok.AccessToken); got["error"] == nil ||
		!strings.Contains(got["error"].(string), "aud") {
		t.Fatalf("another host accepted it: %v", got)
	}
	// This system refuses it too: its aud is the CISP's host.
	if code, _ := call(t, http.MethodGet, base+"/v1/auth/session", tok.AccessToken, "", "", &problem); code != 401 ||
		!strings.Contains(problem["detail"].(string), "aud") {
		t.Fatalf("a token for another host on this system: %d %v", code, problem)
	}

	// Suspended: refused from now on.
	if code, _ := call(t, http.MethodPatch, base+"/v1/oauth/clients/lab-01", sess.Token, jsonCT, `{"status":"suspended"}`, nil); code != 200 {
		t.Fatalf("suspend: %d", code)
	}
	if code, _ := call(t, http.MethodPost, base+"/oauth/token", "", "application/x-www-form-urlencoded", form, &problem); code != 401 || problem["error"] != "invalid_client" {
		t.Fatalf("token after suspension: %d %v", code, problem)
	}

	// Logout ends the session.
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/logout", sess.Token, "", "", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := call(t, http.MethodGet, base+"/v1/auth/session", sess.Token, "", "", &problem); code != 401 || !strings.Contains(problem["detail"].(string), "ended") {
		t.Fatalf("after logout: %d %v", code, problem)
	}
	// A recovery code signs in once (the TOTP step is spent for this
	// 30 s window).
	ch.MFAToken, ch.Enrolment.Secret = "", ""
	code, _ = call(t, http.MethodPost, base+"/v1/auth/login", "", jsonCT, `{"username":"admin","password":"`+adminPW+`"}`, &ch)
	if code != 200 || ch.Enrolment.Secret != "" {
		t.Fatalf("second login: %d %+v", code, ch)
	}
	var again struct {
		Token string `json:"token"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/mfa", "", jsonCT, `{"mfa_token":"`+ch.MFAToken+`","recovery_code":"`+sess.RecoveryCodes[0]+`"}`, &again); code != 200 || again.Token == "" {
		t.Fatalf("recovery code: %d", code)
	}

	got2 := countEvents(t, u)
	for et, n := range map[string]int{
		"user_bootstrapped": 1, "login_refused": 1, "login_password_accepted": 2, "mfa_refused": 1, "mfa_enrolled": 1,
		"session_started": 2, "logout": 1, "oauth_client_created": 1, "oauth_client_updated": 1, "token_issued": 1, "token_refused": 1,
	} {
		if got2[et] != n {
			t.Errorf("%s: %d events, want %d (all %v)", et, got2[et], n, got2)
		}
	}
}

// E-02: the bootstrap variables on a table that has accounts create
// nothing and say so.
func TestIntegrationBootstrapRefusedWhenUsersExist(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	_ = os.WriteFile(pwFile, []byte("correct horse battery staple"), 0o600)
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", pwFile
	for i, want := range []string{
		"first admin created from BOOTSTRAP_ADMIN_USERNAME; remove the bootstrap variables and the password file",
		"bootstrap refused: accounts exist; remove BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD_FILE",
	} {
		var stdout, stderr lines
		ctx, cancel := context.WithCancel(context.Background())
		exit := make(chan int, 1)
		go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(m)) }()
		stdout.waitFor(t, "public listener open", nil)
		if stdout.find(want, nil) == nil {
			t.Errorf("start %d: no %q line", i+1, want)
		}
		cancel()
		<-exit
	}
	if got := countEvents(t, u); got["user_bootstrapped"] != 1 || got["user_bootstrap_refused"] != 1 {
		t.Fatalf("events %v", got)
	}
}
