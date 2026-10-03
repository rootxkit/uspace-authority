package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// adminSession signs the bootstrapped admin in (password, then TOTP
// enrolment) and returns the session token.
func adminSession(t *testing.T, base, password string) string {
	t.Helper()
	var ch struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment struct {
			Secret string `json:"secret"`
		} `json:"enrolment"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/login", "", jsonCT, `{"username":"admin","password":"`+password+`"}`, &ch); code != 200 {
		t.Fatalf("login %d", code)
	}
	otp, err := totp.GenerateCode(ch.Enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var sess struct {
		Token string `json:"token"`
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/auth/mfa", "", jsonCT, `{"mfa_token":"`+ch.MFAToken+`","code":"`+otp+`"}`, &sess); code != 200 || sess.Token == "" {
		t.Fatalf("mfa %d", code)
	}
	return sess.Token
}

type issuedCert struct {
	Certificate struct {
		ID       string `json:"id"`
		ClientID string `json:"client_id"`
		Status   string `json:"status"`
	} `json:"certificate"`
	Client struct {
		Scopes []string `json:"scopes"`
	} `json:"client"`
	Secret string `json:"client_secret"`
}

func issueCert(t *testing.T, base, session, code string) issuedCert {
	t.Helper()
	lc := strings.ToLower(code)
	body, _ := json.Marshal(map[string]any{
		"holder": "ussp", "holder_name": "USSP " + code, "code": code, "holder_email": "ops@" + lc + ".example.test",
		"base_url": "https://" + lc + ".example.test", "terms_url": "https://" + lc + ".example.test/terms",
		"services":    []string{"network_identification", "geo_awareness", "flight_authorisation", "traffic_information"},
		"valid_until": time.Now().AddDate(2, 0, 0).UTC().Format(time.RFC3339), "auth_method": "client_secret_post",
	})
	var out issuedCert
	code2, hdr := call(t, http.MethodPost, base+"/v1/certificates", session, jsonCT, string(body), &out)
	if code2 != http.StatusCreated || out.Secret == "" || out.Certificate.ClientID != "ussp-"+code+"-01" || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("issue %s: %d %+v", code, code2, out)
	}
	return out
}

func clientToken(t *testing.T, base, client, secret, scope string) (int, string, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {client}, "client_secret": {secret},
		"scope": {scope}, "audience": {"http://localhost:8080"}}.Encode()
	var tok map[string]any
	code, _ := call(t, http.MethodPost, base+"/oauth/token", "", "application/x-www-form-urlencoded", form, &tok)
	s, _ := tok["access_token"].(string)
	return code, s, tok
}

// WP-16 through the real process (A-M4): a certificate issued by an
// admin registers its client, whose token is obtained from the token
// service; the holder's start-of-operations notice is recorded with its
// own token and refused with another holder's; the USSP list is queued
// with the holder; the public register is served without a session,
// without contact or client, and rate-limited; a suspension refuses the
// client's next token request, says until when its earlier tokens run,
// and queues the list without the holder.
func TestIntegrationCertificatesThroughTheProcess(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	const adminPW = "correct horse battery staple"
	if err := os.WriteFile(pwFile, []byte(adminPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", pwFile
	m["AUTHORITY_AUDIENCES"] = "localhost"
	m["CERTIFICATES_REGISTER_PER_MIN"], m["CERTIFICATES_REGISTER_BURST"] = "1", "3"
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("exit %d; last lines of stdout:\n%s", code, stdout.tail(40))
			}
		case <-time.After(20 * time.Second):
			t.Error("api did not stop")
		}
	})
	listen := stdout.waitFor(t, "public listener open", nil)
	base := "http://" + listen["addr"].(string)
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })
	session := adminSession(t, base, adminPW)

	a := issueCert(t, base, session, "AB12")
	b := issueCert(t, base, session, "CD34")
	if !slices.Contains(a.Client.Scopes, "certificates.status") || slices.Contains(a.Client.Scopes, "police.query") {
		t.Fatalf("scopes %v", a.Client.Scopes)
	}
	var problem map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/certificates", session, jsonCT, `{"holder":"ussp","holder_name":"x","code":"AB12",
		"services":["weather"],"base_url":"https://x.example.test","terms_url":"https://x.example.test/t","valid_until":"2030-01-01T00:00:00Z",
		"auth_method":"client_secret_post"}`, &problem); code != http.StatusConflict {
		t.Fatalf("code reused: %d %v", code, problem)
	}

	// The clients are usable: tokens from the token service.
	code, tokA, raw := clientToken(t, base, a.Certificate.ClientID, a.Secret, "certificates.status")
	if code != 200 || tokA == "" {
		t.Fatalf("token %d %v", code, raw)
	}
	_, tokB, _ := clientToken(t, base, b.Certificate.ClientID, b.Secret, "certificates.status")
	notice := `{"state":"started","at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","reference":"OPS-START-1"}`
	statusURL := base + "/v1/certificates/" + a.Certificate.ID + "/status"
	// Another holder's token: refused; a session: refused; the holder's own: recorded.
	if code, _ := call(t, http.MethodPost, statusURL, tokB, jsonCT, notice, &problem); code != http.StatusForbidden ||
		problem["type"] != "https://schemas.uspace.ge/problems/certificate_not_yours" {
		t.Fatalf("another client's notice: %d %v", code, problem)
	}
	if code, _ := call(t, http.MethodPost, statusURL, session, jsonCT, notice, &problem); code != http.StatusForbidden {
		t.Fatalf("a session's notice: %d %v", code, problem)
	}
	var rec map[string]any
	if code, _ := call(t, http.MethodPost, statusURL, tokA, jsonCT, notice, &rec); code != http.StatusCreated ||
		rec["certificate"].(map[string]any)["status"] != "operating" || rec["list_publication"].(map[string]any)["state"] != "queued" {
		t.Fatalf("own notice: %d %v", code, rec)
	}
	if code, _ := call(t, http.MethodPost, statusURL, tokA, jsonCT, notice, &rec); code != http.StatusOK || rec["replayed"] != true {
		t.Fatalf("retried notice: %d %v", code, rec)
	}
	db := storetest.Open(t, u)
	lastList := func() string {
		var p string
		if err := db.QueryRow(`SELECT convert_from(payload, 'UTF8') FROM publications WHERE dataset = 'ussp_list' ORDER BY id DESC LIMIT 1`).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if l := lastList(); !strings.Contains(l, `"ussp_id":"AB12"`) {
		t.Fatalf("list %s", l)
	}

	// The public register: no session, no contact, no client id.
	var reg struct {
		Certificates []map[string]any `json:"certificates"`
	}
	code, hdr := call(t, http.MethodGet, base+"/v1/certificates/register", "", "", "", &reg)
	if code != 200 || len(reg.Certificates) != 2 || !strings.Contains(hdr.Get("Cache-Control"), "max-age=") {
		t.Fatalf("register %d %v", code, reg)
	}
	if s := mustJSON(reg); strings.Contains(s, "ussp-AB12-01") || strings.Contains(s, "ops@") || strings.Contains(s, "client") {
		t.Fatalf("the register carries private data: %s", s)
	}
	limited := false
	for range 5 {
		code, hdr := call(t, http.MethodGet, base+"/v1/certificates/register", "", "", "", nil)
		if code == http.StatusTooManyRequests && hdr.Get("Retry-After") != "" {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the register is not rate-limited")
	}

	// Suspension: the next token request refused, the list without AB12.
	var ch map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/certificates/"+a.Certificate.ID+"/suspend", session, jsonCT, `{"reason":"oversight finding 3"}`, &ch); code != 200 ||
		ch["client_status"] != "suspended" || ch["tokens_valid_until"] == nil || ch["list_publication"].(map[string]any)["state"] != "queued" {
		t.Fatalf("suspend %d %v", code, ch)
	}
	if code, _, raw := clientToken(t, base, a.Certificate.ClientID, a.Secret, "certificates.status"); code != http.StatusUnauthorized || raw["error"] != "invalid_client" {
		t.Fatalf("token after suspension: %d %v", code, raw)
	}
	if l := lastList(); strings.Contains(l, "AB12") {
		t.Fatalf("a suspended USSP is on the list: %s", l)
	}
	// The other holder's client is unaffected.
	if code, tok, _ := clientToken(t, base, b.Certificate.ClientID, b.Secret, "certificates.status"); code != 200 || tok == "" {
		t.Fatalf("the other client: %d", code)
	}
	var detail map[string]any
	if code, _ := call(t, http.MethodGet, base+"/v1/certificates/"+a.Certificate.ID, session, "", "", &detail); code != 200 ||
		detail["client_status"] != "suspended" || len(detail["notices"].([]any)) != 1 {
		t.Fatalf("detail %d %v", code, detail)
	}
	var pub map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/certificates/publish-list", session, "", "", &pub); code != 200 || pub["ussps"] != 0.0 {
		t.Fatalf("publish-list %d %v", code, pub)
	}
	got := countEvents(t, u)
	for et, n := range map[string]int{"certificate_issued": 2, "certificate_notice_recorded": 1, "certificate_status_changed": 1, "oauth_client_created": 2} {
		if got[et] != n {
			t.Errorf("%s: %d events, want %d", et, got[et], n)
		}
	}
	if got["oauth_client_updated"] < 1 || got["publication_queued"] < 3 {
		t.Errorf("events %v", got)
	}
}
