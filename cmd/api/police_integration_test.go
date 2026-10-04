package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// client is a caller of the real process: a bearer and the address the
// trusted proxy says the request came from.
type client struct {
	t      *testing.T
	base   string
	bearer string
	from   string
}

func (c client) call(method, path, body string, out any) (int, http.Header, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.from != "" {
		req.Header.Set("X-Forwarded-For", c.from)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/") &&
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "application/zip") {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, resp.Header, raw
}

// signIn runs the password and the TOTP steps (enrolling at the first
// sign-in) and returns the session token.
func (c client) signIn(username, password string) string {
	c.t.Helper()
	var ch struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment struct {
			Secret string `json:"secret"`
		} `json:"enrolment"`
	}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	if code, _, raw := c.call(http.MethodPost, "/v1/auth/login", string(body), &ch); code != http.StatusOK {
		c.t.Fatalf("login %s: %d %s", username, code, raw)
	}
	code, err := totp.GenerateCode(ch.Enrolment.Secret, time.Now())
	if err != nil {
		c.t.Fatal(err)
	}
	var sess struct {
		Token string `json:"token"`
	}
	if status, _, raw := c.call(http.MethodPost, "/v1/auth/mfa", `{"mfa_token":"`+ch.MFAToken+`","code":"`+code+`"}`, &sess); status != http.StatusOK {
		c.t.Fatalf("mfa %s: %d %s", username, status, raw)
	}
	return sess.Token
}

func eventCount(t *testing.T, u, eventType string) int {
	t.Helper()
	return countEvents(t, u)[eventType]
}

// A-M4 police item, end to end through the real process and its real
// sign-in: an admin creates a police account of an agency with an IP
// allow-list (the client address read behind the trusted proxy); its
// sign-in from outside the list is refused, from inside it opens a
// police session. Every query names a purpose and a case reference and
// is exactly one police_queries row and one police_query events row;
// a status-only purpose answers without the operator's identity, a
// personal-data purpose with it; a console session (even an admin's) is
// refused on the police routes and the police session on the console's;
// an export of an area builds a legal pack whose download hash is its
// content_hash; the DPO report lists the queries and the personal-data
// reads with their case reference.
func TestIntegrationPoliceRealmEndToEnd(t *testing.T) {
	pgURL := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, pgURL)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	const pw = "correct horse battery staple"
	if err := os.WriteFile(pwFile, []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", pwFile
	m["AUTHORITY_TRUSTED_PROXIES"] = "127.0.0.1/32,::1/128"
	m["EVIDENCE_DIR"] = t.TempDir()
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("exit %d; last lines of stdout:\n%s\nstderr:\n%s", code, stdout.tail(40), stderr.tail(40))
			}
		case <-time.After(20 * time.Second):
			t.Error("api did not stop")
		}
	})
	listen := stdout.waitFor(t, "public listener open", nil)
	stdout.waitFor(t, "police realm ready", nil)
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })
	base := "http://" + listen["addr"].(string)
	const inside, outside = "192.0.2.5", "198.51.100.7"

	admin := client{t: t, base: base, from: inside}
	admin.bearer = admin.signIn("admin", pw)
	for _, u := range []string{
		`{"username":"registrar","password":"` + pw + `","roles":["registrar"],"realm":"console"}`,
		`{"username":"officer.one","password":"` + pw + `","roles":["police.query"],"realm":"police","agency":"TEST-POLICE","ip_allowlist":["192.0.2.0/24"]}`,
	} {
		if code, _, raw := admin.call(http.MethodPost, "/v1/users", u, nil); code != http.StatusCreated {
			t.Fatalf("create user: %d %s", code, raw)
		}
	}
	// A police account without an allow-list does not exist.
	if code, _, raw := admin.call(http.MethodPost, "/v1/users", `{"username":"officer.two","password":"`+pw+`","roles":["police.query"],"realm":"police","agency":"TEST-POLICE"}`, nil); code != http.StatusBadRequest || !strings.Contains(string(raw), "ip_allowlist") {
		t.Fatalf("no allow-list: %d %s", code, raw)
	}
	reg := client{t: t, base: base, from: inside}
	reg.bearer = reg.signIn("registrar", pw)
	var op map[string]any
	if code, _, raw := reg.call(http.MethodPost, "/v1/registry/operators", `{"operator_type":"legal","registration_number":"GEOTEST00000001",
		"legal_name":"Test Aerial LLC","legal_identification_number":"TEST-404000001","postal_address":"2 Test Avenue",
		"contact_email":"ops@example.test","contact_phone":"+995 555 000 002","valid_until":"2030-01-01T00:00:00Z"}`, &op); code != http.StatusCreated {
		t.Fatalf("operator: %d %s", code, raw)
	}
	if code, _, raw := reg.call(http.MethodPost, "/v1/registry/uas", `{"operator_id":"`+op["id"].(string)+`","serial":"TESTA0123456789","class_label":"C1","rid_capability":"direct"}`, nil); code != http.StatusCreated {
		t.Fatalf("uas: %d %s", code, raw)
	}
	ts := storetest.Open(t, m["TS_URL"])
	for i := range 3 {
		if _, err := ts.Exec(`INSERT INTO tracks (captured_at, track_id, dedupe_key, msg_id, rx_ts, time_source, backlog, source,
			source_instance, trust, lat_deg, lon_deg, alt_amsl_m, alt_source, emergency, ident_status, ident_reason, ident_mismatch,
			ident_basis, serial, operator_reg)
			VALUES (now() - make_interval(secs => $1), 'TRACK-E2E-1', $2, $2, now(), 'broadcast', false, 'direct_rid', 'rx-e2e', 'broadcast',
			        41.70, 44.80, 600, 'geodetic', false, 'registered', 'matched', false, 'as_broadcast', 'TESTA0123456789', 'GEOTEST00000001')`,
			float64(3-i), "e2e-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}

	// Sign-in from outside the allow-list: the answer of a wrong password.
	off := client{t: t, base: base, from: outside}
	if code, _, raw := off.call(http.MethodPost, "/v1/auth/login", `{"username":"officer.one","password":"`+pw+`"}`, nil); code != http.StatusUnauthorized ||
		!strings.Contains(string(raw), "invalid_credentials") {
		t.Fatalf("login from outside: %d %s", code, raw)
	}
	police := client{t: t, base: base, from: inside}
	police.bearer = police.signIn("officer.one", pw)

	q := url.Values{"bbox": {"44.7,41.6,44.9,41.8"}, "case_ref": {"CASE-E2E-1"}}
	q.Set("purpose", "public_order")
	var plain map[string]any
	if code, _, raw := police.call(http.MethodGet, "/v1/police/aircraft?"+q.Encode(), "", &plain); code != http.StatusOK {
		t.Fatalf("aircraft: %d %s", code, raw)
	}
	ac := plain["aircraft"].([]any)
	if len(ac) != 1 || ac[0].(map[string]any)["operator"] != nil || ac[0].(map[string]any)["registration_number"] != "GEOTEST00000001" ||
		plain["pii_released"] != false {
		t.Fatalf("status-only answer %v", plain)
	}
	q.Set("purpose", "criminal_investigation")
	q.Set("case_ref", "CASE-E2E-2")
	var withPII map[string]any
	if code, _, raw := police.call(http.MethodGet, "/v1/police/aircraft?"+q.Encode(), "", &withPII); code != http.StatusOK {
		t.Fatalf("aircraft with a personal-data purpose: %d %s", code, raw)
	}
	if id := withPII["aircraft"].([]any)[0].(map[string]any)["operator"].(map[string]any); id["legal_name"] != "Test Aerial LLC" ||
		id["contact_phone"] != "+995 555 000 002" || id["legal_identification_number"] != nil {
		t.Fatalf("identity %v", id)
	}
	// E-01 pairs: without a purpose, a console admin, the police on a
	// console route, a valid police session from outside the list.
	q.Del("purpose")
	if code, _, _ := police.call(http.MethodGet, "/v1/police/aircraft?"+q.Encode(), "", nil); code != http.StatusBadRequest {
		t.Fatalf("no purpose: %d", code)
	}
	q.Set("purpose", "public_order")
	if code, _, _ := admin.call(http.MethodGet, "/v1/police/aircraft?"+q.Encode(), "", nil); code != http.StatusForbidden {
		t.Fatalf("console admin on a police route: %d", code)
	}
	if code, _, _ := police.call(http.MethodGet, "/v1/users", "", nil); code != http.StatusForbidden {
		t.Fatalf("police on a console route: %d", code)
	}
	moved := client{t: t, base: base, bearer: police.bearer, from: outside}
	if code, _, raw := moved.call(http.MethodGet, "/v1/police/aircraft?"+q.Encode(), "", nil); code != http.StatusForbidden ||
		!strings.Contains(string(raw), "address_not_allowed") {
		t.Fatalf("a police session from outside: %d %s", code, raw)
	}
	var sn map[string]any
	if code, _, raw := police.call(http.MethodGet, "/v1/police/serials/TESTA0123456789?purpose=public_order&case_ref=CASE-E2E-3", "", &sn); code != http.StatusOK ||
		sn["operator"].(map[string]any)["registration_number"] != "GEOTEST00000001" || sn["identity"] != nil {
		t.Fatalf("serial: %d %s", code, raw)
	}
	var opAns map[string]any
	if code, _, raw := police.call(http.MethodGet, "/v1/police/operators/GEOTEST00000001?purpose=criminal_investigation&case_ref=CASE-E2E-4", "", &opAns); code != http.StatusOK ||
		len(opAns["fleet"].([]any)) != 1 || opAns["identity"].(map[string]any)["legal_name"] != "Test Aerial LLC" {
		t.Fatalf("operator: %d %s", code, raw)
	}

	// An export of the area: an incident opened, a legal pack sealed;
	// its download is the archive whose hash is content_hash.
	now := time.Now().UTC()
	exp := `{"purpose":"criminal_investigation","case_ref":"CASE-E2E-5","from":"` + now.Add(-time.Hour).Format(time.RFC3339) +
		`","to":"` + now.Add(time.Minute).Format(time.RFC3339) + `","query":{"bbox":"44.7,41.6,44.9,41.8"}}`
	if code, _, raw := police.call(http.MethodPost, "/v1/police/exports", strings.Replace(exp, "criminal_investigation", "public_order", 1), nil); code != http.StatusForbidden ||
		!strings.Contains(string(raw), "purpose_not_pii") {
		t.Fatalf("export with a status-only purpose: %d %s", code, raw)
	}
	var pack map[string]any
	if code, _, raw := police.call(http.MethodPost, "/v1/police/exports", exp, &pack); code != http.StatusCreated || pack["incident_opened"] != true {
		t.Fatalf("export: %d %s", code, raw)
	}
	code, hdr, data := police.call(http.MethodGet, pack["download"].(string)+"?purpose=criminal_investigation&case_ref=CASE-E2E-5", "", nil)
	sum := sha256.Sum256(data)
	if code != http.StatusOK || "sha256:"+hex.EncodeToString(sum[:]) != pack["content_hash"] || hdr.Get("X-Content-SHA256") != pack["content_hash"] {
		t.Fatalf("download: %d %v %s", code, pack["content_hash"], hdr.Get("X-Content-SHA256"))
	}

	// The record: one police_queries row and one police_query events row
	// per answered query (two aircraft, a serial, an operator, an export,
	// a download).
	db := storetest.Open(t, pgURL)
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM police_queries`).Scan(&rows); err != nil || rows != 6 {
		t.Fatalf("%d police_queries rows %v", rows, err)
	}
	if n := eventCount(t, pgURL, "police_query"); n != 6 {
		t.Fatalf("%d police_query rows", n)
	}
	if n := eventCount(t, pgURL, "police_query_refused"); n != 1 {
		t.Fatalf("%d refusals", n)
	}
	var agency, ip string
	if err := db.QueryRow(`SELECT agency, remote_ip FROM police_queries WHERE case_ref = 'CASE-E2E-1'`).Scan(&agency, &ip); err != nil ||
		agency != "TEST-POLICE" || ip != inside {
		t.Fatalf("row %s %s %v", agency, ip, err)
	}

	var rep map[string]any
	if code, _, raw := admin.call(http.MethodGet, "/v1/audit/dpo-report?month="+now.Format("2006-01"), "", &rep); code != http.StatusOK {
		t.Fatalf("dpo report: %d %s", code, raw)
	}
	if n := len(rep["police_queries"].([]any)); n != 6 {
		t.Fatalf("report lists %d police queries", n)
	}
	cases := map[string]bool{}
	for _, v := range rep["pii_views"].([]any) {
		row := v.(map[string]any)
		if c, ok := row["case_ref"].(string); ok {
			cases[row["event_type"].(string)+" "+c] = true
		}
	}
	for _, want := range []string{"registry_pii_viewed CASE-E2E-2", "registry_pii_viewed CASE-E2E-4", "evidence_pack_built CASE-E2E-5",
		"evidence_pack_downloaded CASE-E2E-5"} {
		if !cases[want] {
			t.Errorf("the report has no %s (has %v)", want, cases)
		}
	}
	if code, _, _ := police.call(http.MethodGet, "/v1/audit/dpo-report?month="+now.Format("2006-01"), "", nil); code != http.StatusForbidden {
		t.Fatalf("police read the DPO report: %d", code)
	}
}
