package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// occurrenceBody is the ANSP's occurrence/v1 body (uspace-ansp
// internal/coord MessageOf) with times the database clock accepts.
func occurrenceBody(ref string, awareAgo time.Duration) string {
	now := time.Now().UTC()
	b, _ := json.Marshal(map[string]any{
		"schema": "occurrence/v1", "report_ref": ref, "channel": "mandatory",
		"occurred_at": now.Add(-awareAgo - time.Minute).Format("2006-01-02T15:04:05.000Z"), "became_aware_at": now.Add(-awareAgo).Format("2006-01-02T15:04:05.000Z"),
		"category": "airprox", "reporter": map[string]any{"org": "ussp-AB12-01", "person_ref": "staff-0042"},
		"aircraft": []any{map[string]any{"serial": "TESTSER0001", "operator_reg": "FIN87astrdge12k8-xyz"}},
		"manned":   []any{map[string]any{"icao24": "4ca7b5", "callsign": "TST123"}}, "intent_refs": []any{"2f8343be-6482-4d1b-a474-16847e01af1e"},
		"narrative": "Synthetic airprox between a UAS and a manned aircraft.", "evidence_urls": []any{},
		"reported_at": now.Format("2006-01-02T15:04:05.000Z"),
	})
	return string(b)
}

// A-M3 through the real process (production identity): a USSP's client,
// issued with its certificate, takes a token of scope occurrences.write
// from the token service and posts an occurrence; the same report again
// is the first receipt; a token without the scope and a console session
// are refused. The fake USSP is the certificate's own client.
func TestIntegrationOccurrenceFromAUSSPClientWithItsToken(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	pwFile := filepath.Join(t.TempDir(), "admin.pw")
	const adminPW = "correct horse battery staple"
	if err := os.WriteFile(pwFile, []byte(adminPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", pwFile
	m["AUTHORITY_AUDIENCES"] = "localhost"
	m["OCCURRENCE_KEY_FILE"] = writeKey(t, t.TempDir(), "occurrence.key")
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
	stdout.waitFor(t, "occurrences ready", func(l map[string]any) bool { return l["occurrence_key"] == true })
	base := "http://" + listen["addr"].(string)
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })
	session := adminSession(t, base, adminPW)
	ussp := issueCert(t, base, session, "AB12")

	code, token, tok := clientToken(t, base, ussp.Certificate.ClientID, ussp.Secret, "occurrences.write")
	if code != http.StatusOK || token == "" {
		t.Fatalf("token %d %v", code, tok)
	}
	body := occurrenceBody("USSP-AB12-OCC-0001", time.Hour)
	var rc map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/occurrences", token, jsonCT, body, &rc); code != http.StatusCreated ||
		rc["within_72h"] != true || rc["state"] != "received" || rc["replayed"] != false {
		t.Fatalf("intake %d %v", code, rc)
	}
	var again map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/occurrences", token, jsonCT, body, &again); code != http.StatusOK ||
		again["occurrence_id"] != rc["occurrence_id"] || again["replayed"] != true {
		t.Fatalf("replay %d %v", code, again)
	}
	if strings.Contains(mustJSON(rc), "staff-0042") {
		t.Fatal("the receipt echoes the reporter")
	}
	// The scope is the gate: a token of the same client without it, and
	// a console session, are refused before anything is stored.
	_, other, _ := clientToken(t, base, ussp.Certificate.ClientID, ussp.Secret, "registry.validate")
	var problem map[string]any
	if code, _ := call(t, http.MethodPost, base+"/v1/occurrences", other, jsonCT, occurrenceBody("USSP-AB12-OCC-0002", time.Hour), &problem); code != http.StatusForbidden {
		t.Fatalf("without the scope: %d %v", code, problem)
	}
	if code, _ := call(t, http.MethodPost, base+"/v1/occurrences", session, jsonCT, occurrenceBody("USSP-AB12-OCC-0003", time.Hour), &problem); code != http.StatusForbidden {
		t.Fatalf("a session: %d %v", code, problem)
	}
	// The admin reads no occurrence (incident officers and inspectors do).
	if code, _ := call(t, http.MethodGet, base+"/v1/occurrences", session, "", "", &problem); code != http.StatusForbidden {
		t.Fatalf("admin list: %d %v", code, problem)
	}
	admin := storetest.Open(t, u)
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM occurrences.occurrence_reports WHERE reporter_org = $1`, ussp.Certificate.ClientID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d reports from the client: %v", n, err)
	}
}

// startAPIWithClients is startAPIWithRoles where X-Test-Role
// "client:<id>" is a machine token of <id> granting occurrences.write and
// "client-noscope:<id>" one granting nothing.
func startAPIWithClients(t *testing.T, m map[string]string) (string, *lines) {
	t.Helper()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		role := r.Header.Get("X-Test-Role")
		if id, ok := strings.CutPrefix(role, "client:"); ok {
			return apiserver.Identity{ActorType: "client", Subject: id, Scopes: []string{"occurrences.write"}}, nil
		}
		if id, ok := strings.CutPrefix(role, "client-noscope:"); ok {
			return apiserver.Identity{ActorType: "client", Subject: id}, nil
		}
		return apiserver.Identity{ActorType: "user", Subject: role + "-1", Roles: []string{role}, Realm: "console", Session: true}, nil
	}
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, &stdout, &stderr, env(m)) }()
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
	return "http://" + listen["addr"].(string), &stdout
}

// A-M3 occurrence items through the API: a report from a test USSP; an
// inspector reads it without its reporter and is refused the reporter
// (403); an incident officer reads the reporter with a purpose (audited),
// classifies, analyses and closes it, and exports a de-identified record
// whose hash is the SHA-256 of the content and is recorded; an oversized
// body is 413; a viewer reaches none of it.
func TestIntegrationOccurrencesThroughTheAPI(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	m["OCCURRENCE_KEY_FILE"] = writeKey(t, t.TempDir(), "occurrence.key")
	base, stdout := startAPIWithClients(t, m)
	stdout.waitFor(t, "occurrences ready", func(l map[string]any) bool {
		return l["occurrence_key"] == true && l["role"] == "authority_occurrences" && l["export_format"] == "eccairs-compatible-draft"
	})
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })

	var rc map[string]any
	if code, body := doAs(t, "client:ussp-tst-01", http.MethodPost, base+"/v1/occurrences", jsonCT, occurrenceBody("USSP-TST-OCC-0001", time.Hour), &rc); code != http.StatusCreated {
		t.Fatalf("intake: %d %s", code, body)
	}
	id := rc["occurrence_id"].(string)
	if code, body := doAs(t, "client-noscope:ussp-tst-01", http.MethodPost, base+"/v1/occurrences", jsonCT, occurrenceBody("USSP-TST-OCC-0002", time.Hour), nil); code != http.StatusForbidden {
		t.Fatalf("without the scope: %d %s", code, body)
	}
	if code, body := doAs(t, "client:ussp-tst-01", http.MethodPost, base+"/v1/occurrences", jsonCT, `{"schema":"occurrence/v1"}`, nil); code != http.StatusBadRequest ||
		!strings.Contains(body, "report_ref") {
		t.Fatalf("an incomplete body: %d %s", code, body)
	}
	huge := strings.Replace(occurrenceBody("USSP-TST-OCC-0003", time.Hour), "Synthetic airprox", strings.Repeat("x", 300<<10), 1)
	if code, body := doAs(t, "client:ussp-tst-01", http.MethodPost, base+"/v1/occurrences", jsonCT, huge, nil); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body: %d %.200s", code, body)
	}

	// The inspector reads the report and never its reporter.
	for _, path := range []string{"/v1/occurrences", "/v1/occurrences/" + id} {
		code, body := doAs(t, "inspector", http.MethodGet, base+path, "", "", nil)
		if code != http.StatusOK || !strings.Contains(body, id) {
			t.Fatalf("inspector GET %s: %d %s", path, code, body)
		}
		for _, leak := range []string{"staff-0042", "ussp-tst-01", "USSP-TST-OCC-0001", "person_ref", "reporter_org", "-xyz"} {
			if strings.Contains(body, leak) {
				t.Fatalf("inspector GET %s holds %q: %s", path, leak, body)
			}
		}
	}
	if code, body := doAs(t, "inspector", http.MethodGet, base+"/v1/occurrences/"+id+"/reporter?purpose=enforcement", "", "", nil); code != http.StatusForbidden {
		t.Fatalf("inspector reporter: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodGet, base+"/v1/occurrences/"+id+"/reporter", "", "", nil); code != http.StatusBadRequest {
		t.Fatalf("reporter without a purpose: %d %s", code, body)
	}
	var who map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodGet, base+"/v1/occurrences/"+id+"/reporter?purpose=follow-up+interview", "", "", &who); code != http.StatusOK ||
		who["person_ref"] != "staff-0042" || who["reporter_org"] != "ussp-tst-01" {
		t.Fatalf("reporter: %d %s", code, body)
	}

	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/occurrences/"+id+"/classify", jsonCT, `{"risk_classification":"incident"}`, nil); code != http.StatusForbidden {
		t.Fatalf("inspector classify: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/occurrences/"+id+"/classify", jsonCT, `{"risk_classification":"made_up"}`, nil); code != http.StatusBadRequest ||
		!strings.Contains(body, "serious_incident") {
		t.Fatalf("an unknown class: %d %s", code, body)
	}
	var occ map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/occurrences/"+id+"/classify", jsonCT, `{"risk_classification":"incident"}`, &occ); code != http.StatusOK ||
		occ["state"] != "classified" {
		t.Fatalf("classify: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPatch, base+"/v1/occurrences/"+id+"/analysis", jsonCT,
		`{"analysis":"Loss of separation below 200 m.","follow_up":"Safety notice to operators.","state":"analysed"}`, &occ); code != http.StatusOK || occ["state"] != "analysed" {
		t.Fatalf("analysis: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPatch, base+"/v1/occurrences/"+id+"/analysis", jsonCT, `{"state":"closed"}`, &occ); code != http.StatusOK || occ["state"] != "closed" {
		t.Fatalf("close: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPatch, base+"/v1/occurrences/"+id+"/analysis", jsonCT, `{"follow_up":"more"}`, nil); code != http.StatusConflict ||
		!strings.Contains(body, "occurrence_closed") {
		t.Fatalf("change a closed report: %d %s", code, body)
	}

	window := `"from":"` + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `","to":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"`
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/occurrences/export", jsonCT, `{`+window+`}`, nil); code != http.StatusForbidden {
		t.Fatalf("inspector export: %d %s", code, body)
	}
	var ex map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/occurrences/export", jsonCT, `{`+window+`}`, &ex); code != http.StatusCreated ||
		ex["format"] != "eccairs-compatible-draft" || ex["record_count"] != 1.0 {
		t.Fatalf("export: %d %s", code, body)
	}
	content := ex["content"].(string)
	sum := sha256.Sum256([]byte(content))
	if h := "sha256:" + hex.EncodeToString(sum[:]); h != ex["content_hash"] {
		t.Fatalf("content hashes to %s, the export says %v", h, ex["content_hash"])
	}
	for _, leak := range []string{"staff-0042", "ussp-tst-01", "USSP-TST-OCC", "-xyz", "Loss of separation"} {
		if strings.Contains(content, leak) {
			t.Fatalf("the export holds %q", leak)
		}
	}
	if !strings.Contains(content, `"operator_registration": "FIN87astrdge12k8"`) || !strings.Contains(content, `"serial_number": "TESTSER0001"`) {
		t.Fatalf("the export lost the aircraft:\n%s", content)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/occurrences/export", jsonCT, `{`+window+`,"format":"e5x"}`, nil); code != http.StatusBadRequest ||
		!strings.Contains(body, "unknown_export_format") {
		t.Fatalf("an unknown format: %d %s", code, body)
	}
	for _, path := range []string{"/v1/occurrences", "/v1/occurrences/" + id, "/v1/occurrences/" + id + "/reporter?purpose=x"} {
		if code, _ := doAs(t, "viewer", http.MethodGet, base+path, "", "", nil); code != http.StatusForbidden {
			t.Fatalf("viewer GET %s: %d", path, code)
		}
	}

	admin := storetest.Open(t, u)
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM events WHERE event_type = 'occurrence_reporter_viewed' AND purpose = 'follow-up interview'
		AND actor_id = 'incident_officer-1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d reporter reads audited: %v", n, err)
	}
	if err := admin.QueryRow(`SELECT count(*) FROM occurrences.deidentified_exports WHERE content_hash = $1`, ex["content_hash"]).Scan(&n); err != nil || n != 1 {
		t.Fatalf("export recorded %d: %v", n, err)
	}
}

// E-02: without OCCURRENCE_KEY_FILE the process starts and says so; a
// report carrying a reporter reference is 503 and nothing is stored, and
// one without is received.
func TestIntegrationOccurrencesWithoutTheKey(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	base, stdout := startAPIWithClients(t, baseEnv(t, u))
	stdout.waitFor(t, "occurrence reports carrying a reporter reference are refused (503 occurrence_key_unavailable) until OCCURRENCE_KEY_FILE is configured", nil)
	stdout.waitFor(t, "occurrences ready", func(l map[string]any) bool { return l["occurrence_key"] == false })
	code, body := doAs(t, "client:ansp-01", http.MethodPost, base+"/v1/occurrences", jsonCT, occurrenceBody("ANSP-OCC-2026-0001", time.Hour), nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "occurrence_key_unavailable") {
		t.Fatalf("with a reference: %d %s", code, body)
	}
	anon := strings.Replace(occurrenceBody("ANSP-OCC-2026-0002", time.Hour), `,"person_ref":"staff-0042"`, "", 1)
	if code, body := doAs(t, "client:ansp-01", http.MethodPost, base+"/v1/occurrences", jsonCT, anon, nil); code != http.StatusCreated {
		t.Fatalf("without a reference: %d %s", code, body)
	}
	var n int
	if err := storetest.Open(t, u).QueryRow(`SELECT count(*) FROM occurrences.occurrence_reports`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d stored: %v", n, err)
	}
}

// E-02: an occurrence key that is the PII key stops the start and names
// the variable.
func TestIntegrationOccurrenceKeyEqualToThePIIKeyStopsTheStart(t *testing.T) {
	m := baseEnv(t, storetest.Migrated(t, migrate.Relational))
	m["OCCURRENCE_KEY_FILE"] = m["PII_KEY_FILE"]
	var stdout, stderr lines
	code := proc.Main(context.Background(), spec(&config.API{}), nil, &stdout, &stderr, env(m))
	if code != proc.ExitFailed || stdout.find("process failed", func(l map[string]any) bool {
		return strings.Contains(l["error"].(string), "OCCURRENCE_KEY_FILE")
	}) == nil {
		t.Fatalf("exit %d:\n%s", code, stdout.tail(20))
	}
}
