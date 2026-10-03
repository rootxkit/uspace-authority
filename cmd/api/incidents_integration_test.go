package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// startAPIWithRoles runs the api process on m with the test identity (the role
// in X-Test-Role) and returns its base URL and its stdout.
func startAPIWithRoles(t *testing.T, m map[string]string) (string, *lines) {
	t.Helper()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		role := r.Header.Get("X-Test-Role")
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

// A-M3 through the API: an incident opened from a notice, assigned and
// noted; an oversight pack built by an incident officer, a legal one
// refused to them and built by an inspector; the manifest read, the
// archive downloaded with a purpose (its hash in the header is its
// SHA-256), the pack verified. A viewer reaches none of it.
func TestIntegrationIncidentsAndEvidencePacksThroughTheAPI(t *testing.T) {
	m := baseEnv(t, storetest.Migrated(t, migrate.Relational))
	m["EVIDENCE_DIR"] = t.TempDir()
	base, stdout := startAPIWithRoles(t, m)
	stdout.waitFor(t, "USSP service records are unavailable in evidence packs until a client secret is configured", nil)
	stdout.waitFor(t, "evidence packs ready", func(l map[string]any) bool {
		return l["storage"] == true && l["signing_kid"] != "" && l["records_client"] == false
	})

	now := time.Now().UTC()
	open := `{"kind":"airprox","occurred_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","opened_from":"ansp_notice",` +
		`"notice_ref":"ANSP-TEST-1","severity":"warning","aircraft":[{"serial":"TESTAPI0001","operator_reg":"FIN87astrdge12k8-xyz"}]}`
	if code, body := doAs(t, "viewer", http.MethodPost, base+"/v1/incidents", "application/json", open, nil); code != http.StatusForbidden {
		t.Fatalf("viewer: %d %s", code, body)
	}
	var inc map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/incidents", "application/json", open, &inc); code != http.StatusCreated {
		t.Fatalf("open: %d %s", code, body)
	}
	id := inc["incident_id"].(string)
	if reg := inc["aircraft"].([]any)[0].(map[string]any)["operator_reg"]; reg != "FIN87astrdge12k8" {
		t.Fatalf("stored registration %v", reg)
	}
	if code, body := doAs(t, "inspector", http.MethodPatch, base+"/v1/incidents/"+id, "application/json",
		`{"status":"assigned","assignee":"inspector-1","note":"called the ANSP"}`, &inc); code != http.StatusOK || inc["status"] != "assigned" {
		t.Fatalf("patch: %d %s", code, body)
	}
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/incidents", "application/json",
		strings.Replace(open, "ansp_notice", "violation", 1), nil); code != http.StatusBadRequest || !strings.Contains(body, "opened_from") {
		t.Fatalf("opened from a violation by hand: %d %s", code, body)
	}

	window := `"from":"` + now.Add(-2*time.Hour).Format(time.RFC3339) + `","to":"` + now.Format(time.RFC3339) + `"`
	var pack map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/incidents/"+id+"/evidence-packs", "application/json",
		`{"kind":"oversight",`+window+`,"purpose":"review"}`, &pack); code != http.StatusCreated {
		t.Fatalf("oversight pack: %d %s", code, body)
	}
	if code, body := doAs(t, "incident_officer", http.MethodPost, base+"/v1/incidents/"+id+"/evidence-packs", "application/json",
		`{"kind":"legal",`+window+`,"purpose":"court","case_ref":"CASE-TEST-1"}`, nil); code != http.StatusForbidden {
		t.Fatalf("legal pack by an incident officer: %d %s", code, body)
	}
	var legal map[string]any
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/incidents/"+id+"/evidence-packs", "application/json",
		`{"kind":"legal",`+window+`,"purpose":"court","case_ref":"CASE-TEST-1"}`, &legal); code != http.StatusCreated {
		t.Fatalf("legal pack: %d %s", code, body)
	}
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/incidents/"+id+"/evidence-packs", "application/json",
		`{"kind":"oversight","from":"`+now.Add(-30*time.Hour).Format(time.RFC3339)+`","to":"`+now.Format(time.RFC3339)+`","purpose":"r"}`, nil); code != http.StatusBadRequest || !strings.Contains(body, "window_too_large") {
		t.Fatalf("a long window: %d %s", code, body)
	}
	packID := pack["pack_id"].(string)
	if sig, _ := pack["signature"].(string); sig == "" || pack["signature_kid"] == nil {
		t.Fatalf("the pack is unsigned with a publication key configured: %v", pack)
	}
	var got map[string]any
	if code, body := doAs(t, "inspector", http.MethodGet, base+"/v1/incidents/"+id+"/evidence-packs/"+packID, "", "", &got); code != http.StatusOK || got["content_hash"] != pack["content_hash"] {
		t.Fatalf("manifest: %d %s", code, body)
	}

	// Download: without a purpose refused; with one, the archive whose
	// hash is the header and the recorded content_hash.
	if code, body := doAs(t, "inspector", http.MethodGet, base+"/v1/incidents/"+id+"/evidence-packs/"+packID+"/download", "", "", nil); code != http.StatusBadRequest {
		t.Fatalf("download without a purpose: %d %s", code, body)
	}
	req, err := http.NewRequest(http.MethodGet, base+"/v1/incidents/"+id+"/evidence-packs/"+packID+"/download?purpose=court+request", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-Role", "incident_officer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/zip" {
		t.Fatalf("download: %d %v", resp.StatusCode, err)
	}
	sum := sha256.Sum256(data)
	if h := "sha256:" + hex.EncodeToString(sum[:]); h != pack["content_hash"] || resp.Header.Get("X-Content-SHA256") != h ||
		resp.Header.Get("X-Evidence-Signature") != pack["signature"] {
		t.Fatalf("downloaded %s, recorded %v, header %s", h, pack["content_hash"], resp.Header.Get("X-Content-SHA256"))
	}
	// A legal pack is not served to an incident officer.
	if code, body := doAs(t, "incident_officer", http.MethodGet, base+"/v1/incidents/"+id+"/evidence-packs/"+legal["pack_id"].(string)+"/download?purpose=x", "", "", nil); code != http.StatusForbidden {
		t.Fatalf("legal download by an incident officer: %d %s", code, body)
	}
	var v map[string]any
	if code, body := doAs(t, "incident_officer", http.MethodGet, base+"/v1/incidents/"+id+"/evidence-packs/"+packID+"/verify", "", "", &v); code != http.StatusOK ||
		v["hash_matches"] != true || v["signature"] != "verified" {
		t.Fatalf("verify: %d %s", code, body)
	}
	var page map[string]any
	if code, body := doAs(t, "inspector", http.MethodGet, base+"/v1/incidents?status=assigned", "", "", &page); code != http.StatusOK ||
		len(page["incidents"].([]any)) != 1 {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, body := doAs(t, "inspector", http.MethodGet, base+"/v1/incidents/"+id, "", "", &inc); code != http.StatusOK ||
		len(inc["evidence_packs"].([]any)) != 2 || len(inc["notes"].([]any)) != 1 {
		t.Fatalf("incident: %d %s", code, body)
	}
	for _, path := range []string{"/v1/incidents", "/v1/incidents/" + id, "/v1/incidents/" + id + "/evidence-packs/" + packID + "/verify"} {
		if code, _ := doAs(t, "viewer", http.MethodGet, base+path, "", "", nil); code != http.StatusForbidden {
			t.Fatalf("viewer GET %s: %d", path, code)
		}
	}
}

// E-02: without EVIDENCE_DIR the process starts, says so, and refuses a
// pack with 503 evidence_storage_unavailable; the case files work.
func TestIntegrationEvidenceRefusedWithoutStorage(t *testing.T) {
	m := baseEnv(t, storetest.Migrated(t, migrate.Relational))
	base, stdout := startAPIWithRoles(t, m)
	stdout.waitFor(t, "evidence packs are refused (503 evidence_storage_unavailable) until EVIDENCE_DIR is configured", nil)
	stdout.waitFor(t, "evidence packs ready", func(l map[string]any) bool { return l["storage"] == false })
	var inc map[string]any
	now := time.Now().UTC()
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/incidents", "application/json",
		`{"kind":"other","occurred_at":"`+now.Format(time.RFC3339)+`","opened_from":"own_observation","severity":"info"}`, &inc); code != http.StatusCreated {
		t.Fatalf("open: %d %s", code, body)
	}
	code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/incidents/"+inc["incident_id"].(string)+"/evidence-packs", "application/json",
		`{"kind":"oversight","from":"`+now.Add(-time.Hour).Format(time.RFC3339)+`","to":"`+now.Format(time.RFC3339)+`","purpose":"r"}`, nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "evidence_storage_unavailable") {
		t.Fatalf("pack without storage: %d %s", code, body)
	}
}
