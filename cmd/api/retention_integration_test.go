package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// WP-27 through the real process: the jobs run at start and print their
// success line with numbers (E-02); GET /v1/audit/verify verifies a
// month and records it; the legal holds are placed and released by the
// roles x-roles names and refused to the others (fail closed); the
// status reads the ledgers with the periods pending GCAA.
func TestIntegrationRetentionThroughTheAPI(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	identify := func(r *http.Request) (apiserver.Identity, error) {
		role := r.Header.Get("X-Test-Role")
		return apiserver.Identity{ActorType: "user", Subject: role + "-1", Roles: []string{role}, Realm: "console", Session: true}, nil
	}
	e := baseEnv(t, u)
	dir := t.TempDir()
	e["ARCHIVE_URL"] = "file://" + filepath.ToSlash(dir)
	if runtime.GOOS == "windows" {
		e["ARCHIVE_URL"] = "file:///" + filepath.ToSlash(dir)
	}
	e["RETENTION_TICK_S"] = "1"
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, &stdout, &stderr, env(e)) }()
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
	base := "http://" + listen["addr"].(string)
	call := func(role, method, path, body string, out any) int {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-Role", role)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}

	// The jobs ran at start, each with its numbers.
	for _, job := range []string{"retention", "audit_verify", "ussp_records"} {
		stdout.waitFor(t, "job run finished", func(m map[string]any) bool { return m["job"] == job && m["summary"] != nil })
	}

	month := time.Now().UTC().Format("2006-01")
	var v map[string]any
	if code := call("auditor", http.MethodGet, "/v1/audit/verify?month="+month, "", &v); code != http.StatusOK || v["intact"] != true ||
		v["rows"].(float64) < 1 || v["month"] != month {
		t.Fatalf("verify: %d %v", code, v)
	}
	if code := call("auditor", http.MethodGet, "/v1/audit/verify?month=2026-13", "", nil); code != http.StatusBadRequest {
		t.Fatalf("a malformed month: %d", code)
	}
	if code := call("viewer", http.MethodGet, "/v1/audit/verify?month="+month, "", nil); code != http.StatusForbidden {
		t.Fatalf("a viewer verifies: %d", code)
	}

	hold := `{"case_ref": "CASE-API", "reason": "court order", "track_ids": ["track-a"]}`
	if code := call("auditor", http.MethodPost, "/v1/retention/holds", hold, nil); code != http.StatusForbidden {
		t.Fatalf("an auditor places a hold: %d", code)
	}
	var problem map[string]any
	if code := call("incident_officer", http.MethodPost, "/v1/retention/holds", `{"case_ref": "C", "reason": "r"}`, &problem); code != http.StatusBadRequest ||
		!strings.Contains(mustJSON(problem["errors"]), "window_from") {
		t.Fatalf("an empty hold: %d %v", code, problem)
	}
	var placed map[string]any
	if code := call("incident_officer", http.MethodPost, "/v1/retention/holds", hold, &placed); code != http.StatusCreated || placed["active"] != true {
		t.Fatalf("place: %d %v", code, placed)
	}
	id := placed["hold_id"].(string)
	var page map[string]any
	if code := call("auditor", http.MethodGet, "/v1/retention/holds", "", &page); code != http.StatusOK || len(page["holds"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, page)
	}
	var released map[string]any
	if code := call("incident_officer", http.MethodPost, "/v1/retention/holds/"+id+"/release", `{"reason": "case closed"}`, &released); code != http.StatusOK ||
		released["active"] != false || released["released_by"] != "incident_officer-1" {
		t.Fatalf("release: %d %v", code, released)
	}
	if code := call("incident_officer", http.MethodPost, "/v1/retention/holds/"+id+"/release", `{"reason": "again"}`, nil); code != http.StatusConflict {
		t.Fatalf("a second release: %d", code)
	}

	var st map[string]any
	if code := call("viewer", http.MethodGet, "/v1/retention/status", "", nil); code != http.StatusForbidden {
		t.Fatalf("a viewer reads the status: %d", code)
	}
	if code := call("admin", http.MethodGet, "/v1/retention/status", "", &st); code != http.StatusOK {
		t.Fatalf("status: %d %v", code, st)
	}
	periods := st["periods"].(map[string]any)
	if periods["pending_gcaa"] != true || periods["online_days"] != 90.0 || periods["audit_years"] != 10.0 || !strings.HasPrefix(periods["archive_store"].(string), "file://") {
		t.Fatalf("periods %v", periods)
	}
	jobs := map[string]string{}
	for _, j := range st["jobs"].([]any) {
		m := j.(map[string]any)
		outcome, _ := m["outcome"].(string)
		jobs[m["job"].(string)] = outcome
	}
	if jobs["retention"] != "ok" || jobs["audit_verify"] != "ok" || jobs["ussp_records"] != "ok" || jobs["evidence_verify"] == "" {
		t.Fatalf("jobs %v", jobs)
	}
}
