package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// lines is a goroutine-safe stdout that the test reads JSON lines from.
type lines struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// find returns the last log line with msg for which ok holds.
func (l *lines) find(msg string, ok func(map[string]any) bool) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found map[string]any
	sc := bufio.NewScanner(bytes.NewReader(l.b.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["msg"] == msg && (ok == nil || ok(m)) {
			found = m
		}
	}
	return found
}

func (l *lines) waitFor(t *testing.T, msg string, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m := l.find(msg, ok); m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("no %q line; stdout:\n%s", msg, l.b.String())
	return nil
}

func env(m map[string]string) config.LookupFunc {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// baseEnv is a working configuration on pgURL with two token keys and
// the PII and registry hash keys generated at run time (spec 06 §4) in
// the test's directory.
func baseEnv(t *testing.T, pgURL string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"PG_URL": pgURL, "TS_URL": "postgres://unused:unused@127.0.0.1:1/unused",
		"REGISTRY_HASH_KEY_FILE": writeKey(t, dir, "registry-hash.key"),
		"NATS_URL":               "nats://127.0.0.1:1", "AUTHORITY_PUBLIC_URL": "http://localhost:8080",
		"API_ADDR": "127.0.0.1:0", "ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1",
		"POLICY_REFRESH_S": "1", "SHUTDOWN_TIMEOUT_S": "5", "AUTHORITY_MTLS_MODE": "off",
		"SIGNING_KEY_FILES":    tokentest.WriteKey(t, dir, 0) + "," + tokentest.WriteKey(t, dir, 1),
		"PUBLICATION_KEY_FILE": tokentest.WriteKey(t, dir, 9),
		"PII_KEY_FILE":         writePIIKey(t, dir),
	}
}

func do(t *testing.T, method, url, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// The /v1/policy round trip through the real process: create, activate,
// read back; the activation and the read of the log are events; and the
// status line of api, which follows the policy, moves from version 1 to
// version 2.
func TestIntegrationPolicyRoundTripAndStatusLine(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	identify := func(*http.Request) (apiserver.Identity, error) {
		return apiserver.Identity{ActorType: "user", Subject: "admin-1", Roles: []string{apiserver.RoleAdmin}, Realm: "console", Session: true}, nil
	}
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() {
		exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, &stdout, &stderr, env(baseEnv(t, u)))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("exit %d", code)
			}
		case <-time.After(20 * time.Second):
			t.Error("api did not stop")
		}
	})

	listen := stdout.waitFor(t, "public listener open", nil)
	base := "http://" + listen["addr"].(string)
	hasVersion := func(v float64) func(map[string]any) bool {
		return func(m map[string]any) bool { return m["policy_version"] == v }
	}
	stdout.waitFor(t, "status", hasVersion(1))

	var active map[string]any
	if code := do(t, http.MethodGet, base+"/v1/policy", "", &active); code != http.StatusOK || active["version"] != 1.0 || active["height_limit_agl_m"] != 120.0 {
		t.Fatalf("GET: %d %v", code, active)
	}
	body, _ := json.Marshal(active)
	in := map[string]any{}
	_ = json.Unmarshal(body, &in)
	for _, k := range []string{"version", "active", "created_at", "created_by", "activated_at", "activated_by"} {
		delete(in, k)
	}
	in["height_limit_agl_m"], in["note"] = 100, "trial"
	body, _ = json.Marshal(in)

	var created map[string]any
	if code := do(t, http.MethodPost, base+"/v1/policy", string(body), &created); code != http.StatusCreated || created["version"] != 2.0 || created["active"] != false {
		t.Fatalf("POST: %d %v", code, created)
	}
	var activated map[string]any
	if code := do(t, http.MethodPost, base+"/v1/policy/2/activate", "", &activated); code != http.StatusOK || activated["active"] != true {
		t.Fatalf("activate: %d %v", code, activated)
	}
	if code := do(t, http.MethodGet, base+"/v1/policy", "", &active); code != http.StatusOK || active["version"] != 2.0 || active["height_limit_agl_m"] != 100.0 {
		t.Fatalf("GET after: %d %v", code, active)
	}
	// E-01 pair: activating the older version again is refused.
	var problem map[string]any
	if code := do(t, http.MethodPost, base+"/v1/policy/1/activate", "", &problem); code != http.StatusConflict {
		t.Fatalf("re-activate 1: %d %v", code, problem)
	}
	// A refused threshold names the field.
	in["clear_after_s"] = 0
	body, _ = json.Marshal(in)
	if code := do(t, http.MethodPost, base+"/v1/policy", string(body), &problem); code != http.StatusBadRequest ||
		!strings.Contains(mustJSON(problem["errors"]), "clear_after_s") {
		t.Fatalf("invalid POST: %d %v", code, problem)
	}

	stdout.waitFor(t, "status", hasVersion(2))

	var page struct {
		Events []map[string]any `json:"events"`
	}
	if code := do(t, http.MethodGet, base+"/v1/audit/events?entity_type=authority_policy&purpose=review", "", &page); code != http.StatusOK || len(page.Events) != 2 ||
		page.Events[0]["event_type"] != "policy_activated" || page.Events[0]["actor_id"] != "admin-1" {
		t.Fatalf("audit: %d %v", code, page)
	}
	if code := do(t, http.MethodGet, base+"/v1/audit/events?event_type=audit_events_viewed", "", &page); code != http.StatusOK || len(page.Events) != 1 ||
		page.Events[0]["purpose"] != "review" {
		t.Fatalf("the read was not recorded: %d %v", code, page)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Production identity without a credential: nobody is admitted, and
// the refusal says how to sign in.
func TestIntegrationProductionSpecRefusesWithoutASession(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &stdout, &stderr, env(baseEnv(t, u))) }()
	defer func() { cancel(); <-exit }()
	listen := stdout.waitFor(t, "public listener open", nil)
	var problem map[string]any
	if code := do(t, http.MethodGet, "http://"+listen["addr"].(string)+"/v1/policy", "", &problem); code != http.StatusUnauthorized ||
		!strings.Contains(problem["detail"].(string), "/v1/auth/login") {
		t.Fatalf("%d %v", code, problem)
	}
}

// E-02: with the database present and a key file that cannot be read,
// api exits non-zero and names the variable; the JWKS of the working
// twin lists both token keys' active one and the publication key.
func TestIntegrationSigningKeyFileMissingStopsTheStart(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	m["SIGNING_KEY_FILES"] = t.TempDir() + "/absent.pem"
	var stdout, stderr lines
	code := proc.Main(context.Background(), spec(&config.API{}), nil, &stdout, &stderr, env(m))
	if code != proc.ExitFailed || stdout.find("process failed", func(l map[string]any) bool {
		return strings.Contains(l["error"].(string), "SIGNING_KEY_FILES")
	}) == nil {
		t.Fatalf("exit %d:\n%s", code, stdout.b.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	var out2, err2 lines
	go func() { exit <- proc.Main(ctx, spec(&config.API{}), nil, &out2, &err2, env(baseEnv(t, u))) }()
	defer func() { cancel(); <-exit }()
	ready := out2.waitFor(t, "token service ready", nil)
	listen := out2.waitFor(t, "public listener open", nil)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if code := do(t, http.MethodGet, "http://"+listen["addr"].(string)+"/.well-known/jwks.json", "", &jwks); code != http.StatusOK || len(jwks.Keys) != 2 ||
		jwks.Keys[0]["kid"] != ready["signing_kid"] {
		t.Fatalf("jwks %d %v (ready %v)", code, jwks, ready)
	}
	out2.waitFor(t, "status", func(l map[string]any) bool { return l["signing_kid"] == ready["signing_kid"] })
}
