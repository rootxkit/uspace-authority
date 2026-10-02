package main

import (
	"context"
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

// WP-3 through the real process: api re-projects the registry at start,
// reports the telemetry database on /readyz, and serves the registrar's
// operations, each written to the projection with the change.
func TestIntegrationRegistryThroughTheProcess(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	identify := func(*http.Request) (apiserver.Identity, error) {
		return apiserver.Identity{ActorType: "user", Subject: "registrar-1", Roles: []string{apiserver.RoleRegistrar}, Realm: "console", Session: true}, nil
	}
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, &stdout, &stderr, env(baseEnv(t, u))) }()
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
	started := stdout.waitFor(t, "started", nil)
	listen := stdout.waitFor(t, "public listener open", nil)
	stdout.waitFor(t, "registry re-projected", func(l map[string]any) bool { return l["cause"] == "startup" })
	base := "http://" + listen["addr"].(string)

	var ready struct {
		Checks map[string]struct {
			OK bool `json:"ok"`
		} `json:"checks"`
	}
	if code := do(t, http.MethodGet, "http://"+started["admin_addr"].(string)+"/readyz", "", &ready); code != http.StatusOK || !ready.Checks["telemetry"].OK {
		t.Fatalf("readyz %d %+v", code, ready)
	}
	// The policy api follows supplies the format; wait for it.
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })
	var op map[string]any
	body := `{"operator_type":"legal","registration_number":"GEOTEST00000001","legal_name":"Test Aerial LLC",
		"legal_identification_number":"TEST-404000001","postal_address":"2 Test Avenue","contact_email":"ops@example.test",
		"contact_phone":"+995 555 000 002","valid_until":"2030-01-01T00:00:00Z"}`
	if code := do(t, http.MethodPost, base+"/v1/registry/operators", body, &op); code != http.StatusCreated || op["status"] != "active" {
		t.Fatalf("operator %d %v", code, op)
	}
	var uas map[string]any
	if code := do(t, http.MethodPost, base+"/v1/registry/uas", `{"operator_id":"`+op["id"].(string)+`","serial":"TESTA0123456789","class_label":"C1","rid_capability":"direct"}`, &uas); code != http.StatusCreated {
		t.Fatalf("uas %d %v", code, uas)
	}
	var problem map[string]any
	if code := do(t, http.MethodPost, base+"/v1/registry/uas", `{"operator_id":"`+op["id"].(string)+`","serial":"testa0123456789","rid_capability":"direct"}`, &problem); code != http.StatusConflict {
		t.Fatalf("ambiguous fold %d %v", code, problem)
	}
	if code := do(t, http.MethodGet, base+"/v1/registry/uas?serial=testa0123456789", "", &problem); code != http.StatusOK || !strings.Contains(mustJSON(problem), uas["id"].(string)) {
		t.Fatalf("lookup %d %v", code, problem)
	}
}

// E-02: with the relational database present and the telemetry database
// absent, api does not serve a registry it cannot project; it exits
// non-zero and says which database.
func TestIntegrationStartWithoutTheTelemetryDatabaseSaysWhich(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	m["TS_URL"] = "postgres://u:p@127.0.0.1:1/absent?connect_timeout=2"
	var stdout, stderr lines
	code := proc.Main(context.Background(), spec(&config.API{}), nil, &stdout, &stderr, env(m))
	if code != proc.ExitFailed || stdout.find("process failed", func(l map[string]any) bool {
		return strings.Contains(l["error"].(string), "telemetry database")
	}) == nil {
		t.Fatalf("exit %d:\n%s", code, stdout.b.String())
	}
	if strings.Contains(stdout.b.String(), "u:p@") {
		t.Fatal("the URL with its password reached the log")
	}
}
