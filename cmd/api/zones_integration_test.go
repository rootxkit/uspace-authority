package main

import (
	"context"
	"encoding/json"
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

// zoneFeature is an invented test zone near Tbilisi; no real restriction.
const zoneFeature = `{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.79,41.69],[44.81,41.69],[44.81,41.71],[44.79,41.71],[44.79,41.69]]],
	"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"WGS84","uom":"m"}},
	"properties":{"identifier":"TST001","country":"GEO","name":[{"text":"Test zone","lang":"en-GB"}],"type":"PROHIBITED","variant":"COMMON",
	"zoneAuthority":[{"purpose":"AUTHORIZATION"}]}}`

// doAs is do with the console role the test identity takes.
func doAs(t *testing.T, role, method, url, contentType, body string, out any) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-Role", role)
	if body != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%v: %s", err, b)
		}
	}
	return resp.StatusCode, resp.Header.Get("Content-Type") + " " + string(b)
}

// A-M1 zone item through the API: an inspector authors a zone, an admin
// approves and publishes it, the outbox row is pending with no signature
// (WP-6 signs it), the projection is written, and the export answers it.
func TestIntegrationZoneAuthoredApprovedAndPublishedThroughTheAPI(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	identify := func(r *http.Request) (apiserver.Identity, error) {
		role := r.Header.Get("X-Test-Role")
		return apiserver.Identity{ActorType: "user", Subject: role + "-1", Roles: []string{role}, Realm: "console", Session: true}, nil
	}
	m := baseEnv(t, u)
	m["ZONES_PROVIDER_NAME"] = "Test authority"
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
	stdout.waitFor(t, "zones re-projected", func(l map[string]any) bool { return l["cause"] == "startup" })
	stdout.waitFor(t, "daylight events cannot be resolved until the ground package is wired (WP-11): zones scheduled by BMCT, SR, SS or EECT answer unknown", nil)
	base := "http://" + listen["addr"].(string)
	now := time.Now().UTC()
	period := `"valid_from":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","valid_to":"` + now.Add(24*time.Hour).Format(time.RFC3339) + `"`
	draft := `{"feature":` + zoneFeature + `,` + period + `}`

	// A viewer may read but not author; an inspector may not approve.
	if code, body := doAs(t, "viewer", http.MethodPost, base+"/v1/zones", "application/json", draft, nil); code != http.StatusForbidden {
		t.Fatalf("viewer authoring: %d %s", code, body)
	}
	var v map[string]any
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/zones", "application/json", draft, &v); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	exts, _ := v["extensions"].([]any)
	if v["state"] != "draft" || len(exts) != 1 || !strings.Contains(mustJSON(exts[0]), "feature.geometry.layer.upperReference") {
		t.Fatalf("%v", v)
	}
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/zones/TST001/approve", "application/json", `{"zone_version":1}`, nil); code != http.StatusForbidden {
		t.Fatalf("inspector approving: %d %s", code, body)
	}
	if code, body := doAs(t, "admin", http.MethodPost, base+"/v1/zones/TST001/approve", "application/json", `{"zone_version":1}`, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	var pub map[string]any
	if code, body := doAs(t, "admin", http.MethodPost, base+"/v1/zones/publish", "", "", &pub); code != http.StatusOK {
		t.Fatalf("publish: %d %s", code, body)
	}
	row := pub["publication"].(map[string]any)
	if row["state"] != "pending" || row["signature"] != nil {
		t.Fatalf("outbox row %v", row)
	}
	if _, ok := row["signature"]; !ok {
		t.Fatal("signature is absent rather than null")
	}
	if code, body := doAs(t, "admin", http.MethodPost, base+"/v1/zones/publish", "", "", nil); code != http.StatusConflict || !strings.Contains(body, "nothing_to_publish") {
		t.Fatalf("second publish: %d %s", code, body)
	}

	// The export is ED-318 as uspace-core wrote it.
	code, body := doAs(t, "viewer", http.MethodGet, base+"/v1/zones/export", "", "", nil)
	if code != http.StatusOK || !strings.HasPrefix(body, "application/geo+json ") || !strings.Contains(body, `"identifier":"TST001"`) ||
		!strings.Contains(body, `"provider":[{"text":"Test authority","lang":"en-GB"}]`) {
		t.Fatalf("export: %d %s", code, body)
	}
	if code, body := doAs(t, "viewer", http.MethodGet, base+"/v1/zones/export?at="+now.Format(time.RFC3339)+"&applies_at="+now.Format(time.RFC3339), "", "", nil); code != http.StatusBadRequest || !strings.Contains(body, "filter_conflict") {
		t.Fatalf("both filters: %d %s", code, body)
	}

	// An ED-269 import arrives as the file's bytes.
	ed269 := `{"features":[{"identifier":"TSA001","country":"GEO","type":"COMMON","restriction":"PROHIBITED",
		"applicability":[{"permanent":"YES"}],"zoneAuthority":[{"name":"Test authority","purpose":"AUTHORIZATION"}],
		"geometry":[{"uomDimensions":"M","lowerVerticalReference":"AGL","upperVerticalReference":"AMSL","upperLimit":500,
		"horizontalProjection":{"type":"Circle","center":[44.83,41.72],"radius":500}}]}]}`
	q := "?valid_from=" + now.Format(time.RFC3339) + "&valid_to=" + now.Add(time.Hour).Format(time.RFC3339)
	var imported map[string]any
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/zones/import"+strings.ReplaceAll(q, "+", "%2B"), "application/octet-stream", ed269, &imported); code != http.StatusCreated || imported["format"] != "ed269" {
		t.Fatalf("import: %d %s", code, body)
	}
	if code, body := doAs(t, "inspector", http.MethodPost, base+"/v1/zones/import", "application/octet-stream", strings.Replace(ed269, "PROHIBITED", "REQ_AUTHORIZATION", 1), nil); code != http.StatusBadRequest || !strings.Contains(body, "features[0].restriction") {
		t.Fatalf("Z spelling: %d %s", code, body)
	}

	// Every act is an events row.
	pg := storetest.Open(t, u)
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM events WHERE event_type IN ('zone_drafted','zone_approved','zones_published','zones_exported','zones_imported')`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("%v: %d events", err, n)
	}
	stdout.waitFor(t, "status", func(l map[string]any) bool {
		c, _ := l["counters"].(map[string]any)
		z, _ := c["zones"].(map[string]any)
		return z != nil && z["zones_published"] == 1.0
	})
}
