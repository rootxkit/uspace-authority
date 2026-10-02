package zonesvc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
)

var testIdentities = map[string]apiserver.Identity{
	"inspector": {ActorType: "user", Subject: "inspector-1", Roles: []string{apiserver.RoleInspector}, Realm: "console", Session: true},
	"viewer":    {ActorType: "user", Subject: "viewer-1", Roles: []string{apiserver.RoleViewer}, Realm: "console", Session: true},
	"admin":     {ActorType: "user", Subject: "admin-1", Roles: []string{apiserver.RoleAdmin}, Realm: "console", Session: true},
}

func handlerServer(t *testing.T, s *Service) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		id, ok := testIdentities[r.Header.Get("X-Test-As")]
		if !ok {
			return apiserver.Identity{}, apiserver.ErrNoSession
		}
		return id, nil
	}
	h := Handler{Service: s}
	apiserver.Mount(mux, apiserver.Server{ZonesHandler: h, USpaceHandler: h}, apiserver.Options{
		Middlewares:  []apiserver.Middleware{apiserver.Authorize(identify, apiserver.DefaultRules())},
		Keep:         apiserver.PathPrefix("/v1/zones", "/v1/uspace"),
		BodyLimits:   map[string]int64{"POST /v1/zones/import": int64(MaxDocumentBytes)},
		BodyCounters: &core.Counters{},
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, as, method, path, contentType string, body []byte) (int, string, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-As", as)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

func TestHandlersAuthorApprovePublishExport(t *testing.T) {
	s, _, _, _ := newService(t)
	srv := handlerServer(t, s)
	draft, _ := json.Marshal(map[string]any{"feature": json.RawMessage(feature(zoneOpts{upperRef: "WGS84"})), "valid_from": t0, "valid_to": t1})
	if code, _, b := call(t, srv, "viewer", http.MethodPost, "/v1/zones", "application/json", draft); code != http.StatusForbidden {
		t.Fatalf("viewer: %d %s", code, b)
	}
	code, _, b := call(t, srv, "inspector", http.MethodPost, "/v1/zones", "application/json", draft)
	if code != http.StatusCreated || !strings.Contains(string(b), `"field":"feature.geometry.layer.upperReference"`) {
		t.Fatalf("%d %s", code, b)
	}
	if code, _, b := call(t, srv, "admin", http.MethodPost, "/v1/zones/TST001/approve", "application/json", []byte(`{"zone_version":1}`)); code != http.StatusOK {
		t.Fatalf("%d %s", code, b)
	}
	code, _, b = call(t, srv, "admin", http.MethodPost, "/v1/zones/publish", "", nil)
	if code != http.StatusOK || !strings.Contains(string(b), `"signature":null`) || !strings.Contains(string(b), `"state":"pending"`) {
		t.Fatalf("%d %s", code, b)
	}
	// The export is the bytes ed318.Export wrote, as application/geo+json.
	code, ct, b := call(t, srv, "viewer", http.MethodGet, "/v1/zones/export", "", nil)
	if code != http.StatusOK || ct != "application/geo+json" || !bytes.HasPrefix(b, []byte(`{"type":"FeatureCollection","metadata":{"issued"`)) {
		t.Fatalf("%d %s %s", code, ct, b)
	}
	for _, path := range []string{"/v1/zones", "/v1/zones/TST001", "/v1/zones/TST001/versions",
		"/v1/zones/TST001/applies?at=" + testNow.Format(time.RFC3339)} {
		if code, _, b := call(t, srv, "viewer", http.MethodGet, path, "", nil); code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, b)
		}
	}
}

func TestHandlerImportTakesTheFileBytesAndRefusesPastTheCap(t *testing.T) {
	s, _, _, _ := newService(t)
	srv := handlerServer(t, s)
	q := "?valid_from=2026-10-01T00:00:00Z&valid_to=2027-10-01T00:00:00Z"
	doc := append([]byte("\xEF\xBB\xBF"), []byte(ed269Doc(ed269Zone("TSA001", "PROHIBITED")))...)
	code, _, b := call(t, srv, "inspector", http.MethodPost, "/v1/zones/import"+q, "application/octet-stream", doc)
	if code != http.StatusCreated || !strings.Contains(string(b), `"format":"ed269"`) {
		t.Fatalf("%d %s", code, b)
	}
	big := bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	code, _, b = call(t, srv, "inspector", http.MethodPost, "/v1/zones/import"+q, "application/octet-stream", big)
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(string(b), "body_too_large") {
		t.Fatalf("%d %s", code, b)
	}
}

func TestHandlerGovGeImport(t *testing.T) {
	s, _, _, _ := newService(t)
	srv := handlerServer(t, s)
	body, _ := json.Marshal(map[string]any{
		"points_js": govGePoints, "page_html": govGePage, "valid_from": t0, "valid_to": t1,
		"rules": map[string]any{
			"country": "GEO", "authority": map[string]string{"name": "Test authority", "purpose": "AUTHORIZATION"},
			"kinds": map[string]any{
				"CTR": map[string]any{"restriction": "REQ_AUTHORISATION", "uom": "M", "lower_reference": "AGL", "upper_reference": "AGL",
					"upper_limit": 120, "applicability": []any{map[string]any{"permanent": "YES"}}},
				"EPR": map[string]any{"restriction": "PROHIBITED", "uom": "FT", "lower_reference": "AGL", "upper_reference": "AMSL",
					"upper_limit": 2500, "applicability": []any{map[string]any{"permanent": "YES"}}, "reason": []string{"SENSITIVE"}},
			},
		},
	})
	code, _, b := call(t, srv, "inspector", http.MethodPost, "/v1/zones/import/airspace-gov-ge", "application/json", body)
	if code != http.StatusBadRequest || !strings.Contains(string(b), `kind \"MIL\" has no rule`) {
		t.Fatalf("%d %s", code, b)
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	m["rules"].(map[string]any)["kinds"].(map[string]any)["MIL"] = m["rules"].(map[string]any)["kinds"].(map[string]any)["EPR"]
	body, _ = json.Marshal(m)
	code, _, b = call(t, srv, "inspector", http.MethodPost, "/v1/zones/import/airspace-gov-ge", "application/json", body)
	if code != http.StatusCreated || strings.Count(string(b), `"zone_version":1`) != 3 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestHandlersUSpace(t *testing.T) {
	s, _, _, _ := newService(t)
	srv := handlerServer(t, s)
	body, _ := json.Marshal(map[string]any{
		"feature": json.RawMessage(uspaceFeature("TSU001")), "designated_from": t0, "designated_to": t1,
		"designation": map[string]any{
			"airspace_name": "Tbilisi U-space (test)", "services_required": []string{"NID", "GEO", "FA", "TI"},
			"uas_requirements": map[string]any{}, "operational_conditions": map[string]any{},
			"service_performance":  map[string]any{"nid_update_hz": 1, "ti_update_hz": 1, "cis_latency_s": 1},
			"airspace_constraints": map[string]any{"max_height_agl_m": 120}, "in_controlled_airspace": false,
		},
	})
	if code, _, b := call(t, srv, "inspector", http.MethodPost, "/v1/uspace", "application/json", body); code != http.StatusForbidden {
		t.Fatalf("inspector: %d %s", code, b)
	}
	code, _, b := call(t, srv, "admin", http.MethodPost, "/v1/uspace", "application/json", body)
	if code != http.StatusCreated || !strings.Contains(string(b), `"airspace_name":"Tbilisi U-space (test)"`) {
		t.Fatalf("%d %s", code, b)
	}
	if code, _, b := call(t, srv, "admin", http.MethodPost, "/v1/uspace/TSU001/designate", "application/json", []byte(`{"zone_version":1}`)); code != http.StatusOK {
		t.Fatalf("%d %s", code, b)
	}
	if code, _, b := call(t, srv, "admin", http.MethodPost, "/v1/uspace/publish", "", nil); code != http.StatusOK || !strings.Contains(string(b), `"dataset":"uspace_airspace"`) {
		t.Fatalf("%d %s", code, b)
	}
	for _, path := range []string{"/v1/uspace", "/v1/uspace/TSU001", "/v1/uspace/TSU001/versions"} {
		if code, _, b := call(t, srv, "admin", http.MethodGet, path, "", nil); code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, b)
		}
	}
	if code, _, _ := call(t, srv, "admin", http.MethodGet, "/v1/zones/TSU001", "", nil); code != http.StatusNotFound {
		t.Fatalf("a U-space airspace under /v1/zones: %d", code)
	}
}
