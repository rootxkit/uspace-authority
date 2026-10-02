package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// identities a test request picks with the X-Test-As header.
var identities = map[string]apiserver.Identity{
	"registrar": {ActorType: "user", Subject: "registrar-1", Roles: []string{apiserver.RoleRegistrar}, Realm: "console", Session: true},
	"inspector": {ActorType: "user", Subject: "inspector-1", Roles: []string{apiserver.RoleInspector}, Realm: "console", Session: true},
	"viewer":    {ActorType: "user", Subject: "viewer-1", Roles: []string{apiserver.RoleViewer}, Realm: "console", Session: true},
	"admin":     {ActorType: "user", Subject: "admin-1", Roles: []string{apiserver.RoleAdmin}, Realm: "console", Session: true},
	"ussp":      {ActorType: "client", Subject: "ussp-TEST-01", Scopes: []string{"registry.validate"}},
	"cisp":      {ActorType: "client", Subject: "cisp-01", Scopes: []string{"cis.read"}},
}

func server(t *testing.T, f *fixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		id, ok := identities[r.Header.Get("X-Test-As")]
		if !ok {
			return apiserver.Identity{}, apiserver.ErrNoSession
		}
		return id, nil
	}
	apiserver.Mount(mux, apiserver.Server{RegistryHandler: Handler{Service: f.svc}}, apiserver.Options{
		Middlewares: []apiserver.Middleware{apiserver.Authorize(identify, apiserver.DefaultRules())},
		Keep:        apiserver.PathPrefix("/v1/registry/"),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("%d %s: %v", r.status, r.body, err)
	}
}

func (r response) slug() string {
	var p httpx.Problem
	_ = json.Unmarshal(r.body, &p)
	if len(p.Type) <= len(httpx.ProblemTypeBase) {
		return ""
	}
	return p.Slug()
}

func call(t *testing.T, srv *httptest.Server, as, method, path string, body any, header ...string) response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Test-As", as)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

func operatorBody() map[string]any {
	return map[string]any{
		"operator_type": "natural", "registration_number": numberA, "secret_part": "x9z",
		"full_name": "Test Person", "date_of_birth": "1980-01-02", "postal_address": "1 Test Street",
		"contact_email": "operator@example.test", "contact_phone": "+995 555 000 001",
		"insurance_policy_number": "TEST-INS-1", "authorisations": []any{map[string]any{"kind": "declaration"}},
		"valid_until": t0.AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z"), "source": "manual",
	}
}

// The registry over HTTP, through the contract's access rules: the
// registrar registers and changes; viewer and inspector read records
// without personal data; only the PII roles read personal data, with a
// purpose; machines reach F8 only, with its scope.
func TestRegistryOverHTTP(t *testing.T) {
	f := newFixture(t)
	srv := server(t, f)

	r := call(t, srv, "viewer", "POST", "/v1/registry/operators", operatorBody())
	if r.status != http.StatusForbidden {
		t.Fatalf("viewer registered: %d", r.status)
	}
	r = call(t, srv, "registrar", "POST", "/v1/registry/operators", operatorBody())
	if r.status != http.StatusCreated {
		t.Fatalf("register: %d %s", r.status, r.body)
	}
	for _, leak := range []string{"Test Person", "operator@example.test", "1980-01-02", "x9z", "Test Street"} {
		if bytes.Contains(r.body, []byte(leak)) {
			t.Fatalf("the record echoes %q: %s", leak, r.body)
		}
	}
	var op struct {
		ID            string `json:"id"`
		HasSecretPart bool   `json:"has_secret_part"`
	}
	r.decode(t, &op)
	if !op.HasSecretPart {
		t.Fatal("has_secret_part")
	}
	if r := call(t, srv, "registrar", "POST", "/v1/registry/operators", operatorBody()); r.status != http.StatusConflict {
		t.Fatalf("duplicate: %d", r.status)
	}
	bad := operatorBody()
	bad["registration_number"] = "GEOTEST00000002-abc"
	if r := call(t, srv, "registrar", "POST", "/v1/registry/operators", bad); r.status != http.StatusBadRequest || r.slug() != "validation" {
		t.Fatalf("hyphen: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/operators/"+op.ID, nil); r.status != http.StatusOK || bytes.Contains(r.body, []byte("Test Person")) {
		t.Fatalf("viewer read: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/operators?number=geotest00000001", nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte(op.ID)) {
		t.Fatalf("lookup by number: %d %s", r.status, r.body)
	}
	// Personal data: never to viewer or a machine; never without a purpose.
	for _, as := range []string{"viewer", "ussp", "admin"} {
		if r := call(t, srv, as, "GET", "/v1/registry/operators/"+op.ID+"/personal-data?purpose=x", nil); r.status != http.StatusForbidden {
			t.Fatalf("%s read personal data: %d", as, r.status)
		}
	}
	if r := call(t, srv, "inspector", "GET", "/v1/registry/operators/"+op.ID+"/personal-data", nil); r.status != http.StatusBadRequest {
		t.Fatalf("no purpose: %d", r.status)
	}
	r = call(t, srv, "inspector", "GET", "/v1/registry/operators/"+op.ID+"/personal-data?purpose=case+TEST-1", nil)
	if r.status != http.StatusOK || !bytes.Contains(r.body, []byte("Test Person")) || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("personal data: %d %v %s", r.status, r.header, r.body)
	}
	if r := call(t, srv, "registrar", "PATCH", "/v1/registry/operators/"+op.ID, map[string]any{"contact_phone": "+995 555 000 009", "date_of_birth": "1981-02-03"}); r.status != http.StatusOK {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "registrar", "PATCH", "/v1/registry/operators/"+op.ID, nil); r.status != http.StatusBadRequest {
		t.Fatalf("patch without body: %d", r.status)
	}

	r = call(t, srv, "registrar", "POST", "/v1/registry/uas", map[string]any{
		"operator_id": op.ID, "serial": serialC1, "class_label": "C1", "mtom_g": 800, "rid_capability": "direct",
		"manufacturer": "TEST", "model": "TEST-QUAD", "registration_mark": "4L-TEST", "owner_ref": "TEST-OWNER",
	})
	if r.status != http.StatusCreated {
		t.Fatalf("UAS: %d %s", r.status, r.body)
	}
	var u struct {
		ID string `json:"id"`
	}
	r.decode(t, &u)
	if r := call(t, srv, "registrar", "POST", "/v1/registry/uas", map[string]any{"operator_id": op.ID, "serial": serialLegacy, "class_label": "C2", "rid_capability": "direct"}); r.status != http.StatusBadRequest {
		t.Fatalf("legacy serial for C2: %d", r.status)
	}
	if r := call(t, srv, "registrar", "PATCH", "/v1/registry/uas/"+u.ID, map[string]any{"class_label": "C2", "rid_capability": "both", "model": "TEST-HEX"}); r.status != http.StatusOK {
		t.Fatalf("UAS patch: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "registrar", "POST", "/v1/registry/uas/"+u.ID+"/status", map[string]any{"status": "suspended"}); r.status != http.StatusBadRequest {
		t.Fatalf("suspension without a reason: %d", r.status)
	}
	if r := call(t, srv, "registrar", "POST", "/v1/registry/uas/"+u.ID+"/status", map[string]any{"status": "suspended", "reason": "unsafe"}); r.status != http.StatusOK {
		t.Fatalf("suspend: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/uas?serial="+strings.ToLower(serialC1), nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte(u.ID)) {
		t.Fatalf("lookup by serial: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/uas/"+u.ID, nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte(`"suspended"`)) {
		t.Fatalf("UAS read: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/uas?status=bogus", nil); r.status != http.StatusBadRequest {
		t.Fatalf("bad status filter: %d", r.status)
	}

	r = call(t, srv, "registrar", "POST", "/v1/registry/pilots", map[string]any{"person_ref": "01001012345", "name": "Test Pilot", "operator_id": op.ID})
	if r.status != http.StatusCreated || bytes.Contains(r.body, []byte("2345")) || bytes.Contains(r.body, []byte("Test Pilot")) {
		t.Fatalf("pilot: %d %s", r.status, r.body)
	}
	var p struct {
		ID string `json:"id"`
	}
	r.decode(t, &p)
	if r := call(t, srv, "registrar", "POST", "/v1/registry/pilots/"+p.ID+"/competencies", map[string]any{"competency": "A2", "certificate_ref": "TEST-A2", "valid_until": "2031-01-01T00:00:00Z"}); r.status != http.StatusOK || !bytes.Contains(r.body, []byte("TEST-A2")) {
		t.Fatalf("competency: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "registrar", "PATCH", "/v1/registry/pilots/"+p.ID, map[string]any{"name": "Renamed"}); r.status != http.StatusOK {
		t.Fatalf("pilot patch: %d", r.status)
	}
	if r := call(t, srv, "registrar", "GET", "/v1/registry/pilots/"+p.ID+"/personal-data?purpose=check", nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte("Renamed")) {
		t.Fatalf("pilot personal data: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/pilots/"+p.ID+"/personal-data?purpose=check", nil); r.status != http.StatusForbidden {
		t.Fatalf("viewer read a pilot's personal data: %d", r.status)
	}
	if r := call(t, srv, "registrar", "POST", "/v1/registry/pilots/"+p.ID+"/status", map[string]any{"status": "suspended", "reason": "medical"}); r.status != http.StatusOK {
		t.Fatalf("pilot status: %d", r.status)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/pilots?operator_id="+op.ID, nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte(p.ID)) {
		t.Fatalf("pilot list: %d %s", r.status, r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/pilots/"+p.ID, nil); r.status != http.StatusOK {
		t.Fatalf("pilot read: %d", r.status)
	}
	if r := call(t, srv, "registrar", "POST", "/v1/registry/operators/"+op.ID+"/status", map[string]any{"status": "suspended", "reason": "insurance"}); r.status != http.StatusOK {
		t.Fatalf("operator status: %d", r.status)
	}

	// F8: machines with the scope only; status only.
	q := fmt.Sprintf("/v1/registry/validate?purpose=identification&operator=%s&serial=%s&pilot=%s", numberA, serialC1, p.ID)
	for _, as := range []string{"registrar", "cisp", ""} {
		if r := call(t, srv, as, "GET", q, nil); r.status != http.StatusForbidden && r.status != http.StatusUnauthorized {
			t.Fatalf("%q validated: %d", as, r.status)
		}
	}
	r = call(t, srv, "ussp", "GET", q, nil)
	if r.status != http.StatusOK {
		t.Fatalf("validate: %d %s", r.status, r.body)
	}
	var v map[string]map[string]any
	r.decode(t, &v)
	if v["operator"]["status"] != "suspended" || v["uas"]["status"] != "suspended" || v["pilot"]["status"] != "suspended" || v["uas"]["mtom_band"] != "under_900g" {
		t.Fatalf("answer %s", r.body)
	}
	if r := call(t, srv, "ussp", "GET", "/v1/registry/validate?purpose=marketing&serial=x", nil); r.status != http.StatusBadRequest {
		t.Fatalf("bad purpose: %d", r.status)
	}
	items := make([]map[string]string, MaxBatch+1)
	for i := range items {
		items[i] = map[string]string{"serial": fmt.Sprintf("TEST-%d", i)}
	}
	if r := call(t, srv, "ussp", "POST", "/v1/registry/validate?purpose=authorisation", map[string]any{"items": items}); r.status != http.StatusBadRequest {
		t.Fatalf("over the bound: %d", r.status)
	}
	r = call(t, srv, "ussp", "POST", "/v1/registry/validate?purpose=authorisation", map[string]any{"items": items[:MaxBatch]})
	var list struct {
		Results []map[string]any `json:"results"`
	}
	r.decode(t, &list)
	if r.status != http.StatusOK || len(list.Results) != MaxBatch {
		t.Fatalf("batch: %d %d", r.status, len(list.Results))
	}

	r = call(t, srv, "ussp", "GET", "/v1/registry/changes?since=0&limit=2", nil)
	etag := r.header.Get("ETag")
	if r.status != http.StatusOK || etag == "" {
		t.Fatalf("changes: %d %v", r.status, r.header)
	}
	var page struct {
		Changes   []map[string]any `json:"changes"`
		NextSince int64            `json:"next_since"`
	}
	r.decode(t, &page)
	if len(page.Changes) != 2 || page.NextSince != 2 {
		t.Fatalf("page %s", r.body)
	}
	if r := call(t, srv, "ussp", "GET", "/v1/registry/changes?since=0&limit=2", nil, "If-None-Match", etag); r.status != http.StatusNotModified {
		t.Fatalf("unchanged page: %d", r.status)
	}
	if r := call(t, srv, "ussp", "GET", "/v1/registry/changes", nil, "If-None-Match", etag); r.status != http.StatusOK {
		t.Fatalf("another page answered 304: %d", r.status)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/changes", nil); r.status != http.StatusForbidden {
		t.Fatalf("a session read the change feed: %d", r.status)
	}

	// Paging cursors.
	f.operator(t, legalOperator(numberB))
	r = call(t, srv, "viewer", "GET", "/v1/registry/operators?limit=1", nil)
	var ops struct {
		Operators []map[string]any `json:"operators"`
		NextAfter *string          `json:"next_after"`
	}
	r.decode(t, &ops)
	if len(ops.Operators) != 1 || ops.NextAfter == nil {
		t.Fatalf("page with a cursor: %s", r.body)
	}
	r = call(t, srv, "viewer", "GET", "/v1/registry/operators?limit=1&after="+*ops.NextAfter, nil)
	r.decode(t, &ops)
	if len(ops.Operators) != 1 {
		t.Fatalf("second page: %s", r.body)
	}
	if r := call(t, srv, "viewer", "GET", "/v1/registry/operators/0123456789abcdef0123456789abcdef", nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown operator: %d", r.status)
	}
}
