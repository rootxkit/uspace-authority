package overview

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Every console role, an account with two of them, and a police-realm
// account (which holds police.query and never a console role).
var identities = map[string]apiserver.Identity{
	"viewer":           {ActorType: "user", Subject: "viewer-1", Roles: []string{apiserver.RoleViewer}, Realm: apiserver.RealmConsole, Session: true},
	"inspector":        {ActorType: "user", Subject: "inspector-1", Roles: []string{apiserver.RoleInspector}, Realm: apiserver.RealmConsole, Session: true},
	"registrar":        {ActorType: "user", Subject: "registrar-1", Roles: []string{apiserver.RoleRegistrar}, Realm: apiserver.RealmConsole, Session: true},
	"incident_officer": {ActorType: "user", Subject: "officer-1", Roles: []string{apiserver.RoleIncidentOfficer}, Realm: apiserver.RealmConsole, Session: true},
	"admin":            {ActorType: "user", Subject: "admin-1", Roles: []string{apiserver.RoleAdmin}, Realm: apiserver.RealmConsole, Session: true},
	"auditor":          {ActorType: "user", Subject: "auditor-1", Roles: []string{apiserver.RoleAuditor}, Realm: apiserver.RealmConsole, Session: true},
	"police":           {ActorType: "user", Subject: "police-1", Roles: []string{apiserver.RolePoliceQuery}, Realm: apiserver.RealmPolice, Session: true},
	// A police-realm session that claims a console role is still refused: the realm decides.
	"police_admin": {ActorType: "user", Subject: "police-2", Roles: []string{apiserver.RoleAdmin}, Realm: apiserver.RealmPolice, Session: true},
}

var dbNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("+04", 4*3600))

// fakeStore answers the count queries with fixed rows and records what was asked.
type fakeStore struct {
	registry []pggen.OverviewRegistryCountsRow
	uspace   []pggen.OverviewUSpaceCountsRow
	certs    []pggen.OverviewCertificateCountsRow
	events   int64
	err      error
	reads    int
	audit    []pggen.OverviewAuditEventCountParams
}

func (f *fakeStore) Read(_ context.Context, fn func(q Queries) error) error {
	f.reads++
	return fn(f)
}

func (f *fakeStore) DBNow(context.Context) (time.Time, error) { return dbNow, nil }

func (f *fakeStore) OverviewRegistryCounts(context.Context) ([]pggen.OverviewRegistryCountsRow, error) {
	return f.registry, f.err
}

func (f *fakeStore) OverviewUSpaceCounts(context.Context) ([]pggen.OverviewUSpaceCountsRow, error) {
	return f.uspace, f.err
}

func (f *fakeStore) OverviewCertificateCounts(context.Context) ([]pggen.OverviewCertificateCountsRow, error) {
	return f.certs, f.err
}

func (f *fakeStore) OverviewAuditEventCount(_ context.Context, arg pggen.OverviewAuditEventCountParams) (int64, error) {
	f.audit = append(f.audit, arg)
	return f.events, f.err
}

func server(t *testing.T, s Store) *httptest.Server {
	t.Helper()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		id, ok := identities[r.Header.Get("X-Test-As")]
		if !ok {
			return apiserver.Identity{}, apiserver.ErrNoSession
		}
		return id, nil
	}
	mux := http.NewServeMux()
	apiserver.Mount(mux, apiserver.Server{OverviewHandler: Handler{Store: s}}, apiserver.Options{
		Middlewares: []apiserver.Middleware{apiserver.Authorize(identify, apiserver.DefaultRules())},
		Admit:       apiserver.Admission(identify, apiserver.DefaultRules()),
		Keep:        apiserver.PathPrefix("/v1/overview/"),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, as, path string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if as != "" {
		req.Header.Set("X-Test-As", as)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s as %q: %d %s", path, as, resp.StatusCode, b)
	}
	return resp.StatusCode, out
}

func full() *fakeStore {
	return &fakeStore{
		registry: []pggen.OverviewRegistryCountsRow{
			{Entity: "operators", Status: "active", N: 7}, {Entity: "operators", Status: "suspended", N: 2},
			{Entity: "operators", Status: "revoked", N: 1}, {Entity: "operators", Status: "expired", N: 3},
			{Entity: "uas", Status: "active", N: 11}, {Entity: "uas", Status: "revoked", N: 4},
			{Entity: "pilots", Status: "active", N: 5},
		},
		uspace: []pggen.OverviewUSpaceCountsRow{{State: "draft", N: 1}, {State: "published", N: 2}, {State: "superseded", N: 1}},
		certs:  []pggen.OverviewCertificateCountsRow{{Status: "operating", N: 3}, {Status: "suspended", N: 1}, {Status: "lapsed", N: 2}},
		events: 42,
	}
}

// The operations and the roles the contract admits to each: the roles
// of the domain's list operation, nothing more.
var admitted = map[string][]string{
	"/v1/overview/registry":     {"registrar", "inspector", "viewer"},
	"/v1/overview/uspace":       {"admin"},
	"/v1/overview/certificates": {"admin"},
	"/v1/overview/audit":        {"admin", "auditor"},
}

// Every role on every operation: the admitted roles get the counts, every
// other console role a 403, a police-realm session a 403 whatever role it
// claims, and a request without a session a 401. The pair of each
// refusal is the admission of the same operation.
func TestEveryOperationAdmitsItsRolesOnly(t *testing.T) {
	f := full()
	srv := server(t, f)
	for path, roles := range admitted {
		for as := range identities {
			code, body := get(t, srv, as, path)
			want := http.StatusForbidden
			if slices.Contains(roles, as) {
				want = http.StatusOK
			}
			if code != want {
				t.Errorf("%s as %s: %d, want %d: %v", path, as, code, want, body)
			}
			if code == http.StatusOK && body["as_of"] == nil {
				t.Errorf("%s as %s: no as_of: %v", path, as, body)
			}
			if code == http.StatusForbidden && !strings.HasSuffix(body["type"].(string), "/forbidden") {
				t.Errorf("%s as %s: %v", path, as, body)
			}
		}
		code, body := get(t, srv, "", path)
		if code != http.StatusUnauthorized || !strings.HasSuffix(body["type"].(string), "/unauthenticated") {
			t.Errorf("%s without a session: %d %v", path, code, body)
		}
	}
	// A refused or unauthenticated request never reached the database.
	want := 0
	for _, roles := range admitted {
		want += len(roles)
	}
	if f.reads != want {
		t.Fatalf("reads %d, want %d (one per admitted request)", f.reads, want)
	}
}

// The handler's rule table is the contract's: a test of apiserver holds
// Roles to x-roles; this one holds the overview to its domains' lists.
func TestRolesAreTheDomainListsRoles(t *testing.T) {
	for op, list := range map[string]string{
		"GetOverviewRegistry":     "ListRegistryOperators",
		"GetOverviewUSpace":       "ListUSpaceAirspaces",
		"GetOverviewCertificates": "ListCertificates",
		"GetOverviewAudit":        "ListAuditEvents",
	} {
		got, want := apiserver.Roles[op], apiserver.Roles[list]
		if len(got) == 0 || !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
			t.Errorf("%s admits %v, %s admits %v", op, got, list, want)
		}
		if _, other := apiserver.Realms[op]; other {
			t.Errorf("%s names a realm: it is the console's only", op)
		}
	}
}

func num(t *testing.T, m map[string]any, path ...string) float64 {
	t.Helper()
	var cur any = m
	for _, p := range path {
		cur = cur.(map[string]any)[p]
	}
	n, ok := cur.(float64)
	if !ok {
		t.Fatalf("%v: %v", path, cur)
	}
	return n
}

func TestRegistryCountsByEntityAndStatus(t *testing.T) {
	srv := server(t, full())
	code, body := get(t, srv, "viewer", "/v1/overview/registry")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	if body["as_of"] != "2026-10-15T08:00:00Z" {
		t.Fatalf("as_of %v: the database clock in UTC", body["as_of"])
	}
	for _, c := range []struct {
		entity, status string
		n              float64
	}{
		{"operators", "active", 7}, {"operators", "suspended", 2}, {"operators", "revoked", 1}, {"operators", "expired", 3}, {"operators", "total", 13},
		{"uas", "active", 11}, {"uas", "suspended", 0}, {"uas", "revoked", 4}, {"uas", "expired", 0}, {"uas", "total", 15},
		{"pilots", "active", 5}, {"pilots", "total", 5},
	} {
		if got := num(t, body, c.entity, c.status); got != c.n {
			t.Errorf("%s.%s = %v, want %v", c.entity, c.status, got, c.n)
		}
	}
}

// An empty registry is zeros that api counted, not an absent figure.
func TestEmptyCountsAreZeros(t *testing.T) {
	srv := server(t, &fakeStore{})
	_, reg := get(t, srv, "registrar", "/v1/overview/registry")
	_, usp := get(t, srv, "admin", "/v1/overview/uspace")
	_, crt := get(t, srv, "admin", "/v1/overview/certificates")
	_, aud := get(t, srv, "auditor", "/v1/overview/audit")
	for name, n := range map[string]float64{
		"operators": num(t, reg, "operators", "total"), "uas": num(t, reg, "uas", "total"), "pilots": num(t, reg, "pilots", "total"),
		"uspace": num(t, usp, "total"), "certificates": num(t, crt, "total"), "events": num(t, aud, "events"),
	} {
		if n != 0 {
			t.Errorf("%s: %v", name, n)
		}
	}
	if aud["more"] != false {
		t.Fatalf("more: %v", aud["more"])
	}
}

func TestUSpaceAndCertificateCountsByState(t *testing.T) {
	srv := server(t, full())
	_, usp := get(t, srv, "admin", "/v1/overview/uspace")
	for k, v := range map[string]float64{"draft": 1, "approved": 0, "published": 2, "superseded": 1, "total": 4} {
		if got := num(t, usp, k); got != v {
			t.Errorf("uspace.%s = %v, want %v", k, got, v)
		}
	}
	_, crt := get(t, srv, "admin", "/v1/overview/certificates")
	for k, v := range map[string]float64{"issued": 0, "operating": 3, "ceased": 0, "suspended": 1, "limited": 0, "revoked": 0, "lapsed": 2, "total": 6} {
		if got := num(t, crt, k); got != v {
			t.Errorf("certificates.%s = %v, want %v", k, got, v)
		}
	}
}

// The audit count asks for the 24-hour window and the bound; below the
// bound more is false, at it more is true (E-10's pair).
func TestAuditCountIsBounded(t *testing.T) {
	f := &fakeStore{events: AuditMaxRows - 1}
	srv := server(t, f)
	_, below := get(t, srv, "admin", "/v1/overview/audit")
	if num(t, below, "events") != AuditMaxRows-1 || below["more"] != false || num(t, below, "window_s") != 86400 {
		t.Fatalf("below the bound: %v", below)
	}
	f.events = AuditMaxRows
	_, at := get(t, srv, "auditor", "/v1/overview/audit")
	if num(t, at, "events") != AuditMaxRows || at["more"] != true {
		t.Fatalf("at the bound: %v", at)
	}
	for _, a := range f.audit {
		if a.WindowS != 86400 || a.MaxRows != AuditMaxRows {
			t.Fatalf("asked %+v", a)
		}
	}
}

// A status, state or entity the contract does not name fails the read
// (500) instead of vanishing from a total; a database error fails it too.
// The pair of each is the successful read above.
func TestUnknownValuesAndDatabaseErrorsFailTheRead(t *testing.T) {
	cases := map[string]struct {
		store *fakeStore
		as    string
		path  string
	}{
		"registry entity": {&fakeStore{registry: []pggen.OverviewRegistryCountsRow{{Entity: "drones", Status: "active", N: 1}}}, "viewer", "/v1/overview/registry"},
		"registry status": {&fakeStore{registry: []pggen.OverviewRegistryCountsRow{{Entity: "uas", Status: "lost", N: 1}}}, "viewer", "/v1/overview/registry"},
		"uspace state":    {&fakeStore{uspace: []pggen.OverviewUSpaceCountsRow{{State: "archived", N: 1}}}, "admin", "/v1/overview/uspace"},
		"cert status":     {&fakeStore{certs: []pggen.OverviewCertificateCountsRow{{Status: "paused", N: 1}}}, "admin", "/v1/overview/certificates"},
		"registry error":  {&fakeStore{err: errors.New("connection reset")}, "viewer", "/v1/overview/registry"},
		"uspace error":    {&fakeStore{err: errors.New("connection reset")}, "admin", "/v1/overview/uspace"},
		"cert error":      {&fakeStore{err: errors.New("connection reset")}, "admin", "/v1/overview/certificates"},
		"audit error":     {&fakeStore{err: errors.New("connection reset")}, "admin", "/v1/overview/audit"},
	}
	for name, c := range cases {
		srv := server(t, c.store)
		code, body := get(t, srv, c.as, c.path)
		if code != http.StatusInternalServerError {
			t.Errorf("%s: %d %v", name, code, body)
		}
		if b, _ := json.Marshal(body); strings.Contains(string(b), "connection reset") || strings.Contains(string(b), "unknown") {
			t.Errorf("%s: the cause is echoed to the client: %v", name, body)
		}
	}
}
