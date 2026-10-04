package apiserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// stubPolicy answers every policy operation and records who called.
type stubPolicy struct{ seen *Identity }

func (s stubPolicy) GetPolicy(ctx context.Context, _ gen.GetPolicyRequestObject) (gen.GetPolicyResponseObject, error) {
	id, _ := IdentityFrom(ctx)
	*s.seen = id
	return gen.GetPolicy200JSONResponse{Version: 1}, nil
}

func (s stubPolicy) CreatePolicy(context.Context, gen.CreatePolicyRequestObject) (gen.CreatePolicyResponseObject, error) {
	return nil, httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "stub")
}

func (s stubPolicy) ActivatePolicy(context.Context, gen.ActivatePolicyRequestObject) (gen.ActivatePolicyResponseObject, error) {
	return nil, errors.New("database password=s3cret unreachable")
}

func identity(roles ...string) IdentifyFunc {
	return func(*http.Request) (Identity, error) {
		return Identity{ActorType: "user", Subject: "u-1", Roles: roles, Realm: "console", Session: true}, nil
	}
}

func server(t *testing.T, identify IdentifyFunc) (*httptest.Server, *Identity, []string) {
	t.Helper()
	seen := &Identity{}
	mux := http.NewServeMux()
	mounted := Mount(mux, Server{PolicyHandler: stubPolicy{seen: seen}}, Options{
		Middlewares: []Middleware{RequireRole(identify, Roles)},
		Keep:        PathPrefix("/v1/policy"),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, seen, mounted
}

func call(t *testing.T, method, url string) (int, httpx.Problem) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var p httpx.Problem
	if resp.Header.Get("Content-Type") == httpx.ProblemContentType {
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, p
}

func TestMountServesOnlyTheKeptPatterns(t *testing.T) {
	srv, _, mounted := server(t, identity(RoleAdmin))
	slices.Sort(mounted)
	want := []string{"GET /v1/policy", "POST /v1/policy", "POST /v1/policy/{version}/activate"}
	if !slices.Equal(mounted, want) {
		t.Fatalf("mounted %v", mounted)
	}
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unmounted operation answered %d", resp.StatusCode)
	}
}

// E-01: the placeholder refuses without a session (401) and without the
// role (403), and admits the role, handing the identity to the handler.
func TestRequireRoleRefusesThenAdmits(t *testing.T) {
	srv, _, _ := server(t, NoSession)
	if code, p := call(t, http.MethodGet, srv.URL+"/v1/policy"); code != http.StatusUnauthorized || p.Slug() != httpx.SlugUnauthn {
		t.Fatalf("no session: %d %+v", code, p)
	}
	srv, _, _ = server(t, identity(RoleAuditor, RoleViewer))
	if code, p := call(t, http.MethodGet, srv.URL+"/v1/policy"); code != http.StatusForbidden || !strings.Contains(p.Detail, RoleAdmin) {
		t.Fatalf("wrong role: %d %+v", code, p)
	}
	srv, seen, _ := server(t, identity(RoleViewer, RoleAdmin))
	if code, _ := call(t, http.MethodGet, srv.URL+"/v1/policy"); code != http.StatusOK || seen.Subject != "u-1" {
		t.Fatalf("admin: %d seen %+v", code, seen)
	}
}

func TestRequireRoleRefusesAnOperationWithoutARule(t *testing.T) {
	mw := RequireRole(identity(RoleAdmin), map[string][]string{})
	called := false
	h := mw(func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
		called = true
		return nil, nil
	}, "Unlisted")
	rec := httptest.NewRecorder()
	_, _ = h(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/v1/x", nil), nil)
	if called || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no role rule") {
		t.Fatalf("called %v code %d %s", called, rec.Code, rec.Body.String())
	}
}

// Errors keep the contract's shape: a handler's problem passes through,
// an unparsable parameter is a 400 naming the request, and an internal
// error is a 500 that does not echo its text.
func TestErrorsAreProblems(t *testing.T) {
	srv, _, _ := server(t, identity(RoleAdmin))
	if code, p := call(t, http.MethodPost, srv.URL+"/v1/policy"); code != http.StatusConflict || p.Slug() != httpx.SlugConflict {
		t.Fatalf("handler problem: %d %+v", code, p)
	}
	if code, p := call(t, http.MethodPost, srv.URL+"/v1/policy/abc/activate"); code != http.StatusBadRequest || len(p.Errors) != 1 || p.Errors[0].Field != "request" {
		t.Fatalf("bad parameter: %d %+v", code, p)
	}
	code, p := call(t, http.MethodPost, srv.URL+"/v1/policy/2/activate")
	if code != http.StatusInternalServerError || strings.Contains(p.Detail+p.Title, "s3cret") {
		t.Fatalf("internal: %d %+v", code, p)
	}
}

// xRoles reads x-roles of every operation from api/openapi.yaml, keyed
// by the operation id as the generated code names it.
func xRoles(t *testing.T) map[string][]string {
	t.Helper()
	f, err := os.Open("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	rolesRe := regexp.MustCompile(`^\s+x-roles:\s*\[([^\]]*)\]`)
	out := map[string][]string{}
	op := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := opRe.FindStringSubmatch(sc.Text()); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
			continue
		}
		if m := rolesRe.FindStringSubmatch(sc.Text()); m != nil && op != "" {
			var roles []string
			for r := range strings.SplitSeq(m[1], ",") {
				roles = append(roles, strings.TrimSpace(r))
			}
			out[op] = roles
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRolesMatchTheContract(t *testing.T) {
	spec := xRoles(t)
	if len(spec) == 0 {
		t.Fatal("no x-roles found in api/openapi.yaml")
	}
	for op, roles := range spec {
		if !slices.Equal(Roles[op], roles) {
			t.Errorf("%s: contract %v, code %v", op, roles, Roles[op])
		}
	}
	for op := range Roles {
		if _, ok := spec[op]; !ok {
			t.Errorf("%s has roles in code but no x-roles in the contract", op)
		}
	}
}

// contractOps reads, per operation id, whether it has `security: []`
// and whether it carries `x-session: any`.
func contractOps(t *testing.T) (public, anySession map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	public, anySession = map[string]bool{}, map[string]bool{}
	op := ""
	for line := range strings.SplitSeq(string(raw), "\n") {
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
			continue
		}
		switch strings.TrimSpace(line) {
		case "security: []":
			public[op] = true
		case "x-session: any":
			anySession[op] = true
		}
	}
	return public, anySession
}

func TestPublicAndAnySessionMatchTheContract(t *testing.T) {
	public, anySession := contractOps(t)
	for name, pair := range map[string][2]map[string]bool{"public": {public, Public}, "x-session": {anySession, AnySession}} {
		for op := range pair[0] {
			if !pair[1][op] {
				t.Errorf("%s: %s in the contract, not in code", name, op)
			}
		}
		for op := range pair[1] {
			if !pair[0][op] {
				t.Errorf("%s: %s in code, not in the contract", name, op)
			}
		}
	}
	for op := range Roles {
		if Public[op] {
			t.Errorf("%s is both public and role-guarded", op)
		}
	}
}

func authorized(rules Rules, id Identity, idErr error, op string) (int, bool, RequestInfo) {
	called := false
	var seen RequestInfo
	h := Authorize(func(*http.Request) (Identity, error) { return id, idErr }, rules)(
		func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			called = true
			seen = RequestInfoFrom(ctx)
			return nil, nil
		}, op)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("User-Agent", "probe")
	_, _ = h(context.Background(), rec, req, nil)
	return rec.Code, called, seen
}

// E-01 pairs of Authorize: a public operation runs without an identity;
// a machine token is refused on a role operation, a session admitted; a
// police session is refused on a console operation unless the operation
// names the police realm; an any-session operation admits a session
// without roles and refuses a machine token.
func TestAuthorizeRules(t *testing.T) {
	rules := Rules{
		Public:     map[string]bool{"Pub": true},
		AnySession: map[string]bool{"Mine": true},
		Roles:      map[string][]string{"Admin": {RoleAdmin}, "Police": {RoleAdmin}},
		Scopes:     map[string]string{"Machine": "registry.validate"},
		Realms:     map[string]string{"Police": RealmPolice},
	}
	session := Identity{ActorType: "user", Subject: "u", Roles: []string{RoleAdmin}, Realm: RealmConsole, Session: true}
	machine := Identity{ActorType: "client", Subject: "cisp-01", Scopes: []string{"cis.read"}}
	police := Identity{ActorType: "user", Subject: "p", Roles: []string{RoleAdmin}, Realm: RealmPolice, Session: true}
	bare := Identity{ActorType: "user", Subject: "v", Realm: RealmConsole, Session: true}
	cases := []struct {
		name   string
		id     Identity
		err    error
		op     string
		code   int
		called bool
	}{
		{"public without identity", Identity{}, ErrNoSession, "Pub", 200, true},
		{"role op without identity", Identity{}, ErrNoSession, "Admin", 401, false},
		{"machine on role op", machine, nil, "Admin", 403, false},
		{"session on role op", session, nil, "Admin", 200, true},
		{"police on console op", police, nil, "Admin", 403, false},
		{"police on police op", police, nil, "Police", 200, true},
		{"console on police op", session, nil, "Police", 403, false},
		{"no roles on any-session op", bare, nil, "Mine", 200, true},
		{"machine on any-session op", machine, nil, "Mine", 403, false},
		{"no rule", session, nil, "Unknown", 403, false},
		{"machine with the scope", Identity{ActorType: "client", Subject: "ussp-A-01", Scopes: []string{"registry.validate"}}, nil, "Machine", 200, true},
		{"machine without the scope", machine, nil, "Machine", 403, false},
		{"session on a scope op", session, nil, "Machine", 403, false},
	}
	for _, c := range cases {
		code, called, ri := authorized(rules, c.id, c.err, c.op)
		if code != c.code || called != c.called {
			t.Errorf("%s: %d called %v", c.name, code, called)
		}
		if called && ri.UserAgent != "probe" {
			t.Errorf("%s: request info %+v", c.name, ri)
		}
	}
}

// xScopes reads x-scope of every operation from api/openapi.yaml.
func xScopes(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	scopeRe := regexp.MustCompile(`^\s+x-scope:\s*(\S+)`)
	out := map[string]string{}
	op := ""
	for line := range strings.SplitSeq(string(raw), "\n") {
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
			continue
		}
		if m := scopeRe.FindStringSubmatch(line); m != nil && op != "" {
			out[op] = strings.TrimSpace(m[1])
		}
	}
	return out
}

// WP-3: the machine operations and their scopes match the contract, and
// no operation is both a machine and a role (or public) operation.
func TestScopesMatchTheContract(t *testing.T) {
	spec := xScopes(t)
	if len(spec) == 0 {
		t.Fatal("no x-scope found in api/openapi.yaml")
	}
	if !maps.Equal(spec, Scopes) {
		t.Errorf("contract %v, code %v", spec, Scopes)
	}
	for op := range Scopes {
		if _, ok := Roles[op]; ok || Public[op] || AnySession[op] {
			t.Errorf("%s is a scope operation and also has another rule", op)
		}
	}
	if DefaultRules().Scopes["ValidateRegistry"] != "registry.validate" {
		t.Error("DefaultRules does not carry the scopes")
	}
}

// WP-19: Realms mirrors x-realm in the contract, every police operation
// is held to the police realm's grant, and the default rules refuse a
// console session (even an admin's) on a police operation and a police
// session on a console one (E-01, through DefaultRules).
func TestRealmsMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	realmRe := regexp.MustCompile(`^\s+x-realm:\s*(\S+)`)
	spec := map[string]string{}
	op := ""
	for line := range strings.SplitSeq(string(raw), "\n") {
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
			continue
		}
		if m := realmRe.FindStringSubmatch(line); m != nil && op != "" {
			spec[op] = m[1]
		}
	}
	if len(spec) == 0 {
		t.Fatal("no x-realm in the contract")
	}
	for op, realm := range spec {
		if Realms[op] != realm {
			t.Errorf("%s: contract %q, code %q", op, realm, Realms[op])
		}
	}
	for op, realm := range Realms {
		if spec[op] != realm {
			t.Errorf("%s: code %q, contract %q", op, realm, spec[op])
		}
		if realm == RealmPolice && !slices.Equal(Roles[op], PoliceRoles) {
			t.Errorf("%s: roles %v", op, Roles[op])
		}
	}
	admin := Identity{ActorType: "user", Subject: "a", Roles: []string{RoleAdmin, RolePoliceQuery}, Realm: RealmConsole, Session: true}
	police := Identity{ActorType: "user", Subject: "p", Roles: []string{RolePoliceQuery}, Realm: RealmPolice, Session: true}
	machine := Identity{ActorType: "client", Subject: "x-01", Scopes: []string{"police.query"}}
	for _, c := range []struct {
		name   string
		id     Identity
		op     string
		called bool
	}{
		{"police on a police op", police, "QueryPoliceAircraft", true},
		{"console admin on a police op", admin, "QueryPoliceAircraft", false},
		{"machine with police.query on a police op", machine, "QueryPoliceOperator", false},
		{"police on a console op", police, "ListUsers", false},
		{"police on the DPO report", police, "GetDPOReport", false},
		{"police without its grant", Identity{ActorType: "user", Subject: "p", Realm: RealmPolice, Session: true}, "QueryPoliceSerial", false},
	} {
		if _, called, _ := authorized(DefaultRules(), c.id, nil, c.op); called != c.called {
			t.Errorf("%s: called %v", c.name, called)
		}
	}
}
