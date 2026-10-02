package tokens

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// serve mounts the token service as cmd/api does, with who as the
// identity of every non-public request.
func serve(t *testing.T, f *fixture, who string) *httptest.Server {
	t.Helper()
	identify := func(*http.Request) (apiserver.Identity, error) {
		if who == "" {
			return apiserver.NoSession(nil)
		}
		return apiserver.Identity{ActorType: "user", Subject: who, Roles: []string{apiserver.RoleAdmin}, Realm: "console", Session: true}, nil
	}
	mux := http.NewServeMux()
	apiserver.Mount(mux, apiserver.Server{TokenHandler: f.parts.Handler, OAuthAdminHandler: f.parts.Handler}, apiserver.Options{
		Middlewares: []apiserver.Middleware{f.parts.Handler.FormGuard(), apiserver.Authorize(identify, apiserver.DefaultRules())},
		Keep:        apiserver.PathPrefix("/v1/", "/oauth/", "/.well-known/"),
	})
	mux.HandleFunc("/", httpx.NotFound)
	srv := httptest.NewServer(httpx.Baseline(mux, discardLogger(), httpx.BaselineDeps{Counters: f.parts.Counters}))
	t.Cleanup(srv.Close)
	return srv
}

type reply struct {
	code   int
	header http.Header
	body   map[string]any
}

func do(t *testing.T, method, u, contentType, body string) reply {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return reply{resp.StatusCode, resp.Header, m}
}

const form = "application/x-www-form-urlencoded"

func TestTokenEndpointOverHTTP(t *testing.T) {
	f := newFixture(t, fixtureOpts{burst: 3})
	srv := serve(t, f, "")
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	v := url.Values{"grant_type": {"client_credentials"}, "client_id": {"cisp-01"}, "client_secret": {secret},
		"scope": {"cis.read"}, "audience": {"https://" + cispHost}}
	r := do(t, http.MethodPost, srv.URL+"/oauth/token", form, v.Encode())
	if r.code != 200 || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" ||
		r.body["token_type"] != "Bearer" || r.body["expires_in"] != 3600.0 || r.body["scope"] != "cis.read" || r.body["access_token"] == "" {
		t.Fatalf("accepted: %d %v %v", r.code, r.header, r.body)
	}

	wrong := url.Values{"grant_type": {"client_credentials"}, "client_id": {"cisp-01"}, "client_secret": {"nope"}, "scope": {"cis.read"}, "audience": {cispHost}}
	r = do(t, http.MethodPost, srv.URL+"/oauth/token", form, wrong.Encode())
	if r.code != 401 || r.body["error"] != "invalid_client" || r.body["type"] != httpx.ProblemTypeBase+"invalid_client" ||
		r.header.Get("Content-Type") != httpx.ProblemContentType {
		t.Fatalf("wrong secret: %d %v", r.code, r.body)
	}
	scope := url.Values{"grant_type": {"client_credentials"}, "client_id": {"cisp-01"}, "client_secret": {secret}, "scope": {"rid.observe"}, "audience": {cispHost}}
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token", form, scope.Encode()); r.code != 400 || r.body["error"] != "invalid_scope" {
		t.Fatalf("bad scope: %d %v", r.code, r.body)
	}
	// Parameters in the query string, the wrong content type and a
	// repeated parameter are refused before the grant, and recorded.
	refusedBefore := len(f.st.eventsOf(audit.EventTokenRefused))
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token?client_secret="+secret, form, v.Encode()); r.code != 400 || r.body["error"] != "invalid_request" {
		t.Fatalf("query: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token", "application/json", `{"grant_type":"client_credentials"}`); r.code != 400 || r.body["error"] != "invalid_request" {
		t.Fatalf("json body: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token", form, v.Encode()+"&client_id=ansp-01"); r.code != 400 || r.body["error"] != "invalid_request" {
		t.Fatalf("repeated: %d %v", r.code, r.body)
	}
	if n := len(f.st.eventsOf(audit.EventTokenRefused)) - refusedBefore; n != 3 {
		t.Fatalf("%d refusal events for 3 guarded refusals", n)
	}
	// resource may repeat (RFC 8707) and is judged by the grant.
	res := url.Values{"grant_type": {"client_credentials"}, "client_id": {"cisp-01"}, "client_secret": {secret}, "scope": {"cis.read"},
		"resource": {"https://" + cispHost + "/a", "https://" + cispHost + "/b"}}
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token", form, res.Encode()); r.code != 200 {
		t.Fatalf("two resources of one host: %d %v", r.code, r.body)
	}
	// Burst 3 is spent (every authenticated request counts, the refused
	// scope included): 429 with Retry-After.
	if r = do(t, http.MethodPost, srv.URL+"/oauth/token", form, v.Encode()); r.code != 429 || r.header.Get("Retry-After") == "" || r.body["error"] != "temporarily_unavailable" {
		t.Fatalf("over budget: %d %v %v", r.code, r.header, r.body)
	}
}

func TestJWKSAndMetadataOverHTTP(t *testing.T) {
	f := newFixture(t, fixtureOpts{publication: true})
	srv := serve(t, f, "")
	r := do(t, http.MethodGet, srv.URL+"/.well-known/jwks.json", "", "")
	keys, _ := r.body["keys"].([]any)
	if r.code != 200 || r.header.Get("Cache-Control") != "public, max-age=300" || len(keys) != 2 {
		t.Fatalf("jwks: %d %v %v", r.code, r.header, r.body)
	}
	for _, k := range keys {
		m := k.(map[string]any)
		if m["d"] != nil || m["p"] != nil || m["use"] != "sig" || m["alg"] != "RS256" {
			t.Fatalf("published key %v", m)
		}
	}
	r = do(t, http.MethodGet, srv.URL+"/.well-known/openid-configuration", "", "")
	if r.code != 200 || r.body["issuer"] != testIssuer || r.body["jwks_uri"] != testIssuer+"/.well-known/jwks.json" ||
		r.body["token_endpoint"] != testIssuer+"/oauth/token" || r.header.Get("Cache-Control") == "" {
		t.Fatalf("metadata: %d %v", r.code, r.body)
	}
	if g := r.body["grant_types_supported"].([]any); len(g) != 1 || g[0] != "client_credentials" {
		t.Fatalf("grants %v", g)
	}
	for _, s := range r.body["scopes_supported"].([]any) {
		if sc, _ := LookupScope(s.(string)); sc.Reserved || sc.ForeignIssuer {
			t.Fatalf("scopes_supported lists %v", s)
		}
	}
}

// The admin routes: refused without a session, served to an admin; the
// secret is shown once at creation and never again.
func TestClientRegistryOverHTTP(t *testing.T) {
	f := newFixture(t, fixtureOpts{keys: 2, twoPerson: true})
	anon := serve(t, f, "")
	if r := do(t, http.MethodGet, anon.URL+"/v1/oauth/clients", "", ""); r.code != 401 {
		t.Fatalf("anonymous: %d", r.code)
	}
	srv := serve(t, f, "admin-1")
	body := `{"client_id":"cisp-01","scopes":["cis.read","cis.publish:restrictions"],"audiences":["` + cispHost + `"],"auth_method":"client_secret_post"}`
	r := do(t, http.MethodPost, srv.URL+"/v1/oauth/clients", "application/json", body)
	if r.code != 201 || r.body["client_secret"] == "" {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	secret := r.body["client_secret"].(string)
	client := r.body["client"].(map[string]any)
	if client["system"] != "cisp" || client["status"] != "active" || client["created_by"] != "admin-1" {
		t.Fatalf("client %v", client)
	}
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/clients", "application/json", body); r.code != 409 {
		t.Fatalf("duplicate: %d %v", r.code, r.body)
	}
	r = do(t, http.MethodGet, srv.URL+"/v1/oauth/clients/cisp-01", "", "")
	if r.code != 200 || r.body["client_secret"] != nil || strings.Contains(mustJSON(r.body), secret) || strings.Contains(mustJSON(r.body), "argon2") {
		t.Fatalf("read back leaks the secret: %v", r.body)
	}
	if r = do(t, http.MethodGet, srv.URL+"/v1/oauth/clients/cisp-99", "", ""); r.code != 404 {
		t.Fatalf("missing: %d", r.code)
	}
	r = do(t, http.MethodPatch, srv.URL+"/v1/oauth/clients/cisp-01", "application/json", `{"status":"suspended"}`)
	if r.code != 200 || r.body["status"] != "suspended" {
		t.Fatalf("suspend: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPatch, srv.URL+"/v1/oauth/clients/cisp-01", "application/json", `{"scopes":["rid.observe"]}`); r.code != 400 {
		t.Fatalf("bad scope: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPatch, srv.URL+"/v1/oauth/clients/cisp-77", "application/json", `{"note":"x"}`); r.code != 404 {
		t.Fatalf("patch missing: %d", r.code)
	}
	r = do(t, http.MethodGet, srv.URL+"/v1/oauth/clients", "", "")
	if cs := r.body["clients"].([]any); r.code != 200 || len(cs) != 1 {
		t.Fatalf("list: %d %v", r.code, r.body)
	}
	// A private_key_jwt client shows its public JWKS.
	jwksBody := `{"client_id":"ussp-GEO1-01","scopes":["rid.service_provider"],"auth_method":"private_key_jwt","jwks":` + string(clientJWKS(t, 3, "k1")) + `}`
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/clients", "application/json", jwksBody); r.code != 201 || r.body["client_secret"] != nil {
		t.Fatalf("key client: %d %v", r.code, r.body)
	}

	// Keys and the two-person rotation over HTTP.
	r = do(t, http.MethodGet, srv.URL+"/v1/oauth/keys", "", "")
	if ks := r.body["keys"].([]any); r.code != 200 || len(ks) != 2 || ks[0].(map[string]any)["state"] != "active" || ks[1].(map[string]any)["state"] != "candidate" {
		t.Fatalf("keys: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/keys/rotate", "", ""); r.code != 202 || r.body["state"] != "requested" {
		t.Fatalf("request: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/keys/rotate", "", ""); r.code != 409 {
		t.Fatalf("same admin: %d %v", r.code, r.body)
	}
	second := serve(t, f, "admin-2")
	if r = do(t, http.MethodPost, second.URL+"/v1/oauth/keys/rotate", "", ""); r.code != 200 || r.body["state"] != "activated" || r.body["previous_kid"] == nil {
		t.Fatalf("confirm: %d %v", r.code, r.body)
	}
	r = do(t, http.MethodGet, srv.URL+"/v1/oauth/keys", "", "")
	if ks := r.body["keys"].([]any); ks[0].(map[string]any)["state"] != "retiring" || ks[1].(map[string]any)["state"] != "active" {
		t.Fatalf("keys after: %v", r.body)
	}
	retiring := r.body["keys"].([]any)[0].(map[string]any)["kid"].(string)
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/keys/"+retiring+"/compromised", "application/json", `{"reason":"leaked"}`); r.code != 200 ||
		r.body["state"] != "compromised" || r.body["compromise_reason"] != "leaked" {
		t.Fatalf("compromise: %d %v", r.code, r.body)
	}
	if r = do(t, http.MethodPost, srv.URL+"/v1/oauth/keys/"+retiring+"/compromised", "application/json", `{"reason":"again"}`); r.code != 409 {
		t.Fatalf("compromise twice: %d", r.code)
	}
	if r = do(t, http.MethodPost, anon.URL+"/v1/oauth/keys/"+retiring+"/compromised", "application/json", `{"reason":"x"}`); r.code != 401 {
		t.Fatalf("anonymous compromise: %d", r.code)
	}
}

func TestAdminHandlersRefuseWithoutIdentityOrBody(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	h := f.parts.Handler
	ctx := context.Background()
	if _, err := h.CreateOAuthClient(ctx, genCreate(nil)); err == nil {
		t.Fatal("create without identity")
	}
	if _, err := h.UpdateOAuthClient(ctx, genUpdate("cisp-01", nil)); err == nil {
		t.Fatal("update without identity")
	}
	if _, err := h.RotateSigningKey(ctx, genRotate()); err == nil {
		t.Fatal("rotate without identity")
	}
	ctx = apiserver.WithIdentity(ctx, apiserver.Identity{ActorType: "user", Subject: "admin-1", Realm: "console", Session: true})
	if _, err := h.CreateOAuthClient(ctx, genCreate(nil)); err == nil {
		t.Fatal("create without body")
	}
	if _, err := h.UpdateOAuthClient(ctx, genUpdate("cisp-01", nil)); err == nil {
		t.Fatal("update without body")
	}
	f.st.failReads = true
	if _, err := h.ListOAuthClients(ctx, genList()); err == nil {
		t.Fatal("list with the store down")
	}
	if _, err := h.ListSigningKeys(ctx, genKeys()); err == nil {
		t.Fatal("keys with the store down")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func genCreate(b *gen.OAuthClientInput) gen.CreateOAuthClientRequestObject {
	return gen.CreateOAuthClientRequestObject{Body: b}
}

func genUpdate(id string, b *gen.OAuthClientPatch) gen.UpdateOAuthClientRequestObject {
	return gen.UpdateOAuthClientRequestObject{ClientId: id, Body: b}
}

func genRotate() gen.RotateSigningKeyRequestObject { return gen.RotateSigningKeyRequestObject{} }
func genList() gen.ListOAuthClientsRequestObject   { return gen.ListOAuthClientsRequestObject{} }
func genKeys() gen.ListSigningKeysRequestObject    { return gen.ListSigningKeysRequestObject{} }
