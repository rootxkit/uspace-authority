package ltest

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TokenServer is a fake of this system's own token endpoint for the
// processes that ask it for tokens towards a peer (detect's DSS reads,
// WP-26): POST /oauth/token with client_credentials and
// client_secret_post. It answers a token whose claims the fake DSS
// reads unverified (aud the requested audience, scope, sub the client),
// and refuses a wrong client or secret with 401 invalid_client. The
// verification of real tokens is internal/tokens' and core's, tested
// there; no scenario judges it.
type TokenServer struct {
	srv      *httptest.Server
	ClientID string
	// SecretFile holds the client secret, generated at run time.
	SecretFile string
	issued     atomic.Int64
	refused    atomic.Int64
}

// NewTokenServer starts the endpoint for clientID with a secret written
// to a file under the test's temporary directory.
func NewTokenServer(t testing.TB, clientID string) *TokenServer {
	t.Helper()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(b[:])
	ts := &TokenServer{ClientID: clientID, SecretFile: filepath.Join(t.TempDir(), "client-secret")}
	if err := os.WriteFile(ts.SecretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" {
			ts.refused.Add(1)
			writeTokenJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		if r.PostForm.Get("client_id") != clientID ||
			subtle.ConstantTimeCompare([]byte(r.PostForm.Get("client_secret")), []byte(secret)) != 1 {
			ts.refused.Add(1)
			writeTokenJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		}
		claims, _ := json.Marshal(map[string]any{"aud": r.PostForm.Get("audience"), "scope": r.PostForm.Get("scope"), "sub": clientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iss": "ltest"})
		tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
			base64.RawURLEncoding.EncodeToString(claims) + ".ltest-unsigned"
		ts.issued.Add(1)
		writeTokenJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func writeTokenJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// URL is the endpoint's /oauth/token.
func (ts *TokenServer) URL() string { return ts.srv.URL + "/oauth/token" }

// Issued and Refused count the answers.
func (ts *TokenServer) Issued() int64 { return ts.issued.Load() }

// Refused counts refused requests.
func (ts *TokenServer) Refused() int64 { return ts.refused.Load() }

// HostURL is u with a loopback IP literal replaced by "localhost": an
// audience names a published host, never an IP (M18), so a process
// that asks for a token towards a fake at 127.0.0.1 is pointed at its
// host name instead.
func HostURL(u string) string {
	return strings.Replace(strings.Replace(u, "://127.0.0.1:", "://localhost:", 1), "://[::1]:", "://localhost:", 1)
}
