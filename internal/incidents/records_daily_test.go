package incidents

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type dailyToken struct{}

func (dailyToken) Token(context.Context, string, ...string) (string, error) { return "tok", nil }

// WP-27, 02 F7: the daily bundle is read with the token and kept as
// received (presence); a 404 is ErrNoDay, a redirect is not followed, a
// body that is not one JSON object or is past the bound is refused, and
// without a client nothing is requested (absence).
func TestFetchDailyReadsTheBundleAndRefusesTheRest(t *testing.T) {
	day := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/ok/v1/records/daily/2026-09-30":
			_, _ = w.Write([]byte(` {"flights": [1, 2]} `))
		case "/redirect/v1/records/daily/2026-09-30":
			http.Redirect(w, r, "/ok/v1/records/daily/2026-09-30", http.StatusFound)
		case "/text/v1/records/daily/2026-09-30":
			_, _ = w.Write([]byte(`not json`))
		case "/big/v1/records/daily/2026-09-30":
			_, _ = w.Write([]byte(`{"x": "` + strings.Repeat("a", 100) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	r := &Records{Tokens: dailyToken{}, HTTP: srv.Client()}
	ctx := context.Background()
	b, err := r.FetchDaily(ctx, srv.URL+"/ok", day, time.Second, 1024)
	if err != nil || string(b) != ` {"flights": [1, 2]} ` {
		t.Fatalf("ok: %q %v", b, err)
	}
	if _, err := r.FetchDaily(ctx, srv.URL+"/none", day, time.Second, 1024); !errors.Is(err, ErrNoDay) {
		t.Fatalf("404: %v", err)
	}
	if _, err := r.FetchDaily(ctx, srv.URL+"/redirect", day, time.Second, 1024); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := r.FetchDaily(ctx, srv.URL+"/text", day, time.Second, 1024); err == nil {
		t.Fatal("a body that is not JSON was accepted")
	}
	if _, err := r.FetchDaily(ctx, srv.URL+"/big", day, time.Second, 50); err == nil {
		t.Fatal("a body past the bound was accepted")
	}
	n := len(paths)
	if _, err := (&Records{}).FetchDaily(ctx, srv.URL+"/ok", day, time.Second, 1024); !errors.Is(err, ErrNoRecordsClient) || len(paths) != n {
		t.Fatalf("no client: %v (%d requests)", err, len(paths)-n)
	}
	if _, err := r.FetchDaily(ctx, "http://example.test", day, time.Second, 1024); err == nil {
		t.Fatal("plain http to a remote host was accepted")
	}
}
