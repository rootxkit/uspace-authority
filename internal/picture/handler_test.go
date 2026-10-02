package picture

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

const consoleOrigin = "https://authority.example.test"

// pictureServer serves the three routes with the real session check
// against a fake api and returns the server and its WebSocket URL.
func pictureServer(t *testing.T, h *Hub, checker Checker) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	(&Handler{Hub: h, Sessions: checker, Origins: []string{consoleOrigin}, SessionTimeout: time.Second}).Mount(mux)
	mux.HandleFunc("/", httpx.NotFound)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/picture/ws"
}

func dial(t *testing.T, wsURL, origin, cookie string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	hd := http.Header{}
	if origin != "" {
		hd.Set("Origin", origin)
	}
	if cookie != "" {
		hd.Set("Cookie", CookieSession+"="+cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hd})
	if c != nil {
		c.SetReadLimit(1 << 24)
	}
	return c, resp, err
}

// closeOf reads until the connection closes and returns the close code.
func closeOf(t *testing.T, c *websocket.Conn) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

func readFrame(t *testing.T, c *websocket.Conn) frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, raw, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return validateFrame(t, raw)
}

// M22, E-01: the upgrade with a live console session from an allowed
// origin is served (status, then snapshot); without the cookie, with a
// machine token in it, with a revoked session, or with a token in the
// query string instead of the cookie, it is closed with 4401; with a
// wrong Origin, or none, it is refused 403 and never upgraded.
func TestUpgradeRefusedBesideTheAcceptedOne(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1")
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	srv, wsURL := pictureServer(t, h, api.checker(t, ti))
	_ = srv

	c, _, err := dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil {
		t.Fatalf("accepted upgrade: %v", err)
	}
	if f := readFrame(t, c); f.Schema != SchemaStatus || f.Producer != Producer {
		t.Fatalf("first frame %+v", f)
	}
	if f := readFrame(t, c); f.Schema != SchemaSnapshot {
		t.Fatalf("second frame %s", f.Schema)
	}
	_ = c.Close(websocket.StatusNormalClosure, "")

	for name, cookie := range map[string]string{
		"no cookie":       "",
		"machine token":   ti.machine(t),
		"revoked session": ti.session(t, RealmConsole, "revoked-1", time.Hour),
		"garbage":         "not-a-token",
	} {
		c, _, err := dial(t, wsURL, consoleOrigin, cookie)
		if err != nil {
			t.Fatalf("%s: upgrade failed: %v", name, err)
		}
		if code := closeOf(t, c); code != CloseRelogin {
			t.Errorf("%s: closed %d, want 4401", name, code)
		}
	}
	// A ticket in the query string is not a session (M22).
	c, _, err = dial(t, wsURL+"?token="+ti.session(t, RealmConsole, "live-1", time.Hour), consoleOrigin, "")
	if err != nil {
		t.Fatal(err)
	}
	if code := closeOf(t, c); code != CloseRelogin {
		t.Fatalf("query-string token: closed %d", code)
	}
	for name, origin := range map[string]string{"wrong origin": "https://evil.example.test", "no origin": "", "port differs": consoleOrigin + ":8443"} {
		_, resp, err := dial(t, wsURL, origin, ti.session(t, RealmConsole, "live-1", time.Hour))
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %v %v", name, err, resp)
		}
	}
	if h.Counters().Get(CounterRefusedOrigin) != 3 || h.Len() != 0 {
		t.Fatalf("origin refusals %d, consoles %d", h.Counters().Get(CounterRefusedOrigin), h.Len())
	}
}

// With api unreachable the upgrade is closed with 1013 (fail closed, not
// a re-login); a plain GET is 426; a full instance is 503 with
// Retry-After.
func TestUpgradeUnavailableNotUpgradeAndFull(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1")
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.MaxClients = time.Hour, 1 })
	srv, wsURL := pictureServer(t, h, api.checker(t, ti))
	api.broken.Store(true)
	c, _, err := dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if code := closeOf(t, c); code != CloseTryAgainLater {
		t.Fatalf("api down: closed %d", code)
	}
	api.broken.Store(false)

	resp, err := http.Get(srv.URL + "/v1/picture/ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET: %d", resp.StatusCode)
	}

	held, _, err := dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	readFrame(t, held)
	_, resp, err = dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("full: %v %v", err, resp)
	}
	_ = held.Close(websocket.StatusNormalClosure, "")
}

// GET /v1/picture/snapshot: the snapshot frame of the box itself (a
// track in the margin cell is left out, the WebSocket viewport holds
// it); bbox missing, malformed or too large is 400 naming bbox; no
// session is 401; an Origin outside the list is 403.
func TestHTTPSnapshot(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1")
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.MaxCells = time.Hour, 500 })
	srv, _ := pictureServer(t, h, api.checker(t, ti))
	now := time.Now()
	h.OfferTrack(trackMsg(t, "inside", 41.715, 44.825, now, core.IdentRegistered), now)
	h.OfferTrack(trackMsg(t, "margin", 41.715, 44.905, now, core.IdentRegistered), now)
	tok := ti.session(t, RealmConsole, "live-1", time.Hour)
	get := func(query, auth, origin string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/picture/snapshot"+query, nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := get("?bbox=44.81,41.71,44.85,41.72", tok, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	snap := snapshotOf(t, validateFrame(t, body))
	if len(snap.Tracks) != 1 || trackOf(t, snap.Tracks[0]).TrackID != "inside" {
		t.Fatalf("tracks %d", len(snap.Tracks))
	}
	// The same box over the WebSocket holds the margin cell's track.
	conn := connect(t, h, consoleSession(), nil)
	if _, ws := subscribe(t, conn, subscribeFrameOf(44.81, 41.71, 44.85, 41.72)); len(ws.Tracks) != 2 {
		t.Fatalf("websocket snapshot %d tracks", len(ws.Tracks))
	}
	for q, field := range map[string]string{"": "bbox", "?bbox=1,2,3": "bbox", "?bbox=a,b,c,d": "bbox", "?bbox=30,30,50,50": "bbox",
		"?bbox=44.81,41.71,44.85,41.72&layers=planes": "layers"} {
		resp, body := get(q, tok, "")
		var p struct {
			Errors []struct{ Field string } `json:"errors"`
		}
		_ = json.Unmarshal(body, &p)
		if resp.StatusCode != http.StatusBadRequest || len(p.Errors) == 0 || p.Errors[0].Field != field {
			t.Errorf("%q: %d %s", q, resp.StatusCode, body)
		}
	}
	if resp, _ := get("?bbox=44.81,41.71,44.85,41.72", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
	if resp, _ := get("?bbox=44.81,41.71,44.85,41.72", ti.machine(t), ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("machine token: %d", resp.StatusCode)
	}
	if resp, _ := get("?bbox=44.81,41.71,44.85,41.72", tok, "https://evil.example.test"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", resp.StatusCode)
	}
	if resp, _ := get("?bbox=44.81,41.71,44.85,41.72", tok, consoleOrigin); resp.StatusCode != http.StatusOK {
		t.Fatalf("own origin: %d", resp.StatusCode)
	}
	api.broken.Store(true)
	if resp, _ := get("?bbox=44.81,41.71,44.85,41.72", tok, ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("api down: %d", resp.StatusCode)
	}
}

// GET /v1/picture/sources: every source with its state and the extras,
// for a session only.
func TestHTTPSources(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1")
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	h.Tick(time.Now())
	mux := http.NewServeMux()
	(&Handler{Hub: h, Sessions: api.checker(t, ti), Origins: []string{consoleOrigin}, SourcesState: func(time.Time) SourcesExtras {
		return SourcesExtras{RegistryAgeS: f64(2), NATS: NATSUnavailable, NATSSince: ptr("2026-10-02T09:15:06.000Z")}
	}}).Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/picture/sources", nil)
	req.AddCookie(&http.Cookie{Name: CookieSession, Value: ti.session(t, RealmConsole, "live-1", time.Hour)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b sourcesBody
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %v", resp.StatusCode, err)
	}
	if b.NATS != NATSUnavailable || b.RegistryAgeS == nil || b.Sources == nil {
		t.Fatalf("%+v", b)
	}
	resp2, err := http.Get(srv.URL + "/v1/picture/sources")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", resp2.StatusCode)
	}
}

// A binary message from the console is not a subscription: closed 1007.
func TestBinaryFrameRefused(t *testing.T) {
	ti := newTestIssuer(t)
	api := newFakeAPI(t, ti, "live-1")
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	_, wsURL := pictureServer(t, h, api.checker(t, ti))
	c, _, err := dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	readFrame(t, c)
	readFrame(t, c)
	if err := c.Write(context.Background(), websocket.MessageBinary, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if code := closeOf(t, c); code != CloseInvalid {
		t.Fatalf("closed %d", code)
	}
	// And an oversized frame is closed by the read limit (1009).
	c, _, err = dial(t, wsURL, consoleOrigin, ti.session(t, RealmConsole, "live-1", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	readFrame(t, c)
	readFrame(t, c)
	_ = c.Write(context.Background(), websocket.MessageText, []byte(strings.Repeat(" ", 10000)))
	if code := closeOf(t, c); code != CloseTooBig {
		t.Fatalf("closed %d", code)
	}
}
