package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// The integration kit: picture-ws runs as a process (proc.Main) against
// the development stack's NATS and a migrated scratch telemetry
// database; api's session check and this issuer's JWKS are served by a
// stand-in on a loopback address with a key generated for the test
// (CLAUDE.md rule 11). cmd/api's integration tests run the same check
// against the real api and its sessions table.

const (
	publicURL     = "https://authority.example.test"
	ownHost       = "authority.example.test"
	consoleOrigin = "https://authority.example.test"
)

// lines is a goroutine-safe stdout read back as JSON log lines.
type lines struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lines) find(msg string) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found map[string]any
	sc := bufio.NewScanner(bytes.NewReader(l.b.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["msg"] == msg {
			found = m
		}
	}
	return found
}

func (l *lines) tail(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	all := strings.Split(strings.TrimRight(l.b.String(), "\n"), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return strings.Join(all, "\n")
}

func (l *lines) waitFor(t testing.TB, msg string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := l.find(msg); m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %q line; stdout:\n%s", msg, l.tail(60))
	return nil
}

func natsURL(t testing.TB) string {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs NATS JetStream and TimescaleDB (make up)")
	}
	u := os.Getenv("NATS_URL")
	if u == "" {
		t.Fatal("INTEGRATION=1 but NATS_URL is unset")
	}
	return u
}

// sessionAPI stands in for api: this issuer's JWKS and GET
// /v1/auth/session (200 for a live jti, 401 otherwise).
type sessionAPI struct {
	srv  *httptest.Server
	iss  *auth.Issuer
	mu   sync.Mutex
	live map[string]bool
}

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func newSessionAPI(t testing.TB) *sessionAPI {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	iss, err := auth.NewIssuer(publicURL, testKey, "picture-test-1")
	if err != nil {
		t.Fatal(err)
	}
	s := &sessionAPI{iss: iss, live: map[string]bool{}}
	jwks, err := json.Marshal(iss.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{publicURL: {Keys: iss.JWKS()}}, Audiences: []string{ownHost}, StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("GET /v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		cl, err := v.Verify(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		s.mu.Lock()
		live := err == nil && s.live[cl.JTI]
		s.mu.Unlock()
		if !live {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":401,"detail":"the session was ended"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": cl.Subject, "roles": cl.Roles, "realm": cl.Realm, "jti": cl.JTI,
			"expires_at": cl.ExpiresAt.UTC().Format(time.RFC3339), "idle_expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// session issues a live console session.
func (s *sessionAPI) session(t testing.TB, jti string) string {
	t.Helper()
	now := time.Now()
	tok, err := s.iss.IssueSession(auth.SessionClaims{Audience: ownHost, Subject: "u-" + jti, Roles: []string{"viewer"},
		Realm: picture.RealmConsole, IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: jti})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.live[jti] = true
	s.mu.Unlock()
	return tok
}

// pictureProc is a running picture-ws.
type pictureProc struct {
	base, ws string
	out      *lines
	stop     func()
}

// startPicture runs picture-ws with env (the defaults below, changed by
// change) until the test ends.
func startPicture(t testing.TB, api *sessionAPI, natsURL string, change func(map[string]string)) *pictureProc {
	t.Helper()
	m := map[string]string{
		"NATS_URL": natsURL, "TS_URL": storetest.Migrated(t, migrate.Timeseries), "AUTHORITY_PUBLIC_URL": publicURL,
		"PICTURE_SESSION_URL": api.srv.URL + "/v1/auth/session", "PICTURE_JWKS_URL": api.srv.URL + "/.well-known/jwks.json",
		"PICTURE_ALLOWED_ORIGINS": consoleOrigin, "PICTURE_ADDR": "127.0.0.1:0", "ADMIN_ADDR": "127.0.0.1:0",
		"STATUS_INTERVAL_S": "1", "SHUTDOWN_TIMEOUT_S": "10", "PICTURE_STATUS_INTERVAL_MS": "500",
		"PICTURE_PROJECTION_REFRESH_S": "1", "NATS_START_ATTEMPTS": "1", "NATS_START_BACKOFF_MS": "10",
		"HTTP_RATE_LIMIT_RPS": "1000", "HTTP_RATE_LIMIT_BURST": "1000",
	}
	if change != nil {
		change(m)
	}
	out := &lines{}
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	cfg := &config.PictureWS{}
	go func() {
		exit <- proc.Main(ctx, specWith(cfg, picture.Options{BusCheckEvery: 100 * time.Millisecond}), nil, out, io.Discard,
			func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case code := <-exit:
				if code != proc.ExitOK {
					t.Errorf("picture-ws exit %d:\n%s", code, out.tail(40))
				}
			case <-time.After(30 * time.Second):
				t.Error("picture-ws did not stop")
			}
		})
	}
	t.Cleanup(stop)
	listen := out.waitFor(t, "public listener open")
	addr := listen["addr"].(string)
	return &pictureProc{base: "http://" + addr, ws: "ws://" + addr + "/v1/picture/ws", out: out, stop: stop}
}

// console is a WebSocket console with its frames.
type console struct {
	c      *websocket.Conn
	frames chan []byte
	errc   chan error
	// delay slows the reader down (a console that falls behind).
	delay time.Duration
}

func dialConsole(t testing.TB, wsURL, token string, delay time.Duration) *console {
	t.Helper()
	hd := http.Header{"Origin": {consoleOrigin}, "Cookie": {picture.CookieSession + "=" + token}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hd})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.SetReadLimit(64 << 20)
	k := &console{c: c, frames: make(chan []byte, 1<<16), errc: make(chan error, 1), delay: delay}
	go func() {
		for {
			_, raw, err := c.Read(context.Background())
			if err != nil {
				k.errc <- err
				close(k.frames)
				return
			}
			if k.delay > 0 {
				time.Sleep(k.delay)
			}
			k.frames <- raw
		}
	}()
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return k
}

func (k *console) subscribe(t testing.TB, w, s, e, n float64) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"schema": picture.SchemaSubscribe,
		"body": map[string]any{"bbox": []float64{w, s, e, n}, "layers": []string{"tracks", "manned", "alerts", "zones"}}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := k.c.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
}

// envelope is what a test reads of every frame.
type envelope struct {
	Schema   string          `json:"schema"`
	Producer string          `json:"producer"`
	Body     json.RawMessage `json:"body"`
}

// until reads frames until ok accepts one of schema, within d.
func (k *console) until(t testing.TB, schema string, d time.Duration, ok func(envelope) bool) envelope {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case raw, open := <-k.frames:
			if !open {
				t.Fatalf("connection closed waiting for %s: %v", schema, <-k.errc)
			}
			var e envelope
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatalf("frame does not decode: %s", raw)
			}
			if e.Schema == schema && (ok == nil || ok(e)) {
				return e
			}
		case <-deadline:
			t.Fatalf("no matching %s within %s", schema, d)
		}
	}
}

func statusBody(t testing.TB, e envelope) picture.StatusBody {
	t.Helper()
	var b picture.StatusBody
	if err := json.Unmarshal(e.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func snapshotBody(t testing.TB, e envelope) picture.SnapshotBody {
	t.Helper()
	var b picture.SnapshotBody
	if err := json.Unmarshal(e.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// trackBody is what a test reads of a track frame.
type trackBody struct {
	TrackID        string              `json:"track_id"`
	Trust          core.Trust          `json:"trust"`
	Identification core.Identification `json:"identification"`
	AgeS           float64             `json:"age_s"`
	SourceState    string              `json:"source_state"`
}

func trackOf(t testing.TB, raw []byte) trackBody {
	t.Helper()
	var f struct {
		Body trackBody `json:"body"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Body
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func f64(v float64) *float64 { return &v }

// publishTrack publishes a direct Remote ID track on its trk.v1 subject.
func publishTrack(t testing.TB, nc *nats.Conn, id string, lat, lon float64, at time.Time) {
	t.Helper()
	ref := f3411.TakeoffLocation
	m, err := track.New("authority/rid-ingest", core.Times{RxTS: at, CapturedAt: at, Source: core.TimeReceiver}, track.Body{
		TrackID: id, Trust: core.TrustBroadcast, Source: track.SourceDirectRID, SourceInstance: "rx-int-1",
		Position: track.Position{Lat: lat, Lng: lon}, AltAMSLM: f64(500), AltSource: core.AltGeodetic, HeightM: f64(40), HeightRef: &ref,
		Identification: core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched, Basis: core.BasisAsBroadcast},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := track.Publish(nc, m); err != nil {
		t.Fatal(err)
	}
}

func connectNATS(t testing.TB) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(natsURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return nc, js
}

// ensureALRT opens (creating when missing) the ALRT stream, as api's
// provisioning would.
func ensureALRT(t testing.TB, js jetstream.JetStream) {
	t.Helper()
	cfg, ok := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamALRT)
	if !ok {
		t.Fatal("no ALRT in the topology")
	}
	if _, err := bus.OpenStream(context.Background(), js, cfg); err != nil {
		t.Fatal(err)
	}
}

// proxy is a TCP proxy to NATS the test can cut and restore: the bus
// lost as the process sees it.
type proxy struct {
	addr, upstream string
	mu             sync.Mutex
	ln             net.Listener
	conns          []net.Conn
}

func newProxy(t testing.TB, upstream string) *proxy {
	t.Helper()
	p := &proxy{upstream: upstream}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr = ln.Addr().String()
	p.serve(ln)
	t.Cleanup(p.cut)
	return p
}

func (p *proxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.upstream)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

// cut closes the listener and every connection.
func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// restore listens again on the same address.
func (p *proxy) restore(t testing.TB) {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	p.serve(ln)
}

func natsHostPort(t testing.TB, u string) string {
	t.Helper()
	s := strings.TrimPrefix(u, "nats://")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		t.Fatal(errors.New("NATS_URL has no host"))
	}
	return s
}
