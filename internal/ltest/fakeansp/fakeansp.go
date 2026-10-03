// Package fakeansp is a fake ANSP manned traffic service for tests
// (WP-15): an HTTPS server implementing exactly the two operations of
// the ANSP's contract (the pinned api/clients/ansp.yaml) manned-ingest
// calls:
//
//   - GET /v1/manned-traffic/snapshot?bbox=: the MannedSnapshot of the
//     aircraft last sent, with degraded[] and adapters[];
//   - GET /v1/manned-traffic/stream?bbox= (WebSocket): on connect a
//     console/status/v1 and a console/snapshot/v1 frame, then whatever
//     the test sends, and console/status/v1 every StatusEvery.
//
// Both take a bearer (recorded with the bbox and whether a client
// certificate was presented). With RequireClientCert the TLS handshake
// requires a certificate of ClientCAs, as the ANSP does with
// ANSP_MTLS_MODE=required. Down refuses every request with 503 and
// closes the open streams until Up. Recording replays a recorded ADS-B
// track file (testdata/adsb-recording.jsonl, synthetic) restamped to now. It is
// imported by tests only (plan §3).
package fakeansp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// The ANSP's paths (api/clients/ansp.yaml).
const (
	PathSnapshot = "/v1/manned-traffic/snapshot"
	PathStream   = "/v1/manned-traffic/stream"
)

// Producer is the ANSP's feed process in its envelopes.
const Producer = "ansp/manned-feed"

// Request is one request the fake received.
type Request struct {
	Path          string
	Authorization string
	BBox          string
	ClientCert    bool
}

// Options configure a fake.
type Options struct {
	// RequireClientCert requires a client certificate of ClientCAs.
	RequireClientCert bool
	ClientCAs         *x509.CertPool
	// StatusEvery is the period of console/status/v1 (default 2 s).
	StatusEvery time.Duration
}

// ANSP is the fake.
type ANSP struct {
	srv  *httptest.Server
	opts Options

	mu       sync.Mutex
	requests []Request
	down     bool
	streams  map[*stream]bool
	last     map[string]json.RawMessage // icao24 -> last track frame
	adapters []map[string]any
	degraded []string
	connects int
}

type stream struct {
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func (s *stream) close() { s.once.Do(func() { close(s.done) }) }

// New starts a fake on TLS.
func New(o Options) *ANSP {
	if o.StatusEvery <= 0 {
		o.StatusEvery = 2 * time.Second
	}
	a := &ANSP{opts: o, streams: map[*stream]bool{}, last: map[string]json.RawMessage{}, degraded: []string{},
		adapters: []map[string]any{{"id": "adsb-tbs", "state": "live", "enabled": true, "last_frame_at": nil, "age_s": nil}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathSnapshot, a.snapshot)
	mux.HandleFunc("GET "+PathStream, a.stream)
	a.srv = httptest.NewUnstartedServer(mux)
	a.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	if o.RequireClientCert {
		a.srv.TLS.ClientAuth, a.srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, o.ClientCAs
	}
	a.srv.StartTLS()
	return a
}

// URL is the fake's base URL (https://127.0.0.1:port).
func (a *ANSP) URL() string { return a.srv.URL }

// RootCAs trusts the fake's server certificate.
func (a *ANSP) RootCAs() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.srv.Certificate())
	return p
}

// Close stops the fake.
func (a *ANSP) Close() {
	a.Down()
	a.srv.Close()
}

// Requests are the requests received so far.
func (a *ANSP) Requests() []Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Request(nil), a.requests...)
}

// Connects is how many streams were opened.
func (a *ANSP) Connects() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connects
}

// Open is how many streams are open.
func (a *ANSP) Open() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.streams)
}

// Down closes every stream and refuses requests with 503 until Up.
func (a *ANSP) Down() {
	a.mu.Lock()
	a.down = true
	for s := range a.streams {
		s.close()
	}
	a.mu.Unlock()
}

// Up accepts requests again.
func (a *ANSP) Up() {
	a.mu.Lock()
	a.down = false
	a.mu.Unlock()
}

// SetAdapter sets one adapter's state in status frames and snapshots.
func (a *ANSP) SetAdapter(id, state string, enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ad := range a.adapters {
		if ad["id"] == id {
			ad["state"], ad["enabled"] = state, enabled
			return
		}
	}
	a.adapters = append(a.adapters, map[string]any{"id": id, "state": state, "enabled": enabled, "last_frame_at": nil, "age_s": nil})
}

func (a *ANSP) record(r *http.Request) (bool, Request) {
	req := Request{Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), BBox: r.URL.Query().Get("bbox"),
		ClientCert: r.TLS != nil && len(r.TLS.PeerCertificates) > 0}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, req)
	return a.down, req
}

func (a *ANSP) snapshot(w http.ResponseWriter, r *http.Request) {
	down, req := a.record(r)
	switch {
	case down:
		http.Error(w, `{"type":"https://schemas.uspace.ge/problems/unavailable"}`, http.StatusServiceUnavailable)
		return
	case req.Authorization == "":
		http.Error(w, `{"type":"https://schemas.uspace.ge/problems/unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	now := time.Now()
	a.mu.Lock()
	body := map[string]any{"tracks": []any{}, "alerts": []any{}, "manned": a.mannedLocked(now), "zones_version": nil,
		"degraded": a.degraded, "adapters": a.adapters, "cis_version": nil, "cis_age_s": nil, "policy_version": "1",
		"generated_at": stamp(now)}
	b, _ := json.Marshal(body)
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (a *ANSP) mannedLocked(now time.Time) []json.RawMessage {
	out := []json.RawMessage{}
	for _, raw := range a.last {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		body, _ := m["body"].(map[string]any)
		if at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(m["captured_at"])); err == nil && body != nil {
			body["age_s"] = now.Sub(at).Seconds()
		}
		b, _ := json.Marshal(m)
		out = append(out, b)
	}
	return out
}

func (a *ANSP) stream(w http.ResponseWriter, r *http.Request) {
	down, req := a.record(r)
	switch {
	case down:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	case req.Authorization == "":
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	s := &stream{out: make(chan []byte, 1024), done: make(chan struct{})}
	now := time.Now()
	a.mu.Lock()
	a.streams[s] = true
	a.connects++
	snap := map[string]any{"tracks": []any{}, "alerts": []any{}, "manned": a.mannedLocked(now), "zones_version": nil}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.streams, s)
		a.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()
	write := func(b []byte) bool {
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, b) == nil
	}
	if !write(a.statusFrame(now)) || !write(SystemFrame("console/snapshot/v1", now, snap)) {
		return
	}
	tick := time.NewTicker(a.opts.StatusEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			_ = conn.Close(websocket.StatusGoingAway, "the fake ANSP went down")
			return
		case b := <-s.out:
			if !write(b) {
				return
			}
		case <-tick.C:
			if !write(a.statusFrame(time.Now())) {
				return
			}
		}
	}
}

func (a *ANSP) statusFrame(now time.Time) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	srcs := make([]map[string]any, 0, len(a.adapters))
	for _, ad := range a.adapters {
		state, _ := ad["state"].(string)
		var by any
		if state == "disabled" {
			by = "instance"
		}
		srcs = append(srcs, map[string]any{"source": "ansp_feed", "source_instance": ad["id"], "state": state, "since": stamp(now),
			"age_s": 0.4, "disabled_by": by, "counters": map[string]any{"accepted": 10, "refused": 0}})
	}
	return SystemFrame("console/status/v1", now, map[string]any{
		"connection_id": "c-1", "server_ts": stamp(now), "policy_version": "1", "stale_after_s": 5, "live_max_age_s": 3,
		"dropped_frames": 0, "degraded": a.degraded, "sources": srcs, "adapters": a.adapters, "nats": "connected",
	})
}

// SetDegraded sets degraded[] of status frames and snapshots.
func (a *ANSP) SetDegraded(d ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.degraded = append([]string{}, d...)
}

// Send sends a frame to every open stream; a track/manned/v1 frame is
// also kept for the snapshots.
func (a *ANSP) Send(frame []byte) {
	var m struct {
		Schema string `json:"schema"`
		Body   struct {
			ICAO24 string `json:"icao24"`
		} `json:"body"`
	}
	_ = json.Unmarshal(frame, &m)
	a.mu.Lock()
	defer a.mu.Unlock()
	if m.Schema == "track/manned/v1" && m.Body.ICAO24 != "" {
		a.last[m.Body.ICAO24] = append(json.RawMessage(nil), frame...)
	}
	for s := range a.streams {
		select {
		case s.out <- frame:
		default:
		}
	}
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ULID is a fresh ULID-shaped id (Crockford base32, first digit 0-7).
func ULID() string {
	const digits = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	r := make([]byte, 26)
	_, _ = rand.Read(r)
	for i := range b {
		b[i] = digits[int(r[i])%32]
	}
	b[0] = digits[int(r[0])%8]
	return string(b[:])
}

// SystemFrame is a frame the ANSP's feed originates (status, snapshot):
// placed at now on its clock.
func SystemFrame(schema string, now time.Time, body any) []byte {
	b, _ := json.Marshal(map[string]any{"schema": schema, "msg_id": ULID(), "producer": Producer, "ts": nil,
		"rx_ts": stamp(now), "captured_at": stamp(now), "time_source": "system", "backlog": false, "body": body})
	return b
}

// TrackFrame is a track/manned/v1 frame of body captured at captured on
// the ANSP's clock and written at now (age_s the difference).
func TrackFrame(body map[string]any, captured, now time.Time) []byte {
	b := map[string]any{}
	for k, v := range body {
		b[k] = v
	}
	b["age_s"] = now.Sub(captured).Seconds()
	out, _ := json.Marshal(map[string]any{"schema": "track/manned/v1", "msg_id": ULID(), "producer": Producer, "ts": stamp(captured),
		"rx_ts": stamp(captured.Add(150 * time.Millisecond)), "captured_at": stamp(captured), "time_source": "receiver",
		"backlog": false, "body": b})
	return out
}

// Sample is one line of a recording: a track/manned/v1 body and its
// offset from the recording's start.
type Sample struct {
	OffsetMS int64          `json:"offset_ms"`
	Body     map[string]any `json:"body"`
}

// LoadRecording reads a JSON-lines recording.
func LoadRecording(path string) ([]Sample, error) {
	f, err := os.Open(path) //nolint:gosec // a test's own testdata file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		var s Sample
		if err := json.Unmarshal(line, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// Replay sends the recording's samples at the recording's pace divided
// by speed, each restamped as captured 300 ms before it is sent (the
// recording's own clock is not replayed). It returns when done or when
// ctx ends.
func (a *ANSP) Replay(ctx context.Context, samples []Sample, speed float64) {
	if speed <= 0 {
		speed = 1
	}
	start := time.Now()
	for _, s := range samples {
		due := start.Add(time.Duration(float64(s.OffsetMS)/speed) * time.Millisecond)
		if d := time.Until(due); d > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
		}
		now := time.Now()
		a.Send(TrackFrame(s.Body, now.Add(-300*time.Millisecond), now))
	}
}
