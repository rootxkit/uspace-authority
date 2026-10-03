package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakeansp"
	"github.com/rootxkit/uspace-authority/internal/manned"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// staticTokens stands in for this system's token service.
type staticTokens struct{}

func (staticTokens) Token(context.Context, string, ...string) (string, error) {
	return "test-token", nil
}

// clientPKI writes a CA and a client certificate signed by it, generated
// at test time (CLAUDE.md rule 11).
func clientPKI(t *testing.T) (*x509.CertPool, string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test mTLS CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "authority-01"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, certFile, keyFile
}

// startManned runs manned-ingest as a process against the fake ANSP.
func startManned(t *testing.T, a *fakeansp.ANSP, env map[string]string) *lines {
	t.Helper()
	out := &lines{}
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	cfg := &config.MannedIngest{}
	spec := proc.Spec{Name: "manned-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return manned.Run(ctx, rt, cfg, manned.Options{Tokens: staticTokens{}, RootCAs: a.RootCAs()})
	}}
	go func() {
		exit <- proc.Main(ctx, spec, nil, out, io.Discard, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("manned-ingest exit %d:\n%s", code, out.tail(40))
			}
		case <-time.After(30 * time.Second):
			t.Error("manned-ingest did not stop")
		}
	})
	return out
}

// mannedFrames collects the console's track/manned/v1 frames and its
// statuses' ansp_feed row while the test reads other frames.
type mannedFrames struct {
	mu     sync.Mutex
	frames []mannedFrame
	feed   []picture.SourceState
	// snapshots are the manned counts of the snapshots received.
	snapshots []int
	// unavailable says, per status, whether it carried manned_unavailable.
	unavailable []bool
}

type mannedFrame struct {
	Producer   string
	CapturedAt string
	ICAO24     string
	State      string
	Trust      string
	AgeS       *float64
	WGS84      *float64
}

func (m *mannedFrames) read(k *console) {
	go func() {
		for raw := range k.frames {
			var e struct {
				Schema     string          `json:"schema"`
				Producer   string          `json:"producer"`
				CapturedAt string          `json:"captured_at"`
				Body       json.RawMessage `json:"body"`
			}
			if json.Unmarshal(raw, &e) != nil {
				continue
			}
			switch e.Schema {
			case picture.SchemaManned:
				var b struct {
					ICAO24    string   `json:"icao24"`
					State     string   `json:"state"`
					Trust     string   `json:"trust"`
					AgeS      *float64 `json:"age_s"`
					AltWGS84M *float64 `json:"alt_wgs84_m"`
				}
				_ = json.Unmarshal(e.Body, &b)
				m.mu.Lock()
				m.frames = append(m.frames, mannedFrame{Producer: e.Producer, CapturedAt: e.CapturedAt, ICAO24: b.ICAO24, State: b.State,
					Trust: b.Trust, AgeS: b.AgeS, WGS84: b.AltWGS84M})
				m.mu.Unlock()
			case picture.SchemaSnapshot:
				var sb picture.SnapshotBody
				if json.Unmarshal(e.Body, &sb) == nil {
					m.mu.Lock()
					m.snapshots = append(m.snapshots, len(sb.Manned))
					m.mu.Unlock()
				}
			case picture.SchemaStatus:
				var st picture.StatusBody
				if json.Unmarshal(e.Body, &st) != nil {
					continue
				}
				m.mu.Lock()
				m.unavailable = append(m.unavailable, has(st.Degraded, picture.DegradedManned))
				m.mu.Unlock()
				for _, s := range st.Sources {
					if s.Source == manned.SourceType && s.SourceInstance != nil && *s.SourceInstance == "ansp" {
						m.mu.Lock()
						m.feed = append(m.feed, s)
						m.mu.Unlock()
					}
				}
			}
		}
	}()
}

func (m *mannedFrames) count(icao, state string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, f := range m.frames {
		if f.ICAO24 == icao && f.State == state {
			n++
		}
	}
	return n
}

func (m *mannedFrames) lastFeed() (picture.SourceState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.feed) == 0 {
		return picture.SourceState{}, false
	}
	return m.feed[len(m.feed)-1], true
}

func (m *mannedFrames) feedSince(i int) []picture.SourceState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]picture.SourceState(nil), m.feed[min(i, len(m.feed)):]...)
}

func (m *mannedFrames) unavailableSince(i int) []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bool(nil), m.unavailable[min(i, len(m.unavailable)):]...)
}

func (m *mannedFrames) statuses() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.unavailable)
}

func (m *mannedFrames) snapshotCounts() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int(nil), m.snapshots...)
}

func (m *mannedFrames) all() []mannedFrame {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mannedFrame(nil), m.frames...)
}

func waitUntil(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: not within %v", what, within)
}

// rowsOf writes every manned_tracks row on tsw.v1.manned_tracks after
// the sequence it started at, as tsdb-writer does, and returns the
// counts written and deduplicated.
type rowsOf struct {
	st   jetstream.Stream
	next uint64
	w    *ts.WriterPool
}

func (r *rowsOf) drain(t *testing.T) (inserted, duplicates int64) {
	t.Helper()
	ctx := context.Background()
	info, err := r.st.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for ; r.next <= info.State.LastSeq; r.next++ {
		m, err := r.st.GetMsg(ctx, r.next)
		if err != nil || m.Subject != "tsw.v1."+manned.Table {
			continue
		}
		var in ts.RowsMessageIn
		if err := json.Unmarshal(m.Data, &in); err != nil || in.Table != manned.Table {
			t.Fatalf("tsw message %s: %v", m.Data, err)
		}
		part := ts.Part{Table: ts.MannedTracks}
		for _, raw := range in.Rows {
			row, err := ts.MannedTracks.DecodeRow(raw)
			if err != nil {
				t.Fatalf("row %s: %v", raw, err)
			}
			part.Rows = append(part.Rows, row)
		}
		got, err := r.w.Write(ctx, part)
		if err != nil {
			t.Fatal(err)
		}
		inserted += got[0].Inserted
		duplicates += got[0].Duplicates
	}
	return inserted, duplicates
}

// A-M4, WP-15, E-02, B-04, B-11 (INV-02 for the feed's degraded state):
// the recorded ADS-B file served by the fake ANSP over mTLS reaches the
// console as track/manned/v1 with trust surveillance and an age, the two
// altitudes apart, and lands in manned_tracks; the feed is live on the
// console's status. The ANSP closed for 30 s: the console is told the
// feed is down since that instant on every status of the outage, the
// aircraft age stale and stay on the picture (never an empty sky), and
// after the ANSP is back the feed is live again with not one sample
// published or written twice. Source control switching ansp_feed off
// closes the stream and the aircraft show source_disabled, the feed
// disabled by whom.
func TestIntegrationMannedTrafficOnThePicture(t *testing.T) {
	nc, js := connectNATS(t)
	ctx := context.Background()
	tswCfg, _ := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamTSW)
	if _, err := bus.OpenStream(ctx, js, tswCfg); err != nil {
		t.Fatal(err)
	}
	tsw, err := js.Stream(ctx, bus.StreamTSW)
	if err != nil {
		t.Fatal(err)
	}
	info, err := tsw.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ts.OpenWriterPool(ctx, store.PoolOptions{URL: storetest.Migrated(t, migrate.Timeseries), ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	rows := &rowsOf{st: tsw, next: info.State.LastSeq + 1, w: w}

	pool, certFile, keyFile := clientPKI(t)
	a := fakeansp.New(fakeansp.Options{RequireClientCert: true, ClientCAs: pool, StatusEvery: 500 * time.Millisecond})
	t.Cleanup(a.Close)
	recording, err := fakeansp.LoadRecording("../../internal/ltest/fakeansp/testdata/adsb-recording.jsonl")
	if err != nil || len(recording) != 40 {
		t.Fatalf("recording %d %v", len(recording), err)
	}

	api := newSessionAPI(t)
	bucket, subject := fmt.Sprintf("sc_m_%d", time.Now().UnixNano()), fmt.Sprintf("ctl.sources.m%d", time.Now().UnixNano())
	p := startPicture(t, api, natsURL(t), func(m map[string]string) {
		m["SOURCE_CONTROL_BUCKET"], m["SOURCE_CONTROL_SUBJECT"], m["SOURCE_CONTROL_REREAD_S"] = bucket, subject, "1"
	})
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	k := dialConsole(t, p.ws, api.session(t, "manned-1"), 0)
	k.until(t, picture.SchemaStatus, 5*time.Second, nil)
	k.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	k.subscribe(t, 44.6, 41.5, 45.1, 41.9)
	k.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	frames := &mannedFrames{}
	frames.read(k)

	out := startManned(t, a, map[string]string{
		"NATS_URL": natsURL(t), "ANSP_BASE_URL": a.URL(), "MANNED_BBOX": "44.6,41.5,45.1,41.9", "AUTHORITY_MTLS_MODE": "required",
		"MANNED_CLIENT_CERT": certFile, "MANNED_CLIENT_KEY": keyFile, "ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1",
		"SHUTDOWN_TIMEOUT_S": "10", "NATS_START_ATTEMPTS": "1", "SOURCE_CONTROL_BUCKET": bucket, "SOURCE_CONTROL_SUBJECT": subject,
		"SOURCE_CONTROL_REREAD_S": "1", "MANNED_STATUS_INTERVAL_MS": "500", "MANNED_BACKOFF_MIN_MS": "100", "MANNED_BACKOFF_MAX_MS": "1000",
		"MANNED_SWITCHES_REAPPLY_S": "1", "MANNED_STALE_AFTER_S": "5",
	})
	waitUntil(t, "the stream open", 15*time.Second, func() bool { return a.Open() == 1 })
	for _, q := range a.Requests() {
		if !q.ClientCert || q.Authorization != "Bearer test-token" || q.BBox != "44.6,41.5,45.1,41.9" {
			t.Fatalf("request %+v", q)
		}
	}
	a.Replay(ctx, recording, 4)
	waitUntil(t, "every recorded sample on the console", 15*time.Second, func() bool {
		return frames.count("4ca7b5", "live") == 20 && frames.count("4ca7c1", "live") == 20
	})
	for _, f := range frames.all() {
		if f.Producer != manned.Producer || f.Trust != "surveillance" || f.AgeS == nil || *f.AgeS < 0 {
			t.Fatalf("frame %+v", f)
		}
		if (f.ICAO24 == "4ca7b5") != (f.WGS84 != nil) {
			t.Fatalf("altitudes: %s wgs84 %v", f.ICAO24, f.WGS84)
		}
	}
	waitUntil(t, "the feed live on the console", 10*time.Second, func() bool {
		s, ok := frames.lastFeed()
		return ok && s.State == picture.StateLive
	})
	var inserted, dup int64
	deadline := time.Now().Add(15 * time.Second)
	for inserted < 40 && time.Now().Before(deadline) {
		i, d := rows.drain(t)
		inserted, dup = inserted+i, dup+d
		time.Sleep(50 * time.Millisecond)
	}
	if inserted != 40 {
		t.Fatalf("rows in manned_tracks %d (deduplicated %d): %s", inserted, dup, out.tail(5))
	}

	// The ANSP closed for 30 s.
	a.Down()
	downAt := time.Now()
	waitUntil(t, "the feed down on the console", 10*time.Second, func() bool {
		s, ok := frames.lastFeed()
		return ok && s.State == "down"
	})
	s, _ := frames.lastFeed()
	since, err := time.Parse(time.RFC3339Nano, s.Since)
	if err != nil || since.Before(downAt.Add(-time.Second)) || since.After(downAt.Add(2*time.Second)) {
		t.Fatalf("down since %s, closed at %s", s.Since, downAt.Format(time.RFC3339Nano))
	}
	waitUntil(t, "the aircraft aged stale", 10*time.Second, func() bool {
		return frames.count("4ca7b5", "stale") == 1 && frames.count("4ca7c1", "stale") == 1
	})
	// A console that opens its view while the aircraft are still held
	// sees both of them, aged.
	before := len(frames.snapshotCounts())
	k.subscribe(t, 44.6, 41.5, 45.1, 41.9)
	waitUntil(t, "a snapshot with both aircraft", 5*time.Second, func() bool {
		c := frames.snapshotCounts()
		return len(c) > before && c[len(c)-1] == 2
	})
	// Every status of the 30 s outage says the feed is down since the
	// same instant and that manned traffic is unavailable: never an
	// empty sky, even once the picture has aged the aircraft out.
	mark, markStatus := len(frames.feedSince(0)), frames.statuses()
	waitUntil(t, "a 30 s outage", 40*time.Second, func() bool { return time.Since(downAt) >= 30*time.Second })
	outage := frames.feedSince(mark)
	if len(outage) < 20 {
		t.Fatalf("statuses during the outage: %d", len(outage))
	}
	for _, s := range outage {
		if s.State != "down" || s.Since != outage[0].Since {
			t.Fatalf("a status of the outage says %s since %s", s.State, s.Since)
		}
	}
	for i, u := range frames.unavailableSince(markStatus) {
		if !u {
			t.Fatalf("status %d of the outage without manned_unavailable", i)
		}
	}
	if out.find("ANSP manned traffic stream unavailable; reconnecting (data the ANSP holds is not lost)") == nil {
		t.Fatalf("no reconnection line:\n%s", out.tail(30))
	}

	a.Up()
	waitUntil(t, "the stream open again", 15*time.Second, func() bool { return a.Open() == 1 && a.Connects() >= 2 })
	waitUntil(t, "the feed live again", 10*time.Second, func() bool {
		s, ok := frames.lastFeed()
		u := frames.unavailableSince(0)
		return ok && s.State == picture.StateLive && len(u) > 0 && !u[len(u)-1]
	})
	if frames.count("4ca7b5", "live") != 20 || frames.count("4ca7c1", "live") != 20 {
		t.Fatalf("a sample published twice after resumption: %d %d", frames.count("4ca7b5", "live"), frames.count("4ca7c1", "live"))
	}
	seen := map[string]bool{}
	for _, f := range frames.all() {
		key := f.ICAO24 + f.CapturedAt + f.State
		if seen[key] {
			t.Fatalf("frame twice: %+v", f)
		}
		seen[key] = true
	}
	waitUntil(t, "the stale rows written", 10*time.Second, func() bool {
		i, d := rows.drain(t)
		inserted, dup = inserted+i, dup+d
		return inserted == 42
	})
	if i, _ := rows.drain(t); i != 0 {
		t.Fatalf("rows after resumption: %d", i)
	}

	// Source control switches ansp_feed off, as api writes it.
	doc := sources.Document{Epoch: "wp15", Version: 1, Controls: []sources.Control{{SourceType: sources.TypeANSPFeed, Enabled: false,
		Reason: "ANSP maintenance", Actor: "admin:test", ChangedAt: time.Now().UTC(), Version: 1}}}
	raw, err := sources.Encode(doc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, mustBucket(t, bucket))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, sources.StateKey, raw); err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish(subject, raw); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the stream closed", 10*time.Second, func() bool { return a.Open() == 0 })
	waitUntil(t, "the aircraft source_disabled", 10*time.Second, func() bool {
		return frames.count("4ca7b5", "source_disabled") == 1 && frames.count("4ca7c1", "source_disabled") == 1
	})
	waitUntil(t, "the feed disabled by whom", 10*time.Second, func() bool {
		s, ok := frames.lastFeed()
		return ok && s.State == picture.StateDisabled && s.DisabledByWho != nil && *s.DisabledByWho == "admin:test"
	})
	t.Logf("rows written %d, deduplicated %d", inserted, dup)
}
