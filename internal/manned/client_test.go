package manned_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakeansp"
	"github.com/rootxkit/uspace-authority/internal/manned"
)

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: not within %v", what, within)
}

// tokens records the token requests.
type tokens struct {
	mu    sync.Mutex
	calls []string
	fail  bool
}

func (k *tokens) Token(_ context.Context, baseURL string, scopes ...string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, baseURL+" "+strings.Join(scopes, " "))
	if k.fail {
		return "", context.DeadlineExceeded
	}
	return "test-token", nil
}

// sink records publications.
type sink struct {
	mu   sync.Mutex
	pubs []manned.Published
}

func (s *sink) Publish(p manned.Published) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pubs = append(s.pubs, p)
	return nil
}

func (s *sink) Rows([]manned.Row) {}

func (s *sink) all() []manned.Published {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]manned.Published(nil), s.pubs...)
}

func (s *sink) of(icao, state string) int {
	n := 0
	all := s.all()
	for i := range all {
		if all[i].Message.Body.ICAO24 == icao && all[i].Message.Body.State == state {
			n++
		}
	}
	return n
}

type gate struct {
	mu  sync.Mutex
	off bool
}

func (g *gate) Query(string, *string) coresources.Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off {
		why := coresources.WhyType
		return coresources.Decision{WhyDisabled: &why}
	}
	return coresources.Decision{Enabled: true}
}

func (g *gate) set(off bool) {
	g.mu.Lock()
	g.off = off
	g.mu.Unlock()
}

// pki is a CA and a client certificate signed by it, generated at test
// time (CLAUDE.md rule 11: no key in git).
type pki struct {
	pool     *x509.CertPool
	certFile string
	keyFile  string
	cert     tls.Certificate
}

func newPKI(t *testing.T) pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test mTLS CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "authority-01"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyDER, _ := x509.MarshalECPrivateKey(key)
	p := pki{pool: x509.NewCertPool(), certFile: filepath.Join(dir, "client.crt"), keyFile: filepath.Join(dir, "client.key")}
	p.pool.AddCert(ca)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(p.certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p.cert, _ = tls.X509KeyPair(certPEM, keyPEM)
	return p
}

type rig struct {
	ansp    *fakeansp.ANSP
	in      *manned.Ingest
	client  *manned.Client
	sink    *sink
	gate    *gate
	tok     *tokens
	changes chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
}

// startRig runs a client against a fake ANSP with the TLS configuration
// tc (the fake's root added).
func startRig(t *testing.T, a *fakeansp.ANSP, tc *tls.Config, mutate func(*manned.Client)) *rig {
	t.Helper()
	v, err := manned.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tc.RootCAs = a.RootCAs()
	tr := &http.Transport{TLSClientConfig: tc}
	r := &rig{ansp: a, sink: &sink{}, gate: &gate{}, tok: &tokens{}, changes: make(chan struct{}, 1), done: make(chan struct{})}
	r.in = &manned.Ingest{V: v, Sink: r.sink, Gate: r.gate, Counters: &core.Counters{}, Feed: manned.NewFeed(manned.FeedSettings{StaleAfter: time.Second}, time.Now())}
	r.client = &manned.Client{BaseURL: a.URL(), BBox: "44.6,41.6,45.0,41.9", Tokens: r.tok, HTTP: manned.NoRedirectClient(tr), Ingest: r.in,
		Changes: r.changes, Counters: &core.Counters{}, RequestTimeout: 2 * time.Second, SilentAfter: 3 * time.Second, BackoffMin: 50 * time.Millisecond, BackoffMax: 200 * time.Millisecond}
	if mutate != nil {
		mutate(r.client)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { defer close(r.done); r.client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-r.done
		tr.CloseIdleConnections()
	})
	return r
}

func (r *rig) signal() {
	select {
	case r.changes <- struct{}{}:
	default:
	}
}

var body = map[string]any{
	"icao24": "4ca7b5", "callsign": "TST123", "position": map[string]any{"lat": 41.721, "lng": 44.793}, "alt_pressure_m": 1524,
	"alt_wgs84_m": 1561, "gs_ms": 72.5, "track_deg": 134, "vrate_ms": -2.5, "source_class": "ads_b", "trust": "surveillance",
	"source": "ansp_feed", "source_instance": "adsb-tbs", "state": "live",
}

// M18, M25, E-01: with the client certificate the stream opens against
// an ANSP that requires one, presenting the certificate, a bearer of
// scope ansp.traffic for the ANSP's base URL and the configured bbox,
// after a snapshot bootstrap; frames reach the ingest. Without the
// certificate the same ANSP refuses the handshake and the feed is
// unavailable.
func TestClientPresentsTheCertificateTheANSPRequires(t *testing.T) {
	p := newPKI(t)
	a := fakeansp.New(fakeansp.Options{RequireClientCert: true, ClientCAs: p.pool, StatusEvery: 200 * time.Millisecond})
	defer a.Close()
	cfg := &config.MannedIngest{MTLSMode: "required", ClientCert: p.certFile, ClientKey: p.keyFile}
	tc, err := manned.TLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := startRig(t, a, tc, nil)
	eventually(t, "the stream open", 5*time.Second, func() bool { return a.Open() == 1 })
	now := time.Now()
	a.Send(fakeansp.TrackFrame(body, now.Add(-time.Second), now))
	eventually(t, "the aircraft published", 5*time.Second, func() bool { return r.sink.of("4ca7b5", "live") == 1 })
	reqs := a.Requests()
	if len(reqs) < 2 || reqs[0].Path != fakeansp.PathSnapshot || reqs[1].Path != fakeansp.PathStream {
		t.Fatalf("requests %+v", reqs)
	}
	for _, q := range reqs[:2] {
		if q.Authorization != "Bearer test-token" || !q.ClientCert || q.BBox != "44.6,41.6,45.0,41.9" {
			t.Fatalf("request %+v", q)
		}
	}
	if r.tok.calls[0] != a.URL()+" ansp.traffic" {
		t.Fatalf("token %v", r.tok.calls)
	}
	if v := r.in.Feed.View(time.Now()); v.State != manned.FeedHealthy {
		t.Fatalf("feed %+v", v)
	}

	// The same ANSP without the certificate: refused, unavailable.
	off, err := manned.TLSConfig(&config.MannedIngest{MTLSMode: "off"})
	if err != nil || len(off.Certificates) != 0 {
		t.Fatalf("off: %v %d", err, len(off.Certificates))
	}
	r2 := startRig(t, a, off, nil)
	eventually(t, "the handshake refused", 5*time.Second, func() bool { return r2.client.Counters.Get(manned.CounterConnectFailed) >= 1 })
	if v := r2.in.Feed.View(time.Now()); v.State != manned.FeedUnavailable || r2.client.Counters.Get(manned.CounterConnected) != 0 {
		t.Fatalf("without the certificate: %+v", v)
	}
	// required with no readable certificate refuses to build the client.
	if _, err := manned.TLSConfig(&config.MannedIngest{MTLSMode: "required", ClientCert: filepath.Join(t.TempDir(), "x.crt"), ClientKey: p.keyFile}); err == nil {
		t.Fatal("a missing certificate accepted")
	}
}

// B-04, B-08, E-02: the ANSP down closes the stream; the feed says
// unavailable since that instant, the aircraft is aged stale (never
// removed) by the status, and the client reconnects when the ANSP is
// back: the snapshot's replay of the same sample publishes nothing
// twice, a new sample is published live.
func TestClientReconnectsWithoutDuplicates(t *testing.T) {
	a := fakeansp.New(fakeansp.Options{StatusEvery: 100 * time.Millisecond})
	defer a.Close()
	r := startRig(t, a, &tls.Config{MinVersion: tls.VersionTLS12}, nil)
	eventually(t, "the stream open", 5*time.Second, func() bool { return a.Open() == 1 })
	now := time.Now()
	a.Send(fakeansp.TrackFrame(body, now.Add(-time.Second), now))
	eventually(t, "the aircraft published", 5*time.Second, func() bool { return r.sink.of("4ca7b5", "live") == 1 })

	a.Down()
	eventually(t, "the feed unavailable", 5*time.Second, func() bool { return r.in.Feed.View(time.Now()).State == manned.FeedUnavailable })
	since := r.in.Feed.View(time.Now()).UnavailableSince
	st := &manned.Status{Ingest: r.in, Pub: discard{}}
	st.Publish(time.Now())
	if r.sink.of("4ca7b5", "stale") != 1 || r.in.Len() != 1 {
		t.Fatalf("not aged stale: %d held %d", r.sink.of("4ca7b5", "stale"), r.in.Len())
	}
	eventually(t, "reconnection attempts", 5*time.Second, func() bool { return r.client.Counters.Get(manned.CounterReconnects) >= 2 })
	if v := r.in.Feed.View(time.Now()); !v.UnavailableSince.Equal(since) {
		t.Fatalf("unavailable since moved: %v %v", v.UnavailableSince, since)
	}

	a.Up()
	eventually(t, "the stream open again", 5*time.Second, func() bool { return a.Open() == 1 && a.Connects() == 2 })
	eventually(t, "healthy again", 5*time.Second, func() bool { return r.in.Feed.View(time.Now()).State == manned.FeedHealthy })
	if n := r.sink.of("4ca7b5", "live"); n != 1 || r.in.Counters.Get(manned.CounterDuplicates) == 0 {
		t.Fatalf("the replayed sample published again: live %d, duplicates %d", n, r.in.Counters.Get(manned.CounterDuplicates))
	}
	now = time.Now()
	a.Send(fakeansp.TrackFrame(body, now.Add(-time.Second), now))
	eventually(t, "a new sample published", 5*time.Second, func() bool { return r.sink.of("4ca7b5", "live") == 2 })
}

type discard struct{}

func (discard) Publish(string, []byte) error { return nil }

// B-11, E-01: source control switching the feed off closes the stream
// and ages the aircraft source_disabled; switched on, it opens again.
func TestClientClosesWhenSwitchedOff(t *testing.T) {
	a := fakeansp.New(fakeansp.Options{StatusEvery: 100 * time.Millisecond})
	defer a.Close()
	r := startRig(t, a, &tls.Config{MinVersion: tls.VersionTLS12}, nil)
	eventually(t, "the stream open", 5*time.Second, func() bool { return a.Open() == 1 })
	now := time.Now()
	a.Send(fakeansp.TrackFrame(body, now.Add(-time.Second), now))
	eventually(t, "the aircraft published", 5*time.Second, func() bool { return r.sink.of("4ca7b5", "live") == 1 })
	r.gate.set(true)
	r.signal()
	eventually(t, "the stream closed", 5*time.Second, func() bool { return a.Open() == 0 })
	eventually(t, "the aircraft aged", 5*time.Second, func() bool { return r.sink.of("4ca7b5", "source_disabled") == 1 })
	if r.client.Counters.Get(manned.CounterClosedBySwitch) != 1 || r.in.Feed.View(time.Now()).State != manned.FeedDisabled || a.Connects() != 1 {
		t.Fatalf("switched off: %v %s", r.client.Counters.Snapshot(), r.in.Feed.View(time.Now()).State)
	}
	r.gate.set(false)
	r.signal()
	eventually(t, "the stream open again", 5*time.Second, func() bool { return a.Open() == 1 && a.Connects() == 2 })
}

// E-02: with no ANSP configured nothing is connected and the feed says
// ansp_unconfigured; with no token every connection is refused locally
// and the feed says no_token; neither reaches the ANSP.
func TestClientWithoutANSPOrToken(t *testing.T) {
	a := fakeansp.New(fakeansp.Options{})
	defer a.Close()
	r := startRig(t, a, &tls.Config{MinVersion: tls.VersionTLS12}, func(c *manned.Client) { c.BaseURL = "" })
	eventually(t, "unconfigured", 5*time.Second, func() bool {
		v := r.in.Feed.View(time.Now())
		return v.State == manned.FeedUnavailable && v.Reason == manned.ReasonUnconfigured
	})
	r2 := startRig(t, a, &tls.Config{MinVersion: tls.VersionTLS12}, func(c *manned.Client) { c.Tokens = nil })
	eventually(t, "no token", 5*time.Second, func() bool {
		v := r2.in.Feed.View(time.Now())
		return v.State == manned.FeedUnavailable && v.Reason == manned.ReasonNoToken && r2.client.Counters.Get(manned.CounterReconnects) >= 1
	})
	if len(a.Requests()) != 0 {
		t.Fatalf("the ANSP was called: %+v", a.Requests())
	}
}
