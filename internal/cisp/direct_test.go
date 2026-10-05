package cisp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
)

// anspDirectDir is uspace-ansp's testdata/contract/direct, vendored at
// the commit its SOURCE names: what the ANSP's code signs and serves on
// the degraded direct path (the cross-repo contract of H-2).
const anspDirectDir = "testdata/ansp-direct"

// The fixture's names.
const (
	fixtureIssuer      = "https://ansp.test"
	fixtureAudience    = "receiver.test"
	fixtureRestriction = "01K6P0A1B2C3D4E5F6G7H8J9KM"
	fixtureIdentifier  = "DAR7K2Q"
)

func fixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(anspDirectDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

// fixtureCompact joins the three parts of a fixture's compact JWS.
func fixtureCompact(t *testing.T, name string) string {
	t.Helper()
	var p struct{ Protected, Payload, Signature string }
	if err := json.Unmarshal(fixtureFile(t, name), &p); err != nil || p.Protected == "" || p.Payload == "" || p.Signature == "" {
		t.Fatalf("%s: not the three parts of a compact JWS: %v", name, err)
	}
	return p.Protected + "." + p.Payload + "." + p.Signature
}

// The vendored files are the ones SOURCE pins, byte for byte.
func TestANSPDirectFixtureIsPinned(t *testing.T) {
	f, err := os.Open(filepath.Join(anspDirectDir, "SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	pinned, origin := 0, false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if fields[0] == "ansp" {
			origin = len(fields) == 4 && fields[1] == "rootxkit/uspace-ansp" && len(fields[2]) == 40
			continue
		}
		raw, err := os.ReadFile(filepath.Join(anspDirectDir, fields[1]))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != fields[0] {
			t.Errorf("%s does not hash to the SHA-256 SOURCE pins", fields[1])
		}
		pinned++
	}
	if !origin || pinned != 7 {
		t.Fatalf("SOURCE names no commit of uspace-ansp, or pins %d files", pinned)
	}
}

// fakeANSP serves the fixture's pull_url through the subscriber's
// client and records every request.
type fakeANSP struct {
	mu       sync.Mutex
	body     []byte
	sig      string
	status   int
	requests []*http.Request
}

func (f *fakeANSP) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	rec := httptest.NewRecorder()
	switch {
	case r.URL.Host != "ansp.test" || r.URL.Path != "/v1/restrictions/"+fixtureRestriction+"/direct":
		rec.WriteHeader(http.StatusNotFound)
	case f.status != 0:
		rec.WriteHeader(f.status)
	default:
		rec.Header().Set("Content-Type", "application/json")
		rec.Header().Set(HeaderDirectSignature, f.sig)
		_, _ = rec.Write(f.body)
	}
	return rec.Result(), nil
}

func (f *fakeANSP) serve(t *testing.T, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body, f.sig, f.status = fixtureFile(t, name+".direct.json"), string(fixtureFile(t, name+".direct.jws")), 0
}

func (f *fakeANSP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// memDirect is an in-memory DirectStore.
type memDirect struct {
	mu   sync.Mutex
	rows map[string]DirectStored
	down bool
}

func (m *memDirect) SaveDirect(_ context.Context, d DirectStored) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return false, errors.New("the database is down")
	}
	if r, ok := m.rows[d.Identifier]; ok && r.AnspVersion >= d.AnspVersion {
		return false, nil
	}
	m.rows[d.Identifier] = d
	return true, nil
}

func (m *memDirect) LoadDirect(context.Context, int) ([]DirectStored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DirectStored, 0, len(m.rows))
	for id := range m.rows {
		out = append(out, m.rows[id])
	}
	return out, nil
}

func (m *memDirect) DeleteDirect(_ context.Context, id string, v int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok && r.AnspVersion <= v {
		delete(m.rows, id)
	}
	return nil
}

type directRig struct {
	t         *testing.T
	now       time.Time
	ansp      *fakeANSP
	cache     *memCache
	direct    *memDirect
	projector *memProjector
	announcer *memAnnouncer
	pubs      *Publishers
	sub       *Subscriber
	rc        *Receiver
	cispMu    sync.Mutex
	cisp      []Hint
}

// newDirectRig is a receiver and a subscriber as Assemble wires them,
// with the fixture's keys and a clock at the fixture's signing time; the
// CISP holds restrictions version 7 without the fixture's restriction.
func newDirectRig(t *testing.T) *directRig {
	t.Helper()
	jwks := fixtureFile(t, "jwks.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	keys := auth.IssuerConfig{JWKSURL: srv.URL + "/.well-known/jwks.json"}
	g := &directRig{t: t, now: time.Date(2026, 10, 2, 12, 0, 10, 0, time.UTC), ansp: &fakeANSP{}, cache: newMemCache(),
		direct: &memDirect{rows: map[string]DirectStored{}}, projector: &memProjector{}, announcer: &memAnnouncer{}}
	g.pubs = NewPublishers(map[string]auth.IssuerConfig{PublisherANSP: keys}, 0, nil)
	if err := g.pubs.Build(t.Context()); err != nil {
		t.Fatal(err)
	}
	g.start()
	v, err := auth.NewCompactVerifier(t.Context(), auth.CompactConfig{
		Issuers: map[string]auth.IssuerConfig{fixtureIssuer: keys}, Audiences: []string{fixtureAudience}, Now: g.clock})
	if err != nil {
		t.Fatal(err)
	}
	g.rc = NewReceiver(ReceiverConfig{
		Verifier: v, Senders: map[string]NotifySender{fixtureIssuer: {ANSP: true, BaseURL: fixtureIssuer}}, Store: g.cache,
		Trigger: func(_ Dataset, h Hint) {
			g.cispMu.Lock()
			defer g.cispMu.Unlock()
			g.cisp = append(g.cisp, h)
		},
		TriggerDirect: func(h DirectHint) bool { return g.sub.TriggerDirect(h) }, Counters: g.sub.cfg.Counters, Now: g.clock,
	})
	return g
}

func (g *directRig) clock() time.Time { return g.now }

// start builds the subscriber (again, for a restart) on the rig's
// stores, with the CISP's restrictions version 7 held.
func (g *directRig) start() {
	g.sub = NewSubscriber(SubscriberConfig{Publishers: g.pubs, Store: g.cache, Projector: g.projector, Announcer: g.announcer,
		Now: g.clock, Direct: DirectConfig{Client: &http.Client{Transport: g.ansp}, Store: g.direct}})
	g.hold(7)
	g.sub.Warm(context.Background())
}

// hold makes the CISP's restrictions version v (with fs) the one held.
func (g *directRig) hold(v int64, fs ...Feature) {
	g.sub.mu.Lock()
	st := g.sub.st[DatasetRestrictions]
	st.cur = &Version{Dataset: DatasetRestrictions, Number: v, ETag: ETagOf(DatasetRestrictions, v), Features: fs}
	st.fetchedAt, st.checkedAt = g.now, g.now
	g.sub.mu.Unlock()
}

func (g *directRig) post(name string) int {
	g.t.Helper()
	r := httptest.NewRequest(http.MethodPost, NotificationsPath, strings.NewReader(fixtureCompact(g.t, name+".change.json")))
	r.Header.Set("Content-Type", ContentTypeJOSE)
	w := httptest.NewRecorder()
	g.rc.ServeHTTP(w, r)
	return w.Code
}

// projected is the fixture restriction's row in the projection the
// detectors read ("" when absent) and the projection's CIS version.
func (g *directRig) projected() (string, int64) {
	v, rows, _ := g.projector.get()
	for i := range rows {
		if rows[i].Identifier == fixtureIdentifier {
			return rows[i].State, v
		}
	}
	return "", v
}

// H-2, the cross-repo contract: the ANSP's degraded direct delivery,
// exactly as uspace-ansp signs and serves it, lands in the authority and
// is applied, not skipped. Its version (ansp_version 2) is below the
// CISP's restrictions version held (7), which the receiver used to read
// it as and skip; its pull_url is the ANSP's, which the receiver used
// never to follow. The activation is projected for the detectors and
// announced (Z-12); the end, delivered the same way, is projected ended,
// which the detectors do not judge.
func TestDirectDeliveryOfTheANSPIsApplied(t *testing.T) {
	g := newDirectRig(t)
	g.ansp.serve(t, "activated")
	if code := g.post("activated"); code != http.StatusNoContent {
		t.Fatalf("activated: %d", code)
	}
	if len(g.cisp) != 0 {
		t.Fatalf("a direct notification asked the CISP: %+v", g.cisp)
	}
	g.sub.drainDirect(t.Context())
	if st, v := g.projected(); st != "active" || v != 7 {
		t.Fatalf("the activation is not projected: %q at %d; counters %v", st, v, g.sub.cfg.Counters.Snapshot())
	}
	if g.ansp.count() != 1 || g.ansp.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("pulls %d (no credential is sent to the ANSP)", g.ansp.count())
	}
	if n := len(g.announcer.seen); n == 0 || g.announcer.seen[n-1] != "restrictions:7" {
		t.Fatalf("not announced: %v", g.announcer.seen)
	}
	if ds := g.sub.Direct(); len(ds) != 1 || ds[0].Pending || ds[0].State != "active" || ds[0].AnspVersion != 2 {
		t.Fatalf("direct state %+v", ds)
	}
	g.now = g.now.Add(time.Hour - 9*time.Second)
	g.ansp.serve(t, "ended")
	if code := g.post("ended"); code != http.StatusNoContent {
		t.Fatalf("ended: %d", code)
	}
	g.sub.drainDirect(t.Context())
	if st, _ := g.projected(); st != "ended" {
		t.Fatalf("the end is not projected: %q", st)
	}
	// An older version again: nothing pulled, the end stands.
	pulls := g.ansp.count()
	if err := g.sub.ApplyDirect(t.Context(), DirectHint{RestrictionID: fixtureRestriction, AnspVersion: 2,
		FeatureIDs: []string{fixtureIdentifier}, PullURL: "https://ansp.test/v1/restrictions/" + fixtureRestriction + "/direct"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := g.projected(); st != "ended" || g.ansp.count() != pulls || g.sub.cfg.Counters.Get(CounterDirectReplays) != 1 {
		t.Fatalf("an older version was applied or pulled: %q, %d pulls", st, g.ansp.count()-pulls)
	}
	// A restart keeps it.
	g.projector = &memProjector{}
	g.start()
	if st, _ := g.projected(); st != "ended" {
		t.Fatalf("after a restart: %q", st)
	}
	// The CISP catches up (it holds ansp_version 3): the direct one is
	// dropped from memory and the store, and the CISP's row is projected.
	g.hold(9, Feature{Identifier: fixtureIdentifier, Raw: json.RawMessage(`{}`),
		Restriction: &cispclient.CisRestriction{AnspVersion: 3, State: "ended", Id: fixtureRestriction}})
	g.sub.pruneDirect(t.Context())
	if len(g.sub.Direct()) != 0 || len(g.direct.rows) != 0 {
		t.Fatalf("the CISP's version 3 did not replace the direct one: %+v", g.sub.Direct())
	}
	if st, v := g.projected(); st != "ended" || v != 9 {
		t.Fatalf("projected %q at %d", st, v)
	}
}

// The absence pairs. A body the ANSP's key does not sign is never
// applied (and retried, the keys may come later); a body for another
// restriction is dropped; a pull_url off the ANSP's base URL is read
// from the CISP; a full queue is a 503 that records no delivery id.
func TestDirectDeliveryRefusals(t *testing.T) {
	g := newDirectRig(t)
	g.ansp.serve(t, "activated")
	g.ansp.body = fixtureFile(t, "ended.direct.json")
	if code := g.post("activated"); code != http.StatusNoContent {
		t.Fatalf("activated: %d", code)
	}
	g.sub.drainDirect(t.Context())
	if st, _ := g.projected(); st != "" || g.sub.cfg.Counters.Get(CounterDirectRefused) != 1 {
		t.Fatalf("a body its signature does not cover was applied: %q", st)
	}
	if ds := g.sub.Direct(); len(ds) != 1 || !ds[0].Pending {
		t.Fatalf("not retried: %+v", ds)
	}
	g.ansp.serve(t, "activated")
	g.sub.drainDirect(t.Context())
	if st, _ := g.projected(); st != "active" {
		t.Fatalf("the retry did not apply: %q", st)
	}

	h := newDirectRig(t)
	h.ansp.serve(t, "activated")
	if err := h.sub.ApplyDirect(t.Context(), DirectHint{RestrictionID: "01K6P0A1B2C3D4E5F6G7H8J9ZZ", AnspVersion: 2,
		FeatureIDs: []string{fixtureIdentifier}, PullURL: "https://ansp.test/v1/restrictions/" + fixtureRestriction + "/direct"}); !errors.Is(err, errDirectPermanent) {
		t.Fatalf("a body of another restriction: %v", err)
	}

	// Off the ANSP's base URL: the direct path does not take it.
	o := newDirectRig(t)
	o.rc.cfg.Senders = map[string]NotifySender{fixtureIssuer: {ANSP: true, BaseURL: "https://ansp.example"}}
	if code := o.post("activated"); code != http.StatusNoContent || len(o.sub.Direct()) != 0 || len(o.cisp) != 1 || o.cisp[0].Version != 0 {
		t.Fatalf("off the base URL: %d, direct %+v, CISP %+v", code, o.sub.Direct(), o.cisp)
	}

	f := newDirectRig(t)
	f.sub.cfg.Direct.Max = 1
	f.sub.directPending["other"] = &DirectHint{RestrictionID: "other", AnspVersion: 1}
	if code := f.post("activated"); code != http.StatusServiceUnavailable || len(f.cache.jtis) != 0 {
		t.Fatalf("full: %d, %d ids recorded", code, len(f.cache.jtis))
	}
	delete(f.sub.directPending, "other")
	f.ansp.serve(t, "activated")
	if code := f.post("activated"); code != http.StatusNoContent {
		t.Fatalf("the retry: %d", code)
	}
	f.sub.drainDirect(t.Context())
	if st, _ := f.projected(); st != "active" {
		t.Fatalf("the retry was not applied: %q", st)
	}
}
