package cisp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakecisp"
)

// Keys generated at run time (06 §4): never a key in git.
var (
	keysOnce                sync.Once
	authorityRing, anspRing *auth.KeyRing
	errKeys                 error
)

func rings(t *testing.T) (*auth.KeyRing, *auth.KeyRing) {
	t.Helper()
	keysOnce.Do(func() {
		mk := func(kid string) (*auth.KeyRing, error) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			return auth.NewKeyRing(auth.SigningKey{KID: kid, Key: k})
		}
		if authorityRing, errKeys = mk("authority-publication-1"); errKeys != nil {
			return
		}
		anspRing, errKeys = mk("ansp-publication-1")
	})
	if errKeys != nil {
		t.Fatal(errKeys)
	}
	return authorityRing, anspRing
}

func schemas(t *testing.T) *Schemas {
	t.Helper()
	s, err := LoadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// scopeTokens hands out "scope:<scope>" bearers; the fake records them.
type scopeTokens struct{}

func (scopeTokens) Token(_ context.Context, _ string, scopes ...string) (string, error) {
	return fmt.Sprintf("scope:%v", scopes), nil
}

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

// Invented zones around Tbilisi for tests; no real restriction.
func zoneFeature(id, reason string) string {
	return fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.79,41.69],[44.81,41.69],[44.81,41.71],[44.79,41.71],[44.79,41.69]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","name":[{"text":"Test zone","lang":"en-GB"}],"type":"PROHIBITED","variant":"COMMON","reason":[%q],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`, id, reason)
}

func zoneCollection(features ...string) []byte {
	out := `{"type":"FeatureCollection","metadata":{"issued":"2026-10-02T08:00:00Z"},"features":[`
	for i, f := range features {
		if i > 0 {
			out += ","
		}
		out += f
	}
	return []byte(out + "]}")
}

// restrictionFeature is a served restriction: the ANSP's feature with
// the CISP's block.
func restrictionFeature(id, state string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.80,41.70],[44.82,41.70],[44.82,41.72],[44.80,41.72],[44.80,41.70]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR","EMERGENCY"],"limitedApplicability":[{"startDateTime":"2026-10-02T12:00:00Z","endDateTime":"2026-10-02T15:00:00Z"}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"NOTIFICATION"}],"extendedProperties":{"cis_restriction":{"id":"r-%s","ansp_ref":"TEST-DAR-1","ansp_version":1,"state":%q,"starts_at":"2026-10-02T12:00:00Z","ends_at":"2026-10-02T15:00:00Z","ended_by":null,"uspace_airspace_id":"TSU001"}}}}`, id, id, state))
}

// memOutbox is OutboxStore in memory.
type memOutbox struct {
	mu     sync.Mutex
	rows   []*memRow
	events []string
	failAt string
}

type memRow struct {
	DueRow
	resolves        bool
	cispVersion     *int64
	conflictVersion *int64
	signature       string
	lastStatus      int
	lastError       string
}

func (m *memOutbox) Enqueue(_ context.Context, p Prepared, version int64, actor audit.Actor) (Row, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resolves := p.ResolvesConflict
	for _, r := range m.rows {
		if r.Dataset == p.Dataset && r.State == StatePending {
			resolves = resolves || r.resolves
			r.State = StateSuperseded
			m.events = append(m.events, fmt.Sprintf("%d %s", r.ID, StateSuperseded))
		}
	}
	if version == 0 {
		for _, r := range m.rows {
			if r.Dataset == p.Dataset && r.Version >= version {
				version = r.Version
			}
		}
		version++
	}
	r := &memRow{DueRow: DueRow{ID: int64(len(m.rows) + 1), Dataset: p.Dataset, Version: version, Payload: p.Payload,
		PayloadHash: p.PayloadHash, FeatureCount: p.FeatureCount, ContentType: p.ContentType, State: StatePending,
		CreatedAt: time.Now()}, signature: p.Signature, resolves: resolves}
	m.rows = append(m.rows, r)
	m.events = append(m.events, fmt.Sprintf("%d queued by %s", r.ID, actor.ID))
	sig := p.Signature
	return Row{ID: r.ID, Dataset: r.Dataset, Version: r.Version, PayloadHash: r.PayloadHash, FeatureCount: r.FeatureCount,
		Signature: &sig, State: r.State, CreatedAt: r.CreatedAt}, nil
}

func (m *memOutbox) Due(context.Context) ([]DueRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAt == "due" {
		return nil, fmt.Errorf("the outbox cannot be read")
	}
	seen := map[Dataset]bool{}
	blocked := map[Dataset]bool{}
	var out []DueRow
	for _, r := range m.rows {
		switch {
		case r.State == StateConflict:
			blocked[r.Dataset] = true
		case r.State == StateAcknowledged || r.resolves:
			blocked[r.Dataset] = false
		}
		if (r.State == StatePending || r.State == StateSent) && !seen[r.Dataset] && !blocked[r.Dataset] {
			seen[r.Dataset] = true
			out = append(out, r.DueRow)
		}
	}
	return out, nil
}

func (m *memOutbox) IfMatch(_ context.Context, ds Dataset, before int64) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.rows) - 1; i >= 0; i-- {
		r := m.rows[i]
		if r.Dataset != ds || r.ID >= before {
			continue
		}
		if r.cispVersion != nil {
			return *r.cispVersion, true, nil
		}
		if r.conflictVersion != nil {
			return *r.conflictVersion, true, nil
		}
	}
	return 0, false, nil
}

func (m *memOutbox) row(id int64) *memRow {
	for _, r := range m.rows {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (m *memOutbox) set(r *DueRow, from []string, to, event string, fn func(*memRow)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := m.row(r.ID)
	if row == nil || !slices.Contains(from, row.State) {
		return
	}
	row.State = to
	fn(row)
	m.events = append(m.events, fmt.Sprintf("%d %s", r.ID, event))
}

func (m *memOutbox) MarkSending(_ context.Context, r *DueRow, sig, _ string, _ time.Time) (bool, error) {
	ok := false
	m.set(r, []string{StatePending, StateSent}, StateSent, "sent", func(row *memRow) {
		row.Attempts++
		row.signature = sig
		ok = true
	})
	return ok, nil
}

func (m *memOutbox) MarkAcknowledged(_ context.Context, r *DueRow, v int64, o Outcome) error {
	m.set(r, []string{StateSent}, StateAcknowledged, "acknowledged", func(row *memRow) {
		row.cispVersion, row.lastStatus, row.NextRetryAt = &v, o.Status, nil
	})
	return nil
}

func (m *memOutbox) MarkRetry(_ context.Context, r *DueRow, next time.Time, o Outcome) error {
	m.set(r, []string{StateSent}, StatePending, "retry", func(row *memRow) {
		row.NextRetryAt, row.lastStatus, row.lastError = &next, o.Status, o.Reason
	})
	return nil
}

func (m *memOutbox) MarkFailed(_ context.Context, r *DueRow, o Outcome) error {
	m.set(r, []string{StatePending, StateSent}, StateFailed, "failed", func(row *memRow) {
		row.lastStatus, row.lastError = o.Status, o.Reason
	})
	return nil
}

func (m *memOutbox) MarkConflict(_ context.Context, r *DueRow, current *int64, o Outcome) error {
	m.set(r, []string{StateSent}, StateConflict, "conflict", func(row *memRow) {
		row.conflictVersion, row.lastStatus, row.lastError = current, o.Status, o.Reason
	})
	return nil
}

func (m *memOutbox) List(_ context.Context, f ListFilter) ([]OutboxView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OutboxView
	for i := len(m.rows) - 1; i >= 0; i-- {
		r := m.rows[i]
		if (f.Dataset != "" && r.Dataset != f.Dataset) || (f.State != "" && r.State != f.State) {
			continue
		}
		out = append(out, OutboxView{ID: r.ID, Dataset: r.Dataset, Version: r.Version, State: r.State, Attempts: r.Attempts,
			CISPVersion: r.cispVersion, ConflictVersion: r.conflictVersion, CreatedAt: r.CreatedAt, StateChangedAt: r.CreatedAt,
			AgeS: time.Since(r.CreatedAt).Seconds()})
	}
	return out, nil
}

func (m *memOutbox) state(id int64) *memRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := *m.row(id)
	return &r
}

// memCache is CacheStore in memory.
type memCache struct {
	mu      sync.Mutex
	cached  map[Dataset]Cached
	jtis    map[string]time.Time
	touches int
	fail    bool
}

func newMemCache() *memCache {
	return &memCache{cached: map[Dataset]Cached{}, jtis: map[string]time.Time{}}
}

func (m *memCache) Load(context.Context) ([]Cached, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Cached, 0, len(m.cached))
	for d := range m.cached {
		out = append(out, m.cached[d])
	}
	return out, nil
}

func (m *memCache) Save(_ context.Context, c *Cached) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.cached[c.Dataset]; !ok || old.Version <= c.Version {
		m.cached[c.Dataset] = *c
	}
	return nil
}

func (m *memCache) Touch(context.Context, Dataset, int64) error {
	m.mu.Lock()
	m.touches++
	m.mu.Unlock()
	return nil
}

func (m *memCache) RememberJTI(_ context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false, false, fmt.Errorf("the database is down")
	}
	now := time.Now()
	live := int64(0)
	for k, exp := range m.jtis {
		if strings.HasPrefix(k, issuer+" ") && exp.After(now) {
			live++
		}
	}
	key := issuer + " " + jti
	if _, ok := m.jtis[key]; ok {
		return false, false, nil
	}
	if live >= maxLive {
		return false, true, nil
	}
	m.jtis[key] = now.Add(ttl)
	return true, false, nil
}

func (m *memCache) SweepJTIs(context.Context) (int64, error) { return 0, nil }

func (m *memCache) get(d Dataset) (Cached, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cached[d]
	return c, ok
}

// memProjector records the restrictions projection.
type memProjector struct {
	mu      sync.Mutex
	version int64
	rows    []RestrictionRow
	writes  int
}

func (m *memProjector) ProjectRestrictions(_ context.Context, version int64, _ string, rows []RestrictionRow, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writes > 0 && m.version > version {
		return ErrProjectionNewer
	}
	m.version, m.rows = version, slices.Clone(rows)
	m.writes++
	return nil
}

func (m *memProjector) get() (int64, []RestrictionRow, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, slices.Clone(m.rows), m.writes
}

// memAnnouncer records the announcements.
type memAnnouncer struct {
	mu   sync.Mutex
	seen []string
}

func (m *memAnnouncer) Announce(_ context.Context, c *Cached) error {
	m.mu.Lock()
	m.seen = append(m.seen, fmt.Sprintf("%s:%d", c.Dataset, c.Version))
	m.mu.Unlock()
	return nil
}

// world is the CISP client wired to a fake CISP and memory stores.
type world struct {
	fake      *fakecisp.Fake
	client    *Client
	outbox    *Outbox
	store     *memOutbox
	cache     *memCache
	projector *memProjector
	announcer *memAnnouncer
	sub       *Subscriber
	sender    *Sender
	receiver  *Receiver
	rx        *httptest.Server
}

func newWorld(t *testing.T) *world {
	t.Helper()
	authority, ansp := rings(t)
	fake, err := fakecisp.New(auth.IssuerConfig{Keys: authority.JWKS()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	client, err := NewClient(ClientConfig{BaseURL: fake.URL(), Tokens: scopeTokens{}, HTTPClient: fake.Client()})
	if err != nil {
		t.Fatal(err)
	}
	sch := schemas(t)
	w := &world{fake: fake, client: client, store: &memOutbox{}, cache: newMemCache(), projector: &memProjector{}, announcer: &memAnnouncer{}}
	w.outbox = NewOutbox(sch, authority, w.store, nil)
	pubs := NewPublishers(map[string]auth.IssuerConfig{
		PublisherAuthority: {Keys: authority.JWKS()}, PublisherANSP: {Keys: ansp.JWKS()},
	}, 0, nil)
	if err := pubs.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.sub = NewSubscriber(SubscriberConfig{CISP: client, Publishers: pubs, Schemas: sch, Store: w.cache, Projector: w.projector,
		Announcer: w.announcer, Counters: w.outbox.Counters})
	w.sender = &Sender{Store: w.store, CISP: client, Signer: authority, Counters: w.outbox.Counters}
	notify, err := auth.NewCompactVerifier(context.Background(), auth.CompactConfig{
		Issuers:   map[string]auth.IssuerConfig{fakecisp.Issuer: {Keys: fake.Ring.JWKS()}, "https://ansp.test": {Keys: ansp.JWKS()}},
		Audiences: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.receiver = NewReceiver(ReceiverConfig{
		Verifier: notify, Senders: map[string]NotifySender{fakecisp.Issuer: {}, "https://ansp.test": {ANSP: true}},
		Store: w.cache, PullURL: client, Trigger: w.sub.Trigger, Counters: w.outbox.Counters,
	})
	mux := http.NewServeMux()
	w.receiver.Mount(mux)
	w.rx = httptest.NewServer(mux)
	t.Cleanup(w.rx.Close)
	return w
}

func (w *world) count(name string) uint64 { return w.outbox.Counters.Get(name) }

// waitFor polls cond for up to d.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", d, what)
}
