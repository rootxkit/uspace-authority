package cisp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/cisp"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakecisp"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

// The periods of these tests are scaled down from the contract's so the
// suite runs in seconds: the reconciliation every 400 ms (60 s in
// production), the heartbeat every 150 ms (15 s). The CISP's 60 s
// staleness is judged on the fake's clock from the heartbeats' arrival
// times. The behaviour does not depend on the period.
const (
	itReconcile = 400 * time.Millisecond
	itHeartbeat = 150 * time.Millisecond
	itWait      = 15 * time.Second
)

var (
	admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}
	t0    = time.Now().UTC().Add(-24 * time.Hour)
	t1    = time.Now().UTC().Add(365 * 24 * time.Hour)
)

type scopeTokens struct{}

func (scopeTokens) Token(_ context.Context, _ string, scopes ...string) (string, error) {
	return fmt.Sprintf("scope:%v", scopes), nil
}

func newRing(t *testing.T, kid string) *auth.KeyRing {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r, err := auth.NewKeyRing(auth.SigningKey{KID: kid, Key: k})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// stack is the CISP client and the zone service on the real databases
// (PostgreSQL as authority_app, the projection as
// authority_ts_projector) and NATS, against a fake CISP over https.
type stack struct {
	fake    *fakecisp.Fake
	parts   *cisp.Parts
	zones   *zonesvc.Service
	pgAdmin *sql.DB
	tsAdmin *sql.DB
	pgURL   string
	ansp    *auth.KeyRing
	nc      *nats.Conn
	// callback is the receiver's URL (POST /v1/cis/notifications).
	callback string
	cancel   context.CancelFunc
	done     chan struct{}
}

func newStack(t *testing.T, down bool, opts ...func(*cisp.Setup)) *stack {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	nc, js := bustest.Connect(t)
	cfg, _ := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamCIS)
	if _, err := bus.OpenStream(ctx, js, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	proj, err := ts.OpenProjector(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proj.Close)
	authority, ansp := newRing(t, "authority-publication-it"), newRing(t, "ansp-publication-it")
	fake, err := fakecisp.New(auth.IssuerConfig{Keys: authority.JWKS()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	fake.SetDown(down)
	w := audit.NewWriter(db)
	mux := http.NewServeMux()
	rx := httptest.NewServer(mux)
	t.Cleanup(rx.Close)
	fakeKeys, anspKeys := auth.IssuerConfig{Keys: fake.Ring.JWKS()}, auth.IssuerConfig{Keys: ansp.JWKS()}
	setup := cisp.Setup{
		DB: db, Audit: w, Projector: proj, JS: js, NATSTimeout: 2 * time.Second, PublicationRing: authority,
		Tokens: scopeTokens{}, BaseURL: fake.URL(), CallbackURL: rx.URL + cisp.NotificationsPath, Audiences: []string{"127.0.0.1"},
		NotifyIssuers: []cisp.NotifyIssuer{
			{Issuer: fakecisp.Issuer, Keys: &fakeKeys}, {Issuer: "https://ansp.test", Keys: &anspKeys, ANSP: true},
		},
		PublisherKeys:     map[string]auth.IssuerConfig{cisp.PublisherANSP: anspKeys},
		ReconcileInterval: itReconcile, HeartbeatInterval: itHeartbeat, SendPoll: 100 * time.Millisecond,
		BackoffMin: 100 * time.Millisecond, BackoffMax: 300 * time.Millisecond,
		HTTPClient: fake.Client(), Logger: logging.Discard(),
	}
	for _, o := range opts {
		o(&setup)
	}
	parts, err := cisp.Assemble(ctx, setup)
	if err != nil {
		t.Fatal(err)
	}
	parts.Receiver.Mount(mux)
	zp, err := zonesvc.Assemble(zonesvc.Setup{DB: db, Audit: w, Projector: proj, Outbox: parts.Outbox,
		Meta: zonesvc.Meta{ProviderName: "Test authority", ProviderLang: "en-GB"}})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s := &stack{fake: fake, parts: parts, zones: zp.Service, pgAdmin: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL),
		pgURL: pgURL, ansp: ansp, nc: nc, cancel: cancel, done: make(chan struct{}), callback: rx.URL + cisp.NotificationsPath}
	go func() { parts.Run(runCtx); close(s.done) }()
	t.Cleanup(s.stop)
	return s
}

var stopOnce sync.Map

func (s *stack) stop() {
	if _, done := stopOnce.LoadOrStore(s, true); done {
		return
	}
	s.cancel()
	<-s.done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(itWait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", itWait, what)
}

func (s *stack) one(t *testing.T, db *sql.DB, q string, args ...any) string {
	t.Helper()
	var out sql.NullString
	if err := db.QueryRow(q, args...).Scan(&out); err != nil && err != sql.ErrNoRows {
		t.Fatalf("%s: %v", q, err)
	}
	return out.String
}

// Invented zones around Tbilisi for tests; no real restriction.
func zoneFeature(id string) string {
	return fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.79,41.69],[44.81,41.69],[44.81,41.71],[44.79,41.71],[44.79,41.69]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","name":[{"text":"Test zone","lang":"en-GB"}],"type":"PROHIBITED","variant":"COMMON","reason":["SENSITIVE"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`, id)
}

func restrictionFeature(id, state string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.80,41.70],[44.82,41.70],[44.82,41.72],[44.80,41.72],[44.80,41.70]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR","EMERGENCY"],"limitedApplicability":[{"startDateTime":"2026-10-02T12:00:00Z","endDateTime":"2026-10-02T15:00:00Z"}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"NOTIFICATION"}],"extendedProperties":{"cis_restriction":{"id":"r-%s","ansp_ref":"TEST-DAR-1","ansp_version":1,"state":%q,"starts_at":"2026-10-02T12:00:00Z","ends_at":"2026-10-02T15:00:00Z","ended_by":null,"uspace_airspace_id":"TSU001"}}}}`, id, id, state))
}

func (s *stack) publishZone(t *testing.T, id string, create bool) zonesvc.Published {
	t.Helper()
	ctx := context.Background()
	in := zonesvc.DraftInput{Feature: []byte(zoneFeature(id)), ValidFrom: &t0, ValidTo: &t1}
	if !create {
		in.Identifier = id
	}
	v, err := s.zones.Draft(ctx, zonesvc.DatasetZones, in, create, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.zones.Approve(ctx, zonesvc.DatasetZones, id, v.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	p, err := s.zones.Publish(ctx, zonesvc.DatasetZones, admin)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A-M1: a zone authored in WP-5 is published to the fake CISP over
// https, signed and acknowledged; the version is read back through the
// webhook into cis_cache; a restriction the fake pushes (signed by the
// ANSP) lands in cis_cache and proj_restrictions and is announced on
// cis.v1.restrictions; the heartbeat beats every period and the fake
// marks the authority stale after 60 s of silence; a version another
// publisher made is a conflict; with webhooks suppressed the
// reconciliation alone brings the next change.
func TestIntegrationPublishAcknowledgeSubscribeProject(t *testing.T) {
	s := newStack(t, false)
	announced := make(chan string, 16)
	sub, err := s.nc.Subscribe("cis.v1.>", func(m *nats.Msg) { announced <- m.Subject + " " + string(m.Data) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	p := s.publishZone(t, "TST001", true)
	waitFor(t, "the publication acknowledged", func() bool {
		return s.one(t, s.pgAdmin, `SELECT state FROM publications WHERE id = $1`, p.Publication.ID) == "acknowledged"
	})
	if v := s.one(t, s.pgAdmin, `SELECT cisp_version FROM publications WHERE id = $1`, p.Publication.ID); v != "1" {
		t.Fatalf("cisp_version %s", v)
	}
	var payload []byte
	if err := s.pgAdmin.QueryRow(`SELECT payload FROM publications WHERE id = $1`, p.Publication.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if cur := s.fake.Current("zones"); cur == nil || !bytes.Equal(cur.Published, payload) || cur.SignatureKID != "authority-publication-it" {
		t.Fatal("the CISP does not hold the published bytes with their signature")
	}
	events := s.one(t, s.pgAdmin, `SELECT string_agg(event_type, ',' ORDER BY id) FROM events WHERE entity_type = 'publication' AND entity_id = $1`,
		fmt.Sprint(p.Publication.ID))
	if events != "publication_queued,publication_sent,publication_acknowledged" {
		t.Fatalf("events %s", events)
	}
	waitFor(t, "the zones version read back into cis_cache", func() bool {
		return s.one(t, s.pgAdmin, `SELECT version FROM cis_cache WHERE dataset = 'zones'`) == "1"
	})
	if kid := s.one(t, s.pgAdmin, `SELECT publisher_kid FROM cis_cache WHERE dataset = 'zones'`); kid != "authority-publication-it" {
		t.Fatalf("kid %q", kid)
	}

	f := restrictionFeature("DAR0001", "active")
	if _, err := s.fake.Publish("restrictions", []json.RawMessage{f}, f, s.ansp, "restriction_activated"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the restriction projected", func() bool {
		return s.one(t, s.tsAdmin, `SELECT state FROM proj_restrictions WHERE identifier = 'DAR0001'`) == "active"
	})
	if v := s.one(t, s.tsAdmin, `SELECT cis_version FROM proj_restrictions_state`); v != "1" {
		t.Fatalf("projection version %s", v)
	}
	if v := s.one(t, s.pgAdmin, `SELECT version FROM cis_cache WHERE dataset = 'restrictions'`); v != "1" {
		t.Fatalf("cache version %s", v)
	}
	waitFor(t, "cis.v1.restrictions announced", func() bool {
		for {
			select {
			case m := <-announced:
				if strings.HasPrefix(m, "cis.v1.restrictions ") && strings.Contains(m, `"cis_version":1`) {
					return true
				}
			default:
				return false
			}
		}
	})

	waitFor(t, "three heartbeats", func() bool { return len(s.fake.Heartbeats()) >= 3 })
	beats := s.fake.Heartbeats()
	if s.fake.PublisherStale(beats[len(beats)-1]) {
		t.Fatal("stale while beating")
	}

	// Another publisher's version is current: the next publication is a
	// conflict, the CISP's version kept.
	other := []json.RawMessage{json.RawMessage(zoneFeature("OTH001"))}
	if _, err := s.fake.Publish("zones", other, []byte(`{"other":true}`), nil, "publication"); err != nil {
		t.Fatal(err)
	}
	p2 := s.publishZone(t, "TST002", true)
	waitFor(t, "the conflict", func() bool {
		return s.one(t, s.pgAdmin, `SELECT state FROM publications WHERE id = $1`, p2.Publication.ID) == "conflict"
	})
	if v := s.one(t, s.pgAdmin, `SELECT conflict_version FROM publications WHERE id = $1`, p2.Publication.ID); v != "2" {
		t.Fatalf("conflict_version %s", v)
	}
	if cur := s.fake.Current("zones"); cur.Number != 2 || cur.Order[0] != "OTH001" {
		t.Fatal("the CISP's version was overwritten")
	}

	// Webhooks suppressed: the reconciliation brings the change.
	s.fake.SuppressWebhooks(true)
	g := restrictionFeature("DAR0001", "ended")
	if _, err := s.fake.Publish("restrictions", []json.RawMessage{g}, g, s.ansp, "restriction_ended"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reconciliation pulled the change", func() bool {
		return s.one(t, s.tsAdmin, `SELECT state FROM proj_restrictions WHERE identifier = 'DAR0001'`) == "ended"
	})
	if s.parts.Counters.Get(cisp.CounterReconcileCatchups) < 1 {
		t.Fatal("not counted as a reconciliation catch-up")
	}

	// The heartbeat stops with the process: 60 s of silence later the
	// CISP marks the authority stale.
	s.stop()
	beats = s.fake.Heartbeats()
	last := beats[len(beats)-1]
	if s.fake.PublisherStale(last.Add(59*time.Second)) || !s.fake.PublisherStale(last.Add(61*time.Second)) {
		t.Fatal("the staleness is not 60 s of silence")
	}
}

// E-02: the CISP down for the whole run. The publication stays pending
// with attempts and a "not yet published" age that grows; the cache
// serves the version it holds with cis_age_s rising, shown stale beyond
// the bound; nothing pretends to be fresh.
func TestIntegrationCISPDownForTheWholeRun(t *testing.T) {
	s := newStack(t, true)
	ctx := context.Background()
	p := s.publishZone(t, "TST001", true)
	waitFor(t, "two attempts", func() bool {
		return s.one(t, s.pgAdmin, `SELECT (attempts >= 2)::text FROM publications WHERE id = $1`, p.Publication.ID) == "true"
	})
	list := func() (string, float64) {
		var state string
		var age float64
		if err := s.pgAdmin.QueryRowContext(ctx, `SELECT state, extract(epoch FROM now() - created_at) FROM publications WHERE id = $1`,
			p.Publication.ID).Scan(&state, &age); err != nil {
			t.Fatal(err)
		}
		return state, age
	}
	st1, age1 := list()
	time.Sleep(300 * time.Millisecond)
	st2, age2 := list()
	if st1 != "pending" && st1 != "sent" || st2 != "pending" && st2 != "sent" || age2 <= age1 {
		t.Fatalf("%s %.2f -> %s %.2f", st1, age1, st2, age2)
	}
	if e := s.one(t, s.pgAdmin, `SELECT last_error FROM publications WHERE id = $1`, p.Publication.ID); !strings.Contains(e, "503") {
		t.Fatalf("last_error %q", e)
	}
	// Nothing was ever pulled: every dataset is stale with no age.
	for _, c := range s.parts.Subscriber.State() {
		if !c.Stale || c.AgeS != nil || c.LastError == "" {
			t.Fatalf("%+v", c)
		}
	}
	if s.parts.Heartbeat.State().ConsecutiveFailures < 1 {
		t.Fatal("the failing heartbeat is not shown")
	}
}

// E-02 with a version held: a restart while the CISP is down serves the
// version cis_cache holds, with its age on the database clock rising.
func TestIntegrationCachedVersionServedWhileTheCISPIsDown(t *testing.T) {
	s := newStack(t, false)
	s.publishZone(t, "TST001", true)
	waitFor(t, "read back", func() bool {
		return s.one(t, s.pgAdmin, `SELECT version FROM cis_cache WHERE dataset = 'zones'`) == "1"
	})
	s.stop()
	s.fake.SetDown(true)
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: s.pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sch, err := cisp.LoadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	sub := cisp.NewSubscriber(cisp.SubscriberConfig{Schemas: sch, Store: cisp.PG{DB: db, Audit: audit.NewWriter(db)}})
	sub.Warm(context.Background())
	age := func() float64 {
		for _, c := range sub.State() {
			if c.Dataset == cisp.DatasetZones && c.Version != nil && *c.Version == 1 && c.AgeS != nil {
				return *c.AgeS
			}
		}
		t.Fatal("the cached version is not served")
		return 0
	}
	a1 := age()
	time.Sleep(200 * time.Millisecond)
	if a2 := age(); a2 <= a1 {
		t.Fatalf("age %.3f -> %.3f", a1, a2)
	}
}

// E-10 on the database: one pending snapshot per dataset; the older one
// is superseded and recorded, a row of another dataset untouched.
func TestIntegrationOutboxSupersedesThePendingSnapshot(t *testing.T) {
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sch, err := cisp.LoadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	o := cisp.NewOutbox(sch, newRing(t, "authority-publication-it"), cisp.PG{DB: db, Audit: audit.NewWriter(db)}, nil)
	coll := func(ids ...string) []byte {
		fs := make([]string, 0, len(ids))
		for _, id := range ids {
			fs = append(fs, zoneFeature(id))
		}
		return []byte(`{"type":"FeatureCollection","features":[` + strings.Join(fs, ",") + `]}`)
	}
	a, err := o.Enqueue(ctx, cisp.DatasetZones, coll("TST001"), admin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.Enqueue(ctx, cisp.DatasetUSpace, []byte(`{"type":"FeatureCollection","features":[]}`), admin)
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.Enqueue(ctx, cisp.DatasetZones, coll("TST001", "TST002"), admin)
	if err != nil {
		t.Fatal(err)
	}
	admin := storetest.Open(t, pgURL)
	state := func(id int64) string {
		var s string
		if err := admin.QueryRow(`SELECT state FROM publications WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if state(a.ID) != "superseded" || state(b.ID) != "pending" || state(c.ID) != "pending" || c.Version != 2 {
		t.Fatalf("%s %s %s v%d", state(a.ID), state(b.ID), state(c.ID), c.Version)
	}
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM events WHERE event_type = 'publication_superseded' AND entity_id = $1`,
		fmt.Sprint(a.ID)).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%v %d", err, n)
	}
}
