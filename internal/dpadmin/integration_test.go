package dpadmin

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// dssTokens signs arbitration tokens as tokens.Client does (aud the
// host of the DSS).
type dssTokens struct{ iss *auth.Issuer }

func (d dssTokens) Token(_ context.Context, baseURL string, scopes ...string) (string, error) {
	u, _ := url.Parse(baseURL)
	return d.iss.Issue("authority-01", u.Hostname(), scopes, time.Hour, time.Now())
}

func service(t *testing.T) (*Service, jetstream.KeyValue, string) {
	t.Helper()
	_, js := bustest.Connect(t)
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	cfg := dpviews.OversightBucketConfig(bustest.Name("dpo"))
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), cfg.Bucket) })
	kv, err := bus.OpenBucket(context.Background(), js, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cnt := &core.Counters{}
	s := &Service{DB: db, Audit: audit.NewWriter(db), KVTimeout: 2 * time.Second, Counters: cnt,
		Oversight: func(context.Context) (jetstream.KeyValue, error) { return kv, nil },
		Logger:    logging.Discard(), Limiter: logging.NewLimiter(logging.Discard(), time.Minute, 0, cnt)}
	return s, kv, u
}

func events(t *testing.T, u, eventType string) int {
	t.Helper()
	db := storetest.Open(t, u)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE event_type = $1`, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// POST /v1/dp/views stores the area with its events row and, after the
// commit, publishes every area to KV with the table's version; a
// publisher holding an older version never replaces a newer value.
func TestIntegrationOversightAreasArePublishedAfterTheCommit(t *testing.T) {
	s, kv, u := service(t)
	ctx := adminCtx()
	for i, b := range [][]float64{{44.70, 41.60, 44.75, 41.65}, {44.80, 41.70, 44.85, 41.73}} {
		resp, err := s.CreateDPView(ctx, gen.CreateDPViewRequestObject{Body: &gen.DPViewInput{Label: "area", Bbox: b}})
		if err != nil {
			t.Fatalf("area %d: %v", i, err)
		}
		if v := resp.(gen.CreateDPView201JSONResponse); v.CreatedBy != "admin-1" || len(v.Bbox) != 4 {
			t.Fatalf("%+v", v)
		}
	}
	e, err := kv.Get(context.Background(), dpviews.OversightKey)
	if err != nil {
		t.Fatal(err)
	}
	o, err := dpviews.DecodeOversight(e.Value())
	if err != nil || len(o.Areas) != 2 || o.Version != o.Areas[1].ID {
		t.Fatalf("%+v %v", o, err)
	}
	if n := events(t, u, audit.EventDPViewCreated); n != 2 {
		t.Fatalf("%d events rows", n)
	}
	// An older value written by a slower replica is refused.
	stored, err := dpviews.PutOversight(context.Background(), kv, dpviews.Oversight{Version: o.Version - 1}, 3)
	if err != nil || stored {
		t.Fatalf("older version stored %v %v", stored, err)
	}
	list, err := s.ListDPViews(ctx, gen.ListDPViewsRequestObject{})
	if err != nil || len(list.(gen.ListDPViews200JSONResponse).Views) != 2 {
		t.Fatalf("%+v %v", list, err)
	}
}

// F3548 availability arbitration: the request is recorded, the DSS's
// version read and the state set with it, the outcome recorded; a DSS
// that is down answers 502 and the failure is recorded (E-01). The
// token carries utm.availability_arbitration for the DSS's host.
func TestIntegrationAvailabilityArbitration(t *testing.T) {
	s, _, u := service(t)
	dss := fakedss.NewDSS()
	defer dss.Close()
	iss, err := auth.NewIssuer("https://authority.example.test", tokentest.Key(t, 0), "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	s.DSS, s.Tokens = dss.URL(), dssTokens{iss: iss}
	ctx := adminCtx()
	for _, state := range []string{"Down", "Normal"} {
		resp, err := s.SetDPProviderAvailability(ctx, gen.SetDPProviderAvailabilityRequestObject{UssId: "ussp-lab-01",
			Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: gen.DPAvailabilityInputAvailability(state), Reason: "lab"}})
		if err != nil {
			t.Fatal(err)
		}
		if r := resp.(gen.SetDPProviderAvailability200JSONResponse); string(r.Availability) != state || r.Version == "" {
			t.Fatalf("%+v", r)
		}
	}
	if a, ok := dss.Availability("ussp-lab-01"); !ok || a.Status.Availability != f3548.Normal {
		t.Fatalf("the DSS holds %+v", a)
	}
	host := func() string { x, _ := url.Parse(dss.URL()); return x.Hostname() }()
	for _, c := range dss.Claims() {
		if c.Aud != host || c.Scope != ScopeArbitration {
			t.Fatalf("%s: aud %q scope %q", c.Path, c.Aud, c.Scope)
		}
	}
	if events(t, u, audit.EventDPAvailabilityRequested) != 2 || events(t, u, audit.EventDPAvailabilitySet) != 2 {
		t.Fatal("arbitrations not recorded before and after")
	}
	dss.SetDown(true)
	_, err = s.SetDPProviderAvailability(ctx, gen.SetDPProviderAvailabilityRequestObject{UssId: "ussp-lab-01",
		Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: "Down", Reason: "lab"}})
	if statusCode(err) != 502 || events(t, u, audit.EventDPAvailabilityFailed) != 1 || s.Counters.Snapshot()[CounterArbitrationsFailed] != 1 {
		t.Fatalf("DSS down: %v", err)
	}
}
