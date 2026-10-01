package policy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

type failingPublisher struct{}

func (failingPublisher) PublishPolicy(context.Context, Policy) error {
	return errors.New("bus unreachable")
}

func newService(t *testing.T) (*Service, *recorder, string) {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: u, Role: pg.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	rec := &recorder{}
	return &Service{DB: db, Audit: audit.NewWriter(db), Publisher: rec, Counters: NewFollower(nil).Counters()}, rec, u
}

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

func problemStatus(err error) int {
	var pe *httpx.ProblemError
	if errors.As(err, &pe) {
		return pe.Problem.Status
	}
	return 0
}

// INV-03: the seeded version 1 is active and holds exactly Defaults().
func TestIntegrationSeededPolicyIsTheDocumentedDefaults(t *testing.T) {
	svc, _, _ := newService(t)
	p, err := svc.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || !p.Active || p.Thresholds != Defaults() || p.ActivatedAt == nil || p.ActivatedBy != "migration" {
		t.Fatalf("seed %+v\nwant %+v", p, Defaults())
	}
}

func TestIntegrationCreateActivateAndPublish(t *testing.T) {
	svc, rec, _ := newService(t)
	ctx := context.Background()
	th := Defaults()
	th.HeightLimitAGLM = 100
	p2, err := svc.Create(ctx, th, "lower limit for the trial", admin)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Version != 2 || p2.Active || p2.CreatedBy != "admin-1" || p2.HeightLimitAGLM != 100 {
		t.Fatalf("created %+v", p2)
	}
	if active, _ := svc.Active(ctx); active.Version != 1 {
		t.Fatalf("creating activated: %d", active.Version)
	}
	if len(rec.got) != 0 {
		t.Fatal("creating published")
	}

	got, err := svc.Activate(ctx, 2, admin)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active || got.ActivatedBy != "admin-1" || got.ActivatedAt == nil {
		t.Fatalf("activated %+v", got)
	}
	if active, _ := svc.Active(ctx); active.Version != 2 || active.HeightLimitAGLM != 100 {
		t.Fatalf("active %+v", active)
	}
	if len(rec.got) != 1 || rec.got[0] != 2 {
		t.Fatalf("published %v", rec.got)
	}

	// Both acts are events in the log, attributed to the admin.
	page, err := audit.Query(ctx, svc.DB.Queries(), audit.Filter{EntityType: "authority_policy"})
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("events %+v %v", page, err)
	}
	if page.Events[0].EventType != audit.EventPolicyActivated || page.Events[1].EventType != audit.EventPolicyCreated ||
		page.Events[0].ActorID != "admin-1" || *page.Events[0].EntityID != "2" {
		t.Fatalf("events %+v", page.Events)
	}
	if res, err := svc.Audit.Verify(ctx, page.Events[0].TS); err != nil || res.Broken != nil || res.Rows != 2 {
		t.Fatalf("verify %+v %v", res, err)
	}
}

// E-01 pair of Activate: the newer version above was accepted; an older
// or the same version is refused with 409, a missing one with 404, and
// neither changes the active policy or publishes.
func TestIntegrationActivateRefusesAnOlderOrMissingVersion(t *testing.T) {
	svc, rec, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, Defaults(), "", admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(ctx, 2, admin); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		version int64
		status  int
	}{{1, http.StatusConflict}, {2, http.StatusConflict}, {99, http.StatusNotFound}} {
		if _, err := svc.Activate(ctx, c.version, admin); problemStatus(err) != c.status {
			t.Errorf("activate %d: %v", c.version, err)
		}
	}
	if active, _ := svc.Active(ctx); active.Version != 2 || len(rec.got) != 1 {
		t.Fatalf("active %d published %v", active.Version, rec.got)
	}
}

func TestIntegrationCreateRefusesInvalidThresholdsAndWritesNothing(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	th := Defaults()
	th.StaleAfterS, th.DPPollHz = 0, -1
	_, err := svc.Create(ctx, th, "", admin)
	if got := fieldsOf(err); len(got) != 2 || got[0] != "stale_after_s" || got[1] != "dp_poll_hz" {
		t.Fatalf("refusal %v", err)
	}
	if v, _ := svc.DB.Queries().MaxPolicyVersion(ctx); v != 1 {
		t.Fatalf("a version was stored: %d", v)
	}
	if page, _ := audit.Query(ctx, svc.DB.Queries(), audit.Filter{}); len(page.Events) != 0 {
		t.Fatalf("an event was written: %+v", page.Events)
	}
}

// The database refuses what Validate refuses, so a value that bypasses
// the service still cannot disarm a check (E-15); the same insert with
// a valid value is accepted (E-01).
func TestIntegrationTableRefusesNaNInfinityAndZero(t *testing.T) {
	_, _, u := newService(t)
	db := storetest.Open(t, u)
	insert := `INSERT INTO authority_policy (version, created_by, clear_after_s) VALUES ($1, 'test', $2::float8)`
	for i, v := range []string{"NaN", "Infinity", "-Infinity", "0", "-3"} {
		if _, err := db.Exec(insert, 10+i, v); store.SQLState(err) != store.StateCheckViolation {
			t.Errorf("clear_after_s = %s: %v", v, err)
		}
	}
	if _, err := db.Exec(insert, 20, "3"); err != nil {
		t.Fatalf("valid insert: %v", err)
	}
	// A second active row is refused by the partial unique index.
	_, err := db.Exec(`UPDATE authority_policy SET active = true, activated_at = now(), activated_by = 't' WHERE version = 20`)
	if store.SQLState(err) != store.StateUniqueViolation {
		t.Fatalf("two active rows: %v", err)
	}
}

// A failed publish does not undo the activation: it is counted and the
// followers catch up on their re-read.
func TestIntegrationActivateCountsAFailedPublish(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	svc.Publisher = failingPublisher{}
	if _, err := svc.Create(ctx, Defaults(), "", admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(ctx, 2, admin); err != nil {
		t.Fatal(err)
	}
	if active, _ := svc.Active(ctx); active.Version != 2 || svc.Counters.Get(CounterPublishFailed) != 1 {
		t.Fatalf("active %d counters %v", active.Version, svc.Counters.Snapshot())
	}
}
