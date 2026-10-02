package assign

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

func newService(t *testing.T, maxBytes int) (*Service, string, jetstream.JetStream, string) {
	t.Helper()
	_, js := bustest.Connect(t)
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	bucket := bustest.Name("cells")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	cfg := jetstream.KeyValueConfig{Bucket: bucket, History: bus.BucketHistory, MaxValueSize: bus.CellsValueBytes, Storage: jetstream.MemoryStorage}
	st := cell.Store{Open: func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, js, cfg) }, MaxBytes: maxBytes}
	return New(db, audit.NewWriter(db), st, nil), u, js, bucket
}

func events(t *testing.T, u string) []string {
	t.Helper()
	rows, err := storetest.Open(t, u).Query(`SELECT actor_id || '|' || (payload->>'reason') || '|' || (payload->>'to_version')
		FROM events WHERE event_type = 'cell_ownership_changed' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func status(err error) int {
	var pe *httpx.ProblemError
	if errors.As(err, &pe) {
		return pe.Problem.Status
	}
	return 0
}

// A rebalance: the map lands in KV with the next version, each change is
// an events row with the actor and the reason, and a worker's claim
// follows the map.
func TestIntegrationPutWritesTheMapAndAnEventsRow(t *testing.T) {
	svc, u, _, _ := newService(t, bus.CellsValueBytes)
	ctx := context.Background()
	if _, err := svc.Get(ctx); status(err) != http.StatusNotFound {
		t.Fatalf("before any map: %v", err)
	}
	o, err := svc.Put(ctx, admin, map[string]string{"c3:131:224": "detect-1", "c3:131:225": "detect-2"}, "initial split")
	if err != nil || o.Version != 1 || o.UpdatedBy != "admin-1" {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = svc.Put(ctx, admin, map[string]string{"c3:131:224": "detect-1", "c3:131:225": "detect-1"}, "detect-2 retired")
	if err != nil || o.Version != 2 {
		t.Fatalf("%+v %v", o, err)
	}
	got, err := svc.Get(ctx)
	if err != nil || got.Version != 2 || got.Assignments["c3:131:225"] != "detect-1" {
		t.Fatalf("%+v %v", got, err)
	}
	claim, err := cell.LoadClaim(ctx, svc.Store, "detect-1", false, 1, 0)
	if err != nil || len(claim.Cells) != 2 || claim.Version != 2 {
		t.Fatalf("%+v %v", claim, err)
	}
	if _, err := cell.LoadClaim(ctx, svc.Store, "detect-2", false, 1, 0); !errors.Is(err, cell.ErrNoCells) {
		t.Fatalf("retired worker: %v", err)
	}
	if ev := events(t, u); len(ev) != 2 || ev[0] != "admin-1|initial split|1" || ev[1] != "admin-1|detect-2 retired|2" {
		t.Fatalf("events %v", ev)
	}
	// A bad map is refused by path and records nothing.
	if _, err := svc.Put(ctx, admin, map[string]string{"c5:1317:2248": "detect-1"}, "x"); err == nil ||
		!strings.Contains(err.Error(), "assignments.c5:1317:2248") {
		t.Fatalf("bad map: %v", err)
	}
	if len(events(t, u)) != 2 {
		t.Fatal("a refused map was recorded")
	}
}

// B-09 shape: with the bucket unreachable the change is refused with 503
// and nothing is recorded.
func TestIntegrationPutRefusedWithoutTheStore(t *testing.T) {
	svc, u, _, _ := newService(t, bus.CellsValueBytes)
	svc.Store.Open = func(context.Context) (jetstream.KeyValue, error) { return nil, errors.New("bus down") }
	_, err := svc.Put(context.Background(), admin, map[string]string{"c3:131:224": "detect-1"}, "x")
	var pe *httpx.ProblemError
	if !errors.As(err, &pe) || pe.Problem.Status != http.StatusServiceUnavailable || !strings.HasSuffix(pe.Problem.Type, "/"+SlugStoreUnavailable) {
		t.Fatalf("%v", err)
	}
	if len(events(t, u)) != 0 || svc.Counters.Get(CounterStoreRefused) != 1 {
		t.Fatal("a refused change was recorded or not counted")
	}
}

// E-10: a map past the bucket's value bound is refused naming the bound,
// and nothing is recorded; the bucket itself refuses a value past its
// own bound.
func TestIntegrationPutRefusesAMapPastTheBound(t *testing.T) {
	svc, u, js, bucket := newService(t, 120)
	_, err := svc.Put(context.Background(), admin, map[string]string{"c3:131:224": "detect-1", "c3:131:225": "detect-1", "c3:131:226": "detect-1"}, "x")
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "assignments" || !strings.Contains(err.Error(), "the bound is 120") {
		t.Fatalf("%v", err)
	}
	if len(events(t, u)) != 0 {
		t.Fatal("a refused map was recorded")
	}
	kv, err := js.KeyValue(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(context.Background(), "x", make([]byte, bus.CellsValueBytes+1)); err == nil {
		t.Fatal("the bucket took a value past its bound")
	}
}
