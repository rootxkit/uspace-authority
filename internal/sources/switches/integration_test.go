package switches

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

type natsMsg = nats.Msg

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

type fixture struct {
	svc    *Service
	pgURL  string
	js     jetstream.JetStream
	bucket string
	source sources.Source
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	nc, js := bustest.Connect(t)
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	bucket, subject := bustest.Name("sc"), "ctltest."+bustest.Name("sources")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	cfg := jetstream.KeyValueConfig{Bucket: bucket, History: bus.BucketHistory, MaxValueSize: bus.DefaultSourceControlValueBytes, Storage: jetstream.MemoryStorage}
	src := sources.Source{
		Open: func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, js, cfg) },
		Conn: nc, Subject: subject, Timeout: 2 * time.Second,
	}
	svc := &Service{
		DB: db, Audit: audit.NewWriter(db), Store: KV{Source: src}, Push: nc, Subject: subject,
		MaxBytes: bus.DefaultSourceControlValueBytes, Bucket: bucket, Counters: &core.Counters{},
	}
	return &fixture{svc: svc, pgURL: u, js: js, bucket: bucket, source: src}
}

// stored is the document in the bucket, or false.
func (f *fixture) stored(t *testing.T) (sources.Document, bool) {
	t.Helper()
	raw, published, err := f.source.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		return sources.Document{}, false
	}
	d, err := sources.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d, true
}

func (f *fixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := storetest.Open(t, f.pgURL).QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func status(err error) (int, string) {
	var pe *httpx.ProblemError
	if errors.As(err, &pe) {
		return pe.Problem.Status, pe.Problem.Type
	}
	return 0, ""
}

// A switch is the row, its events row and the whole state in KV, in one
// transaction; versions rise within the epoch and a follower takes each
// one; a switch to the state held writes nothing (E-01: the write and
// the no-op side by side).
func TestIntegrationSwitchWritesRowEventAndStateWithRisingVersions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fol := sources.NewFollower()

	r1, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, nil, false, "firmware recall")
	if err != nil || !r1.Changed || r1.Control.Actor != "admin-1" || r1.Version == 0 {
		t.Fatalf("%+v %v", r1, err)
	}
	d, ok := f.stored(t)
	if !ok || d.Version != r1.Version || d.Epoch != r1.Epoch || len(d.Controls) != 1 || d.Controls[0].Reason != "firmware recall" {
		t.Fatalf("stored %+v", d)
	}
	if !fol.Apply(d) || fol.Query(sources.TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatal("the follower did not take the switch")
	}
	r2, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, strp("rx-1"), false, "suspected tampering")
	if err != nil || r2.Version <= r1.Version || r2.Epoch != r1.Epoch {
		t.Fatalf("%+v %v", r2, err)
	}
	r3, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, nil, true, "recall over")
	if err != nil || r3.Version <= r2.Version {
		t.Fatalf("%+v %v", r3, err)
	}
	d, _ = f.stored(t)
	if !fol.Apply(d) || fol.Query(sources.TypeDirectRID, strp("rx-1")).Enabled || !fol.Query(sources.TypeDirectRID, strp("rx-2")).Enabled {
		t.Fatalf("after the type is back on, rx-1 stays off by instance: %+v", d)
	}
	if who := fol.DisabledByWho(sources.TypeDirectRID, strp("rx-1")); who == nil || *who != "admin-1" {
		t.Fatal("who")
	}

	// The same switch again: nothing written, nothing recorded.
	same, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, nil, true, "again")
	if err != nil || same.Changed || same.Version != r3.Version {
		t.Fatalf("no-op %+v %v", same, err)
	}
	if after, _ := f.stored(t); after.Version != r3.Version {
		t.Fatal("a no-op switch rewrote the state")
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE entity_type = 'source'`); n != 3 {
		t.Fatalf("%d events", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE event_type = 'source_disabled' AND actor_id = 'admin-1'
		AND payload->>'reason' = 'suspected tampering' AND entity_id = 'direct_rid/rx-1'`); n != 1 {
		t.Fatal("the instance switch's events row")
	}
	if f.svc.Counters.Get(CounterSwitched) != 3 || f.svc.Counters.Get(CounterUnchanged) != 1 {
		t.Fatal(f.svc.Counters.Snapshot())
	}
	if _, err := f.svc.Switch(ctx, admin, "remote_id", nil, false, "x"); err == nil || !strings.Contains(err.Error(), "source_type") {
		t.Fatalf("unknown type: %v", err)
	}
}

// B-09, SC-08 step 8: with the store unreachable a switch is refused
// with 503 and nothing is written: no row, no events row, no version.
func TestIntegrationSwitchRefusedWithoutTheStoreWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.svc.Store = KV{Source: sources.Source{
		Open: func(context.Context) (jetstream.KeyValue, error) { return nil, errors.New("nats: no responders") },
	}}
	_, err := f.svc.Switch(context.Background(), admin, sources.TypeDirectRID, nil, false, "x")
	if code, typ := status(err); code != http.StatusServiceUnavailable || !strings.HasSuffix(typ, "/"+SlugUnavailable) {
		t.Fatalf("%v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM source_controls`); n != 0 {
		t.Fatalf("%d rows", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE entity_type = 'source'`); n != 0 {
		t.Fatalf("%d events", n)
	}
	if n := f.count(t, `SELECT version FROM source_control_epoch`); n != 0 {
		t.Fatalf("version %d", n)
	}
	if f.svc.Counters.Get(CounterStoreRefused) != 1 {
		t.Fatal(f.svc.Counters.Snapshot())
	}
}

// E-10: a state the bucket cannot hold is refused naming the bound, and
// nothing is written.
func TestIntegrationSwitchRefusesAStatePastTheBound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, strp("rx-1"), false, "x"); err != nil {
		t.Fatal(err)
	}
	d, _ := f.stored(t)
	raw, _ := sources.Encode(d, time.Now())
	f.svc.MaxBytes = len(raw) + 10 // room for the first row, not a second
	_, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, strp("rx-2"), false, "x")
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "controls" || !strings.Contains(err.Error(), "SOURCE_CONTROL_MAX_VALUE_BYTES") {
		t.Fatalf("%v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM source_controls`); n != 1 {
		t.Fatalf("%d rows", n)
	}
	if after, _ := f.stored(t); after.Version != d.Version {
		t.Fatal("a refused state was written")
	}
}

// The republish repairs a deleted key: at once with Republish, and on
// its timer with RunRepublish; with the bucket as it should be it writes
// nothing (E-01 pair).
func TestIntegrationRepublishRepairsADeletedKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Switch(ctx, admin, sources.TypeNetworkRID, strp("ussp-1"), false, "x"); err != nil {
		t.Fatal(err)
	}
	want, _ := f.stored(t)
	if wrote, err := f.svc.Republish(ctx); err != nil || wrote {
		t.Fatalf("an intact bucket was rewritten: %v %v", wrote, err)
	}
	kv, err := f.js.KeyValue(ctx, f.bucket)
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.Delete(ctx, sources.StateKey); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.stored(t); ok {
		t.Fatal("the key is still there")
	}
	if wrote, err := f.svc.Republish(ctx); err != nil || !wrote {
		t.Fatalf("not repaired: %v %v", wrote, err)
	}
	if got, ok := f.stored(t); !ok || !got.Same(want) {
		t.Fatalf("repaired as %+v, want %+v", got, want)
	}

	// The periodic republish (SOURCE_CONTROL_REPUBLISH_S, 60 s; 200 ms
	// here) repairs it without anyone asking.
	if err := kv.Purge(ctx, sources.StateKey); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); f.svc.RunRepublish(rctx, 200*time.Millisecond) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, ok := f.stored(t); ok && got.Same(want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the periodic republish did not repair the key")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if f.svc.Counters.Get(CounterRepublished) < 2 {
		t.Fatal(f.svc.Counters.Snapshot())
	}
}

// B-09: a bucket ahead of the database in the same epoch (a restored
// database) starts a new epoch, audited; a follower holding the higher
// version takes the database's state at any version under it (the new
// epoch accepted at a lower version), where the same version under the
// old epoch would have been ignored.
func TestIntegrationRestoredDatabaseStartsANewEpochFollowersTake(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, nil, false, "before the backup"); err != nil {
		t.Fatal(err)
	}
	db, _ := f.stored(t)
	// After the backup the type was switched on and further changes
	// raised the version; then the database was restored.
	ahead := db
	ahead.Version += 5
	ahead.Controls = []sources.Control{{SourceType: sources.TypeDirectRID, Enabled: true, Reason: "lost with the restore", Actor: "admin-2", ChangedAt: time.Now().UTC(), Version: ahead.Version}}
	raw, _ := sources.Encode(ahead, time.Now())
	if err := f.svc.Store.Put(ctx, raw); err != nil {
		t.Fatal(err)
	}
	fol := sources.NewFollower()
	fol.Apply(ahead)
	if fol.Apply(db) {
		t.Fatal("the database's older version was taken in the same epoch")
	}
	if wrote, err := f.svc.Republish(ctx); err != nil || !wrote {
		t.Fatalf("%v %v", wrote, err)
	}
	got, _ := f.stored(t)
	if got.Epoch == db.Epoch || got.Version != db.Version || !got.SameContent(db) {
		t.Fatalf("republished %+v from %+v", got, db)
	}
	if !fol.Apply(got) || fol.Query(sources.TypeDirectRID, nil).Enabled {
		t.Fatal("the follower did not take the new epoch")
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE event_type = 'source_control_epoch_started' AND actor_type = 'system'`); n != 1 {
		t.Fatalf("%d epoch events", n)
	}
	// The next switch continues in the new epoch.
	r, err := f.svc.Switch(ctx, admin, sources.TypeDirectRID, nil, true, "after the restore")
	if err != nil || r.Epoch != got.Epoch || r.Version <= got.Version {
		t.Fatalf("%+v %v", r, err)
	}
}

// A changed default (SOURCES_DEFAULT_DENY) is a new state: the republish
// gives it the next version, so followers holding the old one take it.
func TestIntegrationChangedDefaultIsRepublishedWithANewVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Republish(ctx); err != nil {
		t.Fatal(err)
	}
	before, ok := f.stored(t)
	if !ok || before.DefaultDeny {
		t.Fatalf("%+v %v", before, ok)
	}
	fol := sources.NewFollower()
	fol.Apply(before)
	f.svc.DefaultDeny = true
	if wrote, err := f.svc.Republish(ctx); err != nil || !wrote {
		t.Fatalf("%v %v", wrote, err)
	}
	after, _ := f.stored(t)
	if !after.DefaultDeny || after.Version <= before.Version || after.Epoch != before.Epoch {
		t.Fatalf("%+v", after)
	}
	if !fol.Apply(after) || fol.Query(sources.TypeANSPFeed, strp("feed-1")).Enabled {
		t.Fatal("the follower did not take the new default")
	}
}

// After a commit the state is pushed: a follower subscribed to the push
// subject alone sees the switch.
func TestIntegrationSwitchIsPushed(t *testing.T) {
	f := newFixture(t)
	ch := make(chan []byte, 4)
	sub, err := f.source.Conn.Subscribe(f.source.Subject, func(m *natsMsg) { ch <- m.Data })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := f.source.Conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Switch(context.Background(), admin, sources.TypeANSPFeed, nil, false, "x"); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-ch:
		fol := sources.NewFollower()
		if !fol.Offer(raw) || fol.Query(sources.TypeANSPFeed, nil).Enabled {
			t.Fatal("the pushed state does not disable the type")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing pushed")
	}
}
