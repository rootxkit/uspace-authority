package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// fixture is a migrated scratch database with a writer working as the
// application role and a superuser handle for tampering.
type fixture struct {
	w     *Writer
	admin *sql.DB
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: u, Role: pg.AppRole, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return fixture{w: NewWriter(db), admin: storetest.Open(t, u)}
}

func (f fixture) record(t *testing.T, ts time.Time, payload any) Recorded {
	t.Helper()
	var rec Recorded
	err := f.w.DB.WithTx(context.Background(), func(q *gen.Queries) error {
		var err error
		ev := validEvent()
		ev.TS, ev.Payload = ts, payload
		rec, err = f.w.Record(context.Background(), q, ev)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (f fixture) verify(t *testing.T, month time.Time) Result {
	t.Helper()
	res, err := f.w.Verify(context.Background(), month)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// asAppRole runs stmt on one connection that has SET ROLE to the
// application role, as api's pool does.
func (f fixture) asAppRole(ctx context.Context, stmt string) error {
	conn, err := f.admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET ROLE "+pg.AppRole); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "RESET ROLE") }()
	_, err = conn.ExecContext(ctx, stmt)
	return err
}

var (
	jan = time.Date(2026, 1, 31, 23, 59, 58, 0, time.UTC)
	feb = time.Date(2026, 2, 1, 0, 0, 1, 0, time.UTC)
)

// E-01: the INSERT is accepted, and beside it UPDATE and DELETE are
// refused, by grant for the application role and by the trigger for the
// owner (a superuser here), so the refusal is not only a missing grant.
func TestIntegrationEventsAreAppendOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rec := f.record(t, jan, map[string]any{"k": "v"})
	if rec.ID == 0 || rec.PrevHash != GenesisHash || len(rec.Hash) != 64 {
		t.Fatalf("first row %+v", rec)
	}
	var n int
	if err := f.admin.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d %v", n, err)
	}
	for _, stmt := range []string{
		`UPDATE events SET actor_id = 'someone-else'`,
		`DELETE FROM events`,
	} {
		_, err := f.admin.ExecContext(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "events is append-only") {
			t.Errorf("owner %s: %v", stmt, err)
		}
		if err := f.asAppRole(ctx, stmt); store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Errorf("%s %s: %v", pg.AppRole, stmt, err)
		}
	}
	if err := f.admin.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE actor_id = 'user-1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after the refusals: %d rows %v", n, err)
	}
}

// The chain crosses a month boundary: February's first row links to
// January's last, each month verifies, and the partitions are monthly.
func TestIntegrationHashChainAcrossAMonthBoundary(t *testing.T) {
	f := newFixture(t)
	var janRecs, febRecs []Recorded
	for i := range 3 {
		janRecs = append(janRecs, f.record(t, jan.Add(time.Duration(i)*time.Millisecond), map[string]any{"i": i}))
	}
	for i := range 2 {
		febRecs = append(febRecs, f.record(t, feb.Add(time.Duration(i)*time.Millisecond), map[string]any{"i": i, "n": 1.50}))
	}
	if janRecs[0].PrevHash != GenesisHash || janRecs[1].PrevHash != janRecs[0].Hash || janRecs[2].PrevHash != janRecs[1].Hash {
		t.Fatalf("january is not linear: %+v", janRecs)
	}
	if febRecs[0].PrevHash != janRecs[2].Hash {
		t.Fatalf("february's first row links to %s, january ends with %s", febRecs[0].PrevHash, janRecs[2].Hash)
	}
	if febRecs[1].PrevHash != febRecs[0].Hash {
		t.Fatal("february is not linear")
	}
	// E-02: read what the success says.
	for _, c := range []struct {
		month time.Time
		recs  []Recorded
	}{{jan, janRecs}, {feb, febRecs}} {
		res := f.verify(t, c.month)
		last := c.recs[len(c.recs)-1]
		if res.Broken != nil || res.Rows != int64(len(c.recs)) || res.FirstID != c.recs[0].ID || res.LastID != last.ID || res.LastHash != last.Hash {
			t.Fatalf("%s: %+v (broken %+v)", c.month.Format("2006-01"), res, res.Broken)
		}
	}
	var parts string
	err := f.admin.QueryRow(`SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'events'::regclass`).Scan(&parts)
	if err != nil || parts != "events_2026_01,events_2026_02" {
		t.Fatalf("partitions %q %v", parts, err)
	}
	// A month with no rows verifies, and says it checked none.
	if res := f.verify(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)); res.Broken != nil || res.Rows != 0 || res.Month != "2026-03" {
		t.Fatalf("empty month %+v", res)
	}
}

// E-01: Verify can detect. A superuser bypasses the trigger and rewrites
// one January payload; January breaks at that row, February, untouched,
// still verifies (E-02).
func TestIntegrationVerifyDetectsATamperedRowAndPassesAnUntouchedMonth(t *testing.T) {
	f := newFixture(t)
	var janRecs []Recorded
	for i := range 4 {
		janRecs = append(janRecs, f.record(t, jan.Add(time.Duration(i)*time.Millisecond), map[string]any{"amount": i}))
	}
	febRec := f.record(t, feb, map[string]any{"amount": 9})
	if res := f.verify(t, jan); res.Broken != nil || res.Rows != 4 {
		t.Fatalf("before tampering: %+v", res)
	}

	tamper := func(stmt string, args ...any) {
		t.Helper()
		ctx := context.Background()
		conn, err := f.admin.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, stmt, args...); err != nil {
			t.Fatal(err)
		}
		_, _ = conn.ExecContext(ctx, `RESET session_replication_role`)
	}
	tamper(`UPDATE events SET payload = '{"amount": 1000}' WHERE id = $1`, janRecs[2].ID)

	res := f.verify(t, jan)
	if res.Broken == nil || res.Broken.ID != janRecs[2].ID || res.Broken.Reason != BrokenHash || res.Broken.Got != janRecs[2].Hash {
		t.Fatalf("tampered payload: %+v broken %+v", res, res.Broken)
	}
	if res.Rows != 3 {
		t.Fatalf("verification should stop at the first broken row: %d rows", res.Rows)
	}
	if res := f.verify(t, feb); res.Broken != nil || res.Rows != 1 || res.LastHash != febRec.Hash {
		t.Fatalf("untouched february: %+v broken %+v", res, res.Broken)
	}

	// Recomputing a hash after the edit does not hide it: the next row
	// no longer links to it.
	tamper(`UPDATE events SET hash = $1 WHERE id = $2`, strings.Repeat("a", 64), janRecs[2].ID)
	res = f.verify(t, jan)
	if res.Broken == nil || res.Broken.ID != janRecs[2].ID || res.Broken.Reason != BrokenHash {
		t.Fatalf("forged hash: %+v", res.Broken)
	}
	tamper(`UPDATE events SET hash = $1, payload = '{"amount": 2}' WHERE id = $2`, janRecs[2].Hash, janRecs[2].ID)
	if res := f.verify(t, jan); res.Broken != nil {
		t.Fatalf("restored row: %+v", res.Broken)
	}
	tamper(`UPDATE events SET prev_hash = $1 WHERE id = $2`, strings.Repeat("b", 64), janRecs[1].ID)
	res = f.verify(t, jan)
	if res.Broken == nil || res.Broken.ID != janRecs[1].ID || res.Broken.Reason != BrokenPrevHash {
		t.Fatalf("relinked row: %+v", res.Broken)
	}
}

// Concurrent writers of one month leave one linear chain (the month
// lock), and Verify pages through more rows than one page holds (E-10).
func TestIntegrationConcurrentWritersKeepTheChainLinear(t *testing.T) {
	f := newFixture(t)
	const writers, each = 6, 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for g := range writers {
		wg.Go(func() {
			for i := range each {
				err := f.w.DB.WithTx(context.Background(), func(q *gen.Queries) error {
					ev := validEvent()
					ev.Payload = map[string]any{"writer": g, "i": i}
					_, err := f.w.Record(context.Background(), q, ev)
					return err
				})
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := verify(context.Background(), f.w.DB.Queries(), MonthStart(time.Now()), 4)
	if err != nil || res.Broken != nil || res.Rows != writers*each {
		t.Fatalf("%+v broken %+v err %v", res, res.Broken, err)
	}
}

func TestIntegrationQueryFiltersAndPages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range 5 {
		err := f.w.DB.WithTx(ctx, func(q *gen.Queries) error {
			ev := validEvent()
			ev.EntityID = fmt.Sprint(i % 2)
			_, err := f.w.Record(ctx, q, ev)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	q := f.w.DB.Queries()
	p1, err := Query(ctx, q, Filter{EntityType: "authority_policy", EntityID: "0", Limit: 2})
	if err != nil || len(p1.Events) != 2 || p1.NextBeforeID == 0 || p1.Events[0].ID <= p1.Events[1].ID {
		t.Fatalf("page 1: %+v %v", p1, err)
	}
	p2, err := Query(ctx, q, Filter{EntityType: "authority_policy", EntityID: "0", Limit: 2, BeforeID: p1.NextBeforeID})
	if err != nil || len(p2.Events) != 1 || p2.NextBeforeID != 0 {
		t.Fatalf("page 2: %+v %v", p2, err)
	}
	none, err := Query(ctx, q, Filter{ActorID: "nobody"})
	if err != nil || len(none.Events) != 0 {
		t.Fatalf("no match: %+v %v", none, err)
	}
	all, err := Query(ctx, q, Filter{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || len(all.Events) != 5 {
		t.Fatalf("window: %d %v", len(all.Events), err)
	}
}
