package pg_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

func open(t *testing.T, u, role string) *pg.DB {
	t.Helper()
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: u, Role: role, ApplicationName: "uspace-authority-test", MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// Two goroutines contend for one job lock: exactly one runs, and the
// other gets it once it is released.
func TestIntegrationAdvisoryLockContention(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	db := open(t, u, "")
	ctx := context.Background()
	key := pg.LockKey("job:test")

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan *pg.Lock, 2)
	for range 2 {
		wg.Go(func() {
			<-start
			l, ok, err := db.AdvisoryLock(ctx, key)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				results <- l
			} else {
				results <- nil
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	var held []*pg.Lock
	for l := range results {
		if l != nil {
			held = append(held, l)
		}
	}
	if len(held) != 1 {
		t.Fatalf("%d goroutines hold the lock, want exactly 1", len(held))
	}
	// Still held: a third try fails.
	if _, ok, err := db.AdvisoryLock(ctx, key); err != nil || ok {
		t.Fatalf("while held: ok %v err %v", ok, err)
	}
	if err := held[0].Release(ctx); err != nil {
		t.Fatal(err)
	}
	l, ok, err := db.AdvisoryLock(ctx, key)
	if err != nil || !ok {
		t.Fatalf("after release: ok %v err %v", ok, err)
	}
	if err := l.Release(ctx); err != nil {
		t.Fatal(err)
	}
	// A different key is independent.
	if l2, ok, err := db.AdvisoryLock(ctx, pg.LockKey("job:other")); err != nil || !ok {
		t.Fatalf("other key: ok %v err %v", ok, err)
	} else if err := l2.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

// D7: a process refuses a schema older than its build, and says which
// version it found and which it needs; at the newest version it opens.
func TestIntegrationOpenRefusesAnOlderSchema(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	sqlDB := storetest.Open(t, u)
	ctx := context.Background()
	latest, err := migrate.Latest(migrate.Relational)
	if err != nil {
		t.Fatal(err)
	}
	open(t, u, "") // at the newest version it opens

	if err := migrate.DownTo(ctx, sqlDB, migrate.Relational, latest-1); err != nil {
		t.Fatal(err)
	}
	_, err = pg.Open(ctx, store.PoolOptions{URL: u})
	if err == nil || !strings.Contains(err.Error(), "needs") {
		t.Fatalf("older schema opened: %v", err)
	}
	if !strings.Contains(err.Error(), "uspace-authority migrate") {
		t.Fatalf("the refusal does not say what to do: %v", err)
	}
}
