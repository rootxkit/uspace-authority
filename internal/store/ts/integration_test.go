package ts_test

import (
	"context"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// The hot-path role reads and never writes; the writer role writes. A
// table a later migration creates gets both grants by default privilege,
// so the test creates one as the migrating user, as a migration would.
func TestIntegrationReaderRoleCannotInsertAndWriterRoleCan(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	admin := storetest.Open(t, u)
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, `CREATE TABLE wp1_probe (id bigint, captured_at timestamptz)`); err != nil {
		t.Fatal(err)
	}

	r, err := ts.OpenReader(ctx, store.PoolOptions{URL: u, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	w, err := ts.OpenWriterPool(ctx, store.PoolOptions{URL: u, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)

	// E-01: the writer's INSERT succeeds ...
	if n, err := w.Exec(ctx, `INSERT INTO wp1_probe VALUES (1, now())`); err != nil || n != 1 {
		t.Fatalf("writer INSERT: %d %v", n, err)
	}
	// ... the reader's same INSERT is refused by privilege ...
	_, err = r.Exec(ctx, `INSERT INTO wp1_probe VALUES (2, now())`)
	if store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("reader INSERT: %v", err)
	}
	// ... and the reader still reads what the writer wrote.
	if n, err := r.Exec(ctx, `SELECT * FROM wp1_probe`); err != nil || n != 1 {
		t.Fatalf("reader SELECT: %d %v", n, err)
	}
	// Neither may change or remove a row (T7: no UPDATE on hypertables).
	for _, sql := range []string{`UPDATE wp1_probe SET id = 3`, `DELETE FROM wp1_probe`} {
		if _, err := w.Exec(ctx, sql); store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Errorf("writer %s: %v", sql, err)
		}
	}
	// The version check reads through both query sets.
	if v, err := r.Q.SchemaVersion(ctx); err != nil || v < 2 {
		t.Fatalf("reader schema version %d %v", v, err)
	}
	if v, err := w.Q.SchemaVersion(ctx); err != nil || v < 2 {
		t.Fatalf("writer schema version %d %v", v, err)
	}
}

func TestIntegrationOpenReaderRefusesAnOlderSchema(t *testing.T) {
	u := storetest.Scratch(t, migrate.Timeseries)
	admin := storetest.Open(t, u)
	ctx := context.Background()
	// Version 1 only: the roles migration has not run.
	if _, err := migrate.Up(ctx, admin, migrate.Timeseries, nil); err != nil {
		t.Fatal(err)
	}
	if err := migrate.DownTo(ctx, admin, migrate.Timeseries, 1); err != nil {
		t.Fatal(err)
	}
	// As the login role, so the refusal is the version check and not a
	// missing grant.
	_, err := ts.OpenReader(ctx, store.PoolOptions{URL: u, Role: "postgres"})
	if err == nil || !strings.Contains(err.Error(), "timeseries schema is at version 1") {
		t.Fatalf("got %v", err)
	}
	if _, err := migrate.Up(ctx, admin, migrate.Timeseries, nil); err != nil {
		t.Fatal(err)
	}
	r, err := ts.OpenReader(ctx, store.PoolOptions{URL: u})
	if err != nil {
		t.Fatalf("at the newest version: %v", err)
	}
	r.Close()
}
