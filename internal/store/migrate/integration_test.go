package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

// The integration tests run only with INTEGRATION=1 against the service
// containers: PG_URL (PostGIS) and TS_URL (TimescaleDB). Otherwise they
// are skipped, and say why. Each test works in a scratch database
// created from template0 and dropped afterwards, because the PostGIS
// image preinstalls extensions into its default database that a
// rollback of this tree must not touch.
func integrationDB(t *testing.T, variable string) *sql.DB {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs the service containers (make up)")
	}
	raw := os.Getenv(variable)
	if raw == "" {
		t.Fatalf("INTEGRATION=1 but %s is unset", variable)
	}
	admin, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("wp0_scratch_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name + " TEMPLATE template0"); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)") })
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func extensionInstalled(t *testing.T, db *sql.DB, ext string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pg_extension WHERE extname = $1`, ext).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// jobsIdle waits until every policy job of db has had the run
// TimescaleDB gives a new job at its scheduler's first pass, and none is
// running. A Down to 0 drops the extension; dropped under a running
// policy job, the job's worker outlived its scheduler and the DROP
// DATABASE of the cleanup, and then crashed the server with a
// segmentation fault (CI, "Retention Policy [1002]"), failing every test
// after it. The next scheduled runs are 15 minutes away or more.
func jobsIdle(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var busy int
		if err := db.QueryRow(`SELECT count(*) FROM timescaledb_information.job_stats
			WHERE job_id >= 1000 AND (coalesce(total_runs, 0) = 0 OR coalesce(job_status, '') = 'Running' OR last_run_status IS NULL)`).Scan(&busy); err != nil {
			t.Fatal(err)
		}
		if busy == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d policy jobs not past their first run", busy)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestIntegrationEachTreeAppliesAndRollsBack(t *testing.T) {
	cases := []struct {
		tree      Tree
		variable  string
		extension string
		other     Tree
	}{
		{Relational, "PG_URL", "postgis", Timeseries},
		{Timeseries, "TS_URL", "timescaledb", Relational},
	}
	ctx := context.Background()
	for _, c := range cases {
		t.Run(c.tree.Name, func(t *testing.T) {
			db := integrationDB(t, c.variable)
			latest, err := Latest(c.tree)
			if err != nil {
				t.Fatal(err)
			}
			// WP-1: up and down twice, so a Down that leaves something
			// behind (a function, a grant, a default privilege) fails the
			// second Up.
			for round := 1; round <= 2; round++ {
				v, err := Up(ctx, db, c.tree, nil)
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
				if v != latest || !extensionInstalled(t, db, c.extension) {
					t.Fatalf("round %d after up: version %d (latest %d), %s installed %v", round, v, latest, c.extension, extensionInstalled(t, db, c.extension))
				}
				if !tableExists(t, db, c.tree.VersionTable) {
					t.Fatalf("version table %s missing", c.tree.VersionTable)
				}
				if tableExists(t, db, c.other.VersionTable) {
					t.Fatalf("%s database holds the other tree's version table %s", c.tree.Name, c.other.VersionTable)
				}
				st, err := Status(ctx, db, c.tree)
				if err != nil || int64(len(st)) != latest {
					t.Fatalf("round %d status: %v %v", round, st, err)
				}
				for _, m := range st {
					if !m.Applied || m.AppliedAt.IsZero() {
						t.Fatalf("round %d: migration %d not applied: %+v", round, m.Version, m)
					}
				}
				if c.tree.Name == Timeseries.Name {
					jobsIdle(t, db)
				}
				if err := DownTo(ctx, db, c.tree, 0); err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
				got, err := Version(ctx, db, c.tree)
				if err != nil || got != 0 || extensionInstalled(t, db, c.extension) {
					t.Fatalf("round %d after down: version %d err %v, %s still installed %v", round, got, err, c.extension, extensionInstalled(t, db, c.extension))
				}
				st, err = Status(ctx, db, c.tree)
				if err != nil || st[0].Applied {
					t.Fatalf("round %d status after down: %+v %v", round, st, err)
				}
			}
		})
	}
}
