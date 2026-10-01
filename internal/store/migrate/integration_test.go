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
			v, err := Up(ctx, db, c.tree, nil)
			if err != nil {
				t.Fatal(err)
			}
			if v < 1 || !extensionInstalled(t, db, c.extension) {
				t.Fatalf("after up: version %d, %s installed %v", v, c.extension, extensionInstalled(t, db, c.extension))
			}
			if !tableExists(t, db, c.tree.VersionTable) {
				t.Fatalf("version table %s missing", c.tree.VersionTable)
			}
			if tableExists(t, db, c.other.VersionTable) {
				t.Fatalf("%s database holds the other tree's version table %s", c.tree.Name, c.other.VersionTable)
			}
			if err := DownTo(ctx, db, c.tree, 0); err != nil {
				t.Fatal(err)
			}
			got, err := Version(ctx, db, c.tree)
			if err != nil || got != 0 || extensionInstalled(t, db, c.extension) {
				t.Fatalf("after down: version %d err %v, %s still installed %v", got, err, c.extension, extensionInstalled(t, db, c.extension))
			}
			// Up again after a rollback reaches the same version.
			if v2, err := Up(ctx, db, c.tree, nil); err != nil || v2 != v {
				t.Fatalf("re-up: %d %v", v2, err)
			}
		})
	}
}
