// Package storetest gives integration tests a scratch database of
// either tree: created from template0 on the service container named by
// PG_URL or TS_URL, migrated to the newest version, and dropped when the
// test ends. It runs only with INTEGRATION=1 and otherwise skips, saying
// why. It is imported by _test.go files only; no binary links it (the
// layout test checks the same for internal/ltest).
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store/migrate"
)

// Variable is the environment variable holding the admin URL of the
// service container of tree.
func Variable(tree migrate.Tree) string {
	if tree.Name == migrate.Timeseries.Name {
		return "TS_URL"
	}
	return "PG_URL"
}

// AdminURL is the service container's URL for tree, or a skip when
// INTEGRATION=1 is not set.
func AdminURL(t testing.TB, tree migrate.Tree) string {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs the service containers (make up)")
	}
	raw := os.Getenv(Variable(tree))
	if raw == "" {
		t.Fatalf("INTEGRATION=1 but %s is unset", Variable(tree))
	}
	return raw
}

var seq atomic.Int64

// Scratch creates an empty scratch database beside tree's and returns
// its URL; it is dropped when the test ends.
func Scratch(t testing.TB, tree migrate.Tree) string {
	t.Helper()
	raw := AdminURL(t, tree)
	admin, err := migrate.Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("wp_scratch_%d_%d_%d", os.Getpid(), time.Now().UnixNano(), seq.Add(1))
	if _, err := admin.Exec("CREATE DATABASE " + name + " TEMPLATE template0"); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)") })
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// Migrated is Scratch with tree applied to its newest version.
func Migrated(t testing.TB, tree migrate.Tree) string {
	t.Helper()
	u := Scratch(t, tree)
	db := Open(t, u)
	if _, err := migrate.Up(context.Background(), db, tree, nil); err != nil {
		t.Fatal(err)
	}
	return u
}

// Open is a database/sql handle on u as the login role, closed when the
// test ends: the superuser of the service container, which tests use to
// set up, to tamper, and to SET ROLE.
func Open(t testing.TB, u string) *sql.DB {
	t.Helper()
	db, err := migrate.Open(u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// PauseRetention unschedules the retention policy of hypertable and
// waits until no run of it is in progress, returning its job id. A
// policy's first run is due as soon as it exists, and TimescaleDB starts
// a scheduler for a scratch database a few hundred milliseconds after
// the extension is created: a test that writes backdated rows and then
// checks for them races that run, which drops their chunks. The test
// runs the job itself (CALL run_job) when it wants the disposal.
func PauseRetention(t testing.TB, db *sql.DB, hypertable string) int {
	t.Helper()
	var job int
	if err := db.QueryRow(`SELECT job_id FROM timescaledb_information.jobs
		WHERE hypertable_name = $1 AND proc_name = 'policy_retention'`, hypertable).Scan(&job); err != nil {
		t.Fatalf("retention policy of %s: %v", hypertable, err)
	}
	if _, err := db.Exec(`SELECT alter_job($1, scheduled => false)`, job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var status string
		if err := db.QueryRow(`SELECT job_status FROM timescaledb_information.job_stats WHERE job_id = $1`, job).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "Running" {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("retention job %d of %s still running after 30 s", job, hypertable)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
