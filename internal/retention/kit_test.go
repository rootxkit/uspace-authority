package retention

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// fixture is both databases migrated from scratch, api's pools as its
// roles (authority_app, authority_ts_archiver), superuser handles to set
// up and inspect, a local archive directory and the Service on them with
// the spec's default periods.
type fixture struct {
	pgAdmin, tsAdmin *sql.DB
	db               *pg.DB
	w                *audit.Writer
	arch             *ts.Archiver
	dir              archive.Dir
	svc              *Service
	holds            *Holds
	counters         *core.Counters
	seq              atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	f := &fixture{pgAdmin: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL), dir: archive.Dir{Root: t.TempDir()},
		counters: &core.Counters{}}
	pauseJobs(t, f.tsAdmin)
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	arch, err := ts.OpenArchiver(ctx, store.PoolOptions{URL: tsURL, MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(arch.Close)
	arch.ExportTimeout = time.Minute
	f.db, f.arch, f.w = db, arch, audit.NewWriter(db)
	f.svc = f.service(f.dir)
	f.holds = &Holds{DB: db, Audit: f.w, Counters: f.counters}
	return f
}

// service is a Service on the fixture's databases with st as its store:
// a second one is api after a restart (nothing shared but the databases
// and the archive).
func (f *fixture) service(st archive.Store) *Service {
	s := &Service{DB: f.db, Audit: f.w, TS: f.arch,
		Periods:   Periods{OnlineDays: 90, ArchiveYears: 2, ViolationsYears: 5, AuditYears: 10, Incidents: "indefinite"},
		BatchRows: 1000, MaxBatches: 100, ChunksPerRun: 100, IncidentMargin: 24 * time.Hour, MaxHolds: 1000,
		Counters: f.counters, Logger: logging.Discard()}
	if st != nil {
		s.Store = st
	}
	return s
}

// pauseJobs unschedules every TimescaleDB job of the scratch database
// (compression, the ussp_flights retention) and waits until none runs:
// a job touching the backdated chunks would race the test.
func pauseJobs(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`SELECT alter_job(job_id, scheduled => false) FROM timescaledb_information.jobs WHERE job_id >= 1000`); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "no TimescaleDB job running", 30*time.Second, func() bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM timescaledb_information.job_stats WHERE job_status = 'Running'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 0
	})
}

// waitUntil polls cond until it holds or within ends (a condition, not
// a fixed sleep).
func waitUntil(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *fixture) next() int64 { return f.seq.Add(1) }

func (f *fixture) count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// dayAgo is noon UTC of the day days before today: its rows land in one
// one-day chunk.
func dayAgo(days int) time.Time {
	d := time.Now().UTC().AddDate(0, 0, -days)
	return time.Date(d.Year(), d.Month(), d.Day(), 12, 0, 0, 0, time.UTC)
}

func (f *fixture) track(t *testing.T, at time.Time, trackID, serial string) {
	t.Helper()
	n := f.next()
	var s any
	if serial != "" {
		s = serial
	}
	_, err := f.tsAdmin.Exec(`INSERT INTO tracks (captured_at, track_id, dedupe_key, msg_id, rx_ts, time_source, backlog, source,
		source_instance, trust, lat_deg, lon_deg, alt_source, emergency, ident_status, ident_reason, ident_mismatch, ident_basis, serial)
		VALUES ($1, $2, $3, $4, $1, 'receiver', false, 'direct_rid', 'rx-1', 'broadcast', 41.7, 44.8, 'none', false,
		'unidentified', 'test', false, 'as_broadcast', $5)`,
		at.Add(time.Duration(n)*time.Millisecond), trackID, fmt.Sprintf("direct_rid:test-%d", n), bus.NewULID(at), s)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) frame(t *testing.T, at time.Time, transmitter, serial string, payload []byte) {
	t.Helper()
	n := f.next()
	key := sha256.Sum256(fmt.Appendf(nil, "frame-%d", n))
	ph := sha256.Sum256(payload)
	mt, err := odid.TypeOf(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.tsAdmin.Exec(`INSERT INTO rid_observations (ingest_ts, frame_id, receiver_id, transmitter, payload, payload_sha256,
		msg_type, backlog, sent_at_ms, nonce, serial, id_type)
		VALUES ($1, $2, 'rx-1', $3, $4, $5, $6, false, 0, 'n', $7, 1)`,
		at.Add(time.Duration(n)*time.Millisecond), hex.EncodeToString(key[:16]), transmitter, payload, ph[:], int(mt), serial)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) manned(t *testing.T, at time.Time, icao string) {
	t.Helper()
	n := f.next()
	_, err := f.tsAdmin.Exec(`INSERT INTO manned_tracks (source_captured_at, captured_at, dedupe_key, msg_id, rx_ts, time_source,
		backlog, icao24, lat_deg, lon_deg, source_class, trust, source, source_instance, state)
		VALUES ($1, $1, $2, $3, $1, 'provider', false, $4, 41.7, 44.8, 'adsb', 'surveillance', 'ansp_feed', 'ansp-1', 'live')`,
		at.Add(time.Duration(n)*time.Millisecond), fmt.Sprintf("ansp_feed:test-%d", n), bus.NewULID(at), icao)
	if err != nil {
		t.Fatal(err)
	}
}

func f64(v float64) *float64 { return &v }

// systemFrame is an ODID System message carrying a remote pilot
// position, from core's encoder.
func systemFrame(t *testing.T) []byte {
	t.Helper()
	b, err := odid.Encode(odid.System{OperatorLocationType: 1, OperatorLatDeg: f64(41.7151), OperatorLonDeg: f64(44.8271),
		OperatorAltHAEM: f64(512), TimestampS: 42})
	if err != nil {
		t.Fatal(err)
	}
	return b[:]
}

func locationFrame(t *testing.T) []byte {
	t.Helper()
	b, err := odid.Encode(odid.Location{Status: odid.StatusAirborne, LatDeg: f64(41.72), LonDeg: f64(44.83)})
	if err != nil {
		t.Fatal(err)
	}
	return b[:]
}

func (f *fixture) rows(t *testing.T, table, col string, before time.Time) int {
	t.Helper()
	return f.count(t, f.tsAdmin, fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s < $1`, table, col), before)
}

func (f *fixture) events(t *testing.T, eventType string) int {
	t.Helper()
	return f.count(t, f.pgAdmin, `SELECT count(*) FROM events WHERE event_type = $1`, eventType)
}

func (f *fixture) ledger(t *testing.T, table string) []ts.ChunkRecord {
	t.Helper()
	rows, err := f.tsAdmin.Query(`SELECT chunk_name FROM archive_chunks WHERE hypertable = $1 ORDER BY range_start`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []ts.ChunkRecord
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		rec, ok, err := f.arch.Record(context.Background(), table, name)
		if err != nil || !ok {
			t.Fatal(err, ok)
		}
		out = append(out, rec)
	}
	return out
}

// objectLines reads an archived object's rows.
func objectLines(t *testing.T, st archive.Store, key string) []map[string]any {
	t.Helper()
	r, err := st.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	zr, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("a line is not JSON: %v", err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func manifestOf(t *testing.T, st archive.Store, key string) Manifest {
	t.Helper()
	b, err := archive.Get(st, key, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// failingStore is a store whose writes fail at Commit, or whose reads
// come back altered.
type failingStore struct {
	archive.Store
	failCommit bool
	corrupt    bool
}

type failingWriter struct{ archive.Writer }

func (w failingWriter) Commit() error {
	w.Abort()
	return errors.New("test: the upload failed")
}

func (s failingStore) Create(key string) (archive.Writer, error) {
	w, err := s.Store.Create(key)
	if err != nil || !s.failCommit {
		return w, err
	}
	return failingWriter{w}, nil
}

type flipReader struct {
	io.ReadCloser
	done bool
}

func (r *flipReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 20 && !r.done {
		p[20] ^= 0xff
		r.done = true
	}
	return n, err
}

func (s failingStore) Open(key string) (io.ReadCloser, error) {
	r, err := s.Store.Open(key)
	if err != nil || !s.corrupt || !strings.HasSuffix(key, ".ndjson.gz") {
		return r, err
	}
	return &flipReader{ReadCloser: r}, nil
}

var officer = audit.Actor{Type: audit.ActorUser, ID: "officer-1", Realm: audit.RealmConsole}

func (f *fixture) hold(t *testing.T, in HoldInput) string {
	t.Helper()
	h, err := f.holds.Place(context.Background(), officer, in)
	if err != nil {
		t.Fatal(err)
	}
	return h.HoldID
}

// incident inserts an incident of status with one aircraft (as the
// superuser: the incidents package's own tests cover opening one).
func (f *fixture) incident(t *testing.T, status string, occurred time.Time, serial string, trackIDs []string) string {
	t.Helper()
	id := bus.NewULID(time.Now().Add(time.Duration(f.next()) * time.Millisecond))
	var closed any
	var assignee any
	switch status {
	case "closed":
		closed = time.Now()
	case "assigned":
		assignee = "officer-1"
	}
	if _, err := f.pgAdmin.Exec(`INSERT INTO incidents (incident_id, kind, occurred_at, opened_from, severity, status, closed_at, assignee, opened_by)
		VALUES ($1, 'other', $2, 'own_observation', 'warning', $3, $4, $5, 'officer-1')`, id, occurred, status, closed, assignee); err != nil {
		t.Fatal(err)
	}
	var s any
	if serial != "" {
		s = serial
	}
	if _, err := f.pgAdmin.Exec(`INSERT INTO incident_aircraft (incident_id, serial, track_ids, added_by) VALUES ($1, $2, $3, 'officer-1')`,
		id, s, "{"+strings.Join(trackIDs, ",")+"}"); err != nil {
		t.Fatal(err)
	}
	return id
}
