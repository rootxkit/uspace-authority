package registry

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// itest is the registry on the real databases: PostgreSQL as
// authority_app, the projection written as authority_ts_projector and
// read as authority_ts_reader, scratch databases migrated from scratch.
type itest struct {
	*fixture
	db      *pg.DB
	writer  *audit.Writer
	pgAdmin *sql.DB
	tsAdmin *sql.DB
	tsURL   string
	reader  *ProjectionReader
}

func newIntegration(t *testing.T) *itest {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	proj, err := ts.OpenProjector(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proj.Close)
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test-reader"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	f := newFixture(t)
	w := audit.NewWriter(db)
	f.svc.Store = PG{DB: db, Audit: w}
	f.svc.Projection = TSProjection{P: proj}
	f.svc.Now = nil // the databases' clocks and ours agree on real time
	return &itest{
		fixture: f, db: db, writer: w, pgAdmin: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL), tsURL: tsURL,
		reader: &ProjectionReader{Source: TSSource{R: rd}, Counters: &core.Counters{}},
	}
}

func (it *itest) count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (it *itest) projectedStatus(t *testing.T, uasID string) (status string, inRegistry bool) {
	t.Helper()
	err := it.tsAdmin.QueryRowContext(context.Background(),
		`SELECT registration_status, in_registry FROM proj_registry_uas WHERE uas_id = $1`, uasID).Scan(&status, &inRegistry)
	if err != nil {
		t.Fatalf("projected row of %s: %v", uasID, err)
	}
	return status, inRegistry
}

// A-M1 (brief "Done when"): an operator with every Art. 14(2) field, a
// pilot and two UAS registered, one suspended, looked up by number and
// serial; validate answers status only; every change is audited and the
// chain verifies; nothing personal is stored or logged in clear.
func TestIntegrationRegistryAM1(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	full := naturalOperator(numberA)
	full.SecretPart = "x9z"
	full.Source = SourcePortal
	op := it.operator(t, full)
	legal := it.operator(t, legalOperator(numberB))
	p, err := it.svc.CreatePilot(ctx, NewPilot{PersonRef: "01001012345", Name: "Test Pilot", OperatorID: op.ID}, registrar)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A1_A3", CertificateRef: "TEST-A1A3", ValidUntil: time.Now().AddDate(5, 0, 0)}, registrar); err != nil {
		t.Fatal(err)
	}
	it.uas(t, op.ID, serialC1, "C1")
	u2 := it.uas(t, legal.ID, serialLegacy, "C0")
	if _, err := it.svc.SetUASStatus(ctx, u2.ID, StatusSuspended, "airworthiness", registrar); err != nil {
		t.Fatal(err)
	}

	// Looked up by number (public part, case ignored) and by serial.
	ops, err := it.svc.ListOperators(ctx, "geotest00000001-x9z", "", Page{})
	if err != nil || len(ops) != 1 || ops[0].ID != op.ID || !ops[0].HasSecretPart {
		t.Fatalf("by number: %+v %v", ops, err)
	}
	byFold, err := it.svc.ListUAS(ctx, "test-LEGACY-1", "", "", Page{})
	if err != nil || len(byFold) != 1 || byFold[0].Status != StatusSuspended {
		t.Fatalf("by serial: %+v %v", byFold, err)
	}
	got, err := it.svc.GetPilot(ctx, p.ID)
	if err != nil || len(got.Competencies) != 1 {
		t.Fatalf("pilot %+v %v", got, err)
	}

	// F8: status only, for each entity.
	ans, err := it.svc.Validate(ctx, []Query{
		{Operator: numberA, Serial: serialC1, Pilot: p.ID}, {Serial: serialLegacy}, {Operator: "GEONOBODY000001"},
	}, PurposeAuthorisation, ussp)
	if err != nil {
		t.Fatal(err)
	}
	if ans[0].Operator.Status != ValidityValid || ans[0].UAS.Status != ValidityValid || ans[0].Pilot.Status != ValidityValid ||
		ans[1].UAS.Status != ValiditySuspended || ans[2].Operator.Status != ValidityUnknown {
		t.Fatalf("answers %+v %+v %+v", ans[0], ans[1], ans[2])
	}

	// The personal data is sealed in the database, the secret part and
	// the national id are hashes, and no events payload carries them.
	var stored bytes.Buffer
	rows, err := it.pgAdmin.QueryContext(ctx, `SELECT coalesce(full_name_enc, ''::bytea), coalesce(date_of_birth_enc, ''::bytea),
		postal_address_enc, contact_email_enc, contact_phone_enc, coalesce(secret_part_hash, '') FROM uas_operators`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a, b, c, d, e []byte
		var h string
		if err := rows.Scan(&a, &b, &c, &d, &e, &h); err != nil {
			t.Fatal(err)
		}
		for _, x := range [][]byte{a, b, c, d, e, []byte(h)} {
			stored.Write(x)
		}
	}
	_ = rows.Close()
	var pilotRow []byte
	var ref string
	if err := it.pgAdmin.QueryRowContext(ctx, `SELECT name_enc, person_ref_hash FROM remote_pilots`).Scan(&pilotRow, &ref); err != nil {
		t.Fatal(err)
	}
	stored.Write(pilotRow)
	stored.WriteString(ref)
	var payloads string
	if err := it.pgAdmin.QueryRowContext(ctx, `SELECT string_agg(payload::text || coalesce(purpose, ''), ' ') FROM events`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Test Person", "1980-01-02", "Test Street", "operator@example.test", "x9z", "Test Pilot", "01001012345", "Test Aerial"} {
		if bytes.Contains(stored.Bytes(), []byte(secret)) || strings.Contains(payloads, secret) {
			t.Errorf("%q stored or logged in clear", secret)
		}
	}

	// Every change is an events row; the month's chain verifies.
	for typ, want := range map[string]int{
		audit.EventOperatorRegistered: 2, audit.EventUASRegistered: 2, audit.EventPilotRegistered: 1,
		audit.EventPilotCompetencyRecorded: 1, audit.EventRegistryStatusChanged: 1, audit.EventRegistryValidated: 1,
	} {
		if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = $1`, typ); n != want {
			t.Errorf("%s: %d events, want %d", typ, n, want)
		}
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = $1 AND actor_id = 'ussp-TEST-01' AND purpose = 'authorisation'`, audit.EventRegistryValidated); n != 1 {
		t.Errorf("the lookup is not recorded with the client and purpose")
	}
	res, err := it.writer.Verify(ctx, time.Now())
	if err != nil || res.Broken != nil || res.Rows < 8 {
		t.Fatalf("chain %+v %v", res, err)
	}
	// Five registrations and one suspension in the change feed.
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_status_changes`); n != 6 {
		t.Errorf("change feed %d entries", n)
	}
	if _, err := it.svc.OperatorPersonalData(ctx, op.ID, "A-M1 demonstration", registrar); err != nil {
		t.Fatal(err)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = $1 AND purpose = 'A-M1 demonstration'`, audit.EventRegistryPIIViewed); n != 1 {
		t.Error("the personal-data read is not recorded with its purpose")
	}
}

// The roles of the projection tables: tsdb-writer cannot write them, the
// readers only read, api's projector inserts and updates but never
// deletes (presence beside absence).
func TestIntegrationProjectionGrants(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	it.operator(t, naturalOperator(numberA))
	as := func(role, query string) error {
		conn, err := it.tsAdmin.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "SET ROLE "+role); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = conn.ExecContext(ctx, "RESET ROLE") }()
		_, err = conn.ExecContext(ctx, query)
		return err
	}
	insert := `INSERT INTO proj_registry_uas (uas_id, serial, serial_fold, registration_status, in_registry, projected_at, registry_version)
		VALUES ('probe', 'TEST-P', 'TEST-P', 'active', true, now(), 1)`
	for _, c := range []struct {
		role, query string
		allowed     bool
	}{
		{ts.WriterRole, insert, false},
		{ts.ReaderRole, insert, false},
		{ts.ReaderRole, `SELECT * FROM proj_registry_uas`, true},
		{ts.ProjectorRole, insert, true},
		{ts.ProjectorRole, `UPDATE proj_registry_uas SET in_registry = false WHERE uas_id = 'probe'`, true},
		{ts.ProjectorRole, `DELETE FROM proj_registry_uas`, false},
		{ts.ProjectorRole, `DELETE FROM proj_registry_operators`, false},
	} {
		err := as(c.role, c.query)
		if c.allowed != (err == nil) {
			t.Errorf("%s: %.40s: %v", c.role, c.query, err)
		}
		if !c.allowed && store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Errorf("%s refused for another reason: %v", c.role, err)
		}
	}
}

// SC-17 step 3 on the real databases: a constraint makes the projection
// write fail; the suspension is rolled back whole and the API says why;
// with the constraint gone the same change is applied.
func TestIntegrationAFailedProjectionWriteRollsBack(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op := it.operator(t, naturalOperator(numberA))
	u := it.uas(t, op.ID, serialC1, "C1")
	events := it.count(t, it.pgAdmin, `SELECT count(*) FROM events`)
	changes := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_status_changes`)
	if _, err := it.tsAdmin.ExecContext(ctx, `ALTER TABLE proj_registry_uas ADD CONSTRAINT sc17_no_suspension CHECK (registration_status <> 'suspended')`); err != nil {
		t.Fatal(err)
	}
	_, err := it.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar)
	wantProblem(t, err, http.StatusServiceUnavailable, "")
	if d := problemOf(err).Detail; !strings.Contains(d, "SQLSTATE 23514") || !strings.Contains(d, "sc17_no_suspension") {
		t.Fatalf("reason not named: %q", d)
	}
	var st string
	if err := it.pgAdmin.QueryRowContext(ctx, `SELECT status FROM uas WHERE id = $1`, u.ID).Scan(&st); err != nil || st != "active" {
		t.Fatalf("relational status %q %v", st, err)
	}
	if it.count(t, it.pgAdmin, `SELECT count(*) FROM events`) != events ||
		it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_status_changes`) != changes {
		t.Fatal("the rolled-back change left an event or a feed entry")
	}
	if s, _ := it.projectedStatus(t, u.ID); s != "active" {
		t.Fatalf("projected %q", s)
	}
	if _, err := it.tsAdmin.ExecContext(ctx, `ALTER TABLE proj_registry_uas DROP CONSTRAINT sc17_no_suspension`); err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar); err != nil {
		t.Fatal(err)
	}
	if s, _ := it.projectedStatus(t, u.ID); s != "suspended" {
		t.Fatalf("projected %q after the retry", s)
	}
}

// SC-17 step 4: a row deleted by hand is restored; a row the registry
// does not hold is kept and marked, never deleted; a projection left
// ahead by a lost commit is overwritten.
func TestIntegrationReprojectionRepairs(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op := it.operator(t, naturalOperator(numberA))
	u := it.uas(t, op.ID, serialC1, "C1")
	for _, q := range []string{
		`DELETE FROM proj_registry_uas WHERE uas_id = '` + u.ID + `'`,
		`INSERT INTO proj_registry_uas (uas_id, serial, serial_fold, registration_status, in_registry, projected_at, registry_version)
		 VALUES ('orphan', 'TEST-ORPHAN', 'TEST-ORPHAN', 'active', true, now(), 999999)`,
		`INSERT INTO proj_registry_operators VALUES ('ghost', 'GEOGHOST0000001', 'active', now(), 1)`,
		`UPDATE proj_registry_operators SET status = 'suspended', registry_version = 999999 WHERE operator_id = '` + op.ID + `'`,
	} {
		if _, err := it.tsAdmin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	r, err := it.svc.Reproject(ctx)
	if err != nil || !r.Ran || r.Marked != 2 {
		t.Fatalf("reprojected %+v %v", r, err)
	}
	if s, in := it.projectedStatus(t, u.ID); s != "active" || !in {
		t.Fatalf("restored row %q %v", s, in)
	}
	if _, in := it.projectedStatus(t, "orphan"); in {
		t.Fatal("orphan still in the registry")
	}
	var ghost, owner string
	_ = it.tsAdmin.QueryRowContext(ctx, `SELECT status FROM proj_registry_operators WHERE operator_id = 'ghost'`).Scan(&ghost)
	_ = it.tsAdmin.QueryRowContext(ctx, `SELECT status FROM proj_registry_operators WHERE operator_id = $1`, op.ID).Scan(&owner)
	if ghost != StatusUnregistered || owner != "active" {
		t.Fatalf("ghost %q owner %q", ghost, owner)
	}
	if err := it.reader.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if id := resolve(t, it.reader, "TEST-ORPHAN", ""); id.Reason != core.ReasonNotInRegistry {
		t.Fatalf("orphan %+v", id)
	}
	if id := resolve(t, it.reader, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("restored %+v", id)
	}
}

// heldProjection pauses a repair's write until released, so a change
// can be started while a re-projection holds LockProjection.
type heldProjection struct {
	Projection
	reached, release chan struct{}
}

type heldTx struct {
	ProjectionTx
	p *heldProjection
}

func (h *heldProjection) Begin(ctx context.Context) (ProjectionTx, error) {
	tx, err := h.Projection.Begin(ctx)
	return heldTx{ProjectionTx: tx, p: h}, err
}

func (t heldTx) UpsertUAS(ctx context.Context, rows []ProjectedUAS, at time.Time, repair bool) error {
	if repair {
		close(t.p.reached)
		<-t.p.release
	}
	return t.ProjectionTx.UpsertUAS(ctx, rows, at, repair)
}

// SC-17 step 5: a change made while a re-projection runs waits for its
// lock and is not overwritten by the re-projection's older read.
func TestIntegrationAChangeWaitsForARunningReprojection(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op := it.operator(t, naturalOperator(numberA))
	u := it.uas(t, op.ID, serialC1, "C1")
	held := &heldProjection{Projection: it.svc.Projection, reached: make(chan struct{}), release: make(chan struct{})}
	it.svc.Projection = held

	var wg sync.WaitGroup
	var reprojectErr, changeErr error
	wg.Go(func() { _, reprojectErr = it.svc.Reproject(ctx) })
	<-held.reached // the re-projection has read "active" and holds the lock
	changed := make(chan struct{})
	wg.Go(func() {
		defer close(changed)
		_, changeErr = it.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar)
	})
	select {
	case <-changed:
		t.Fatal("the change did not wait for the re-projection's lock")
	case <-time.After(500 * time.Millisecond):
	}
	close(held.release)
	wg.Wait()
	if reprojectErr != nil || changeErr != nil {
		t.Fatalf("reproject %v, change %v", reprojectErr, changeErr)
	}
	if s, _ := it.projectedStatus(t, u.ID); s != "suspended" {
		t.Fatalf("the re-projection overwrote the change: %q", s)
	}
}

// SC-17 step 6, E-02: the projection unreadable for one refresh (the
// reader's grant revoked, then its connections dropped): the reader
// keeps its snapshot and no aircraft turns unknown; once readable again
// the next refresh applies.
func TestIntegrationReaderKeepsItsSnapshot(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op := it.operator(t, naturalOperator(numberA))
	it.uas(t, op.ID, serialC1, "C1")
	if err := it.reader.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := it.tsAdmin.ExecContext(ctx, `REVOKE SELECT ON proj_registry_uas FROM authority_ts_reader`); err != nil {
		t.Fatal(err)
	}
	if err := it.reader.Refresh(ctx); err == nil {
		t.Fatal("an unreadable projection read")
	}
	if id := resolve(t, it.reader, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("the snapshot was dropped: %+v", id)
	}
	if _, err := it.tsAdmin.ExecContext(ctx, `GRANT SELECT ON proj_registry_uas TO authority_ts_reader`); err != nil {
		t.Fatal(err)
	}
	if _, err := it.tsAdmin.ExecContext(ctx,
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'uspace-authority-test-reader'`); err != nil {
		t.Fatal(err)
	}
	_ = it.reader.Refresh(ctx) // a dropped connection may fail one read ...
	if id := resolve(t, it.reader, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("the snapshot was dropped with the connection: %+v", id)
	}
	if err := it.reader.Refresh(ctx); err != nil { // ... and the pool reconnects
		t.Fatal(err)
	}
	if it.reader.Counters.Get(CounterReaderReadFailed) < 1 {
		t.Error("the failed read was not counted")
	}
}

// The change feed and the batch bound on PostgreSQL.
func TestIntegrationChangeFeedAndBatch(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op := it.operator(t, naturalOperator(numberA))
	u := it.uas(t, op.ID, serialC1, "C1")
	for _, st := range []Status{StatusSuspended, StatusActive, StatusRevoked} {
		if _, err := it.svc.SetUASStatus(ctx, u.ID, st, "r", registrar); err != nil {
			t.Fatal(err)
		}
	}
	var all []Change
	since := int64(0)
	for range 10 {
		page, next, err := it.svc.Changes(ctx, since, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		since = next
	}
	if len(all) != 5 || all[4].Status != StatusRevoked || all[4].PublicKey != serialC1 || all[0].EntityType != EntityOperator {
		t.Fatalf("feed %+v", all)
	}
	qs := make([]Query, MaxBatch)
	for i := range qs {
		qs[i] = Query{Serial: serialC1}
	}
	ans, err := it.svc.Validate(ctx, qs, PurposeIdentification, ussp)
	if err != nil || len(ans) != MaxBatch || ans[99].UAS.Status != ValidityRevoked {
		t.Fatalf("batch %d %v", len(ans), err)
	}
	over := make([]Query, 0, MaxBatch+1)
	over = append(over, qs...)
	_, err = it.svc.Validate(ctx, append(over, Query{Serial: "x"}), PurposeIdentification, ussp)
	wantProblem(t, err, http.StatusBadRequest, "items")
}

// SC-17 steps 1-6 as one timed scenario on the real databases: a change
// is seen by a reader refreshing every DefaultRefresh (5 s) within the
// refresh plus the transaction time; a failed projection write leaves
// nothing half applied; a deleted row comes back with the re-projection;
// an unreadable projection keeps the readers' snapshot.
func TestIntegrationSC17RegistryChangeReachesAReaderWithinTheRefresh(t *testing.T) {
	it := newIntegration(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	op := it.operator(t, naturalOperator(numberA))
	u := it.uas(t, op.ID, serialC1, "C1")
	done := make(chan struct{})
	go func() { defer close(done); it.reader.Run(ctx, DefaultRefresh) }()
	defer func() { cancel(); <-done }()

	// 1. Broadcasting and registered.
	waitUntil(t, 2*DefaultRefresh, func() bool { return resolve(t, it.reader, serialC1, numberA).Status == core.IdentRegistered })

	// 2. Suspended through the registry: every reader says so within the
	// refresh plus the transaction time (no push until the bus lands).
	start := time.Now()
	if _, err := it.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "SC-17", registrar); err != nil {
		t.Fatal(err)
	}
	txTime := time.Since(start)
	waitUntil(t, DefaultRefresh+txTime+250*time.Millisecond, func() bool {
		return resolve(t, it.reader, serialC1, numberA).Status == core.IdentSuspended
	})
	t.Logf("step 2: suspended seen %.2f s after the request (transaction %.3f s, refresh %s)",
		time.Since(start).Seconds(), txTime.Seconds(), DefaultRefresh)

	// 3. A failing projection write: rolled back, the failure reported.
	if _, err := it.tsAdmin.ExecContext(ctx, `ALTER TABLE proj_registry_uas ADD CONSTRAINT sc17 CHECK (registration_status <> 'active')`); err != nil {
		t.Fatal(err)
	}
	_, err := it.svc.SetUASStatus(ctx, u.ID, StatusActive, "", registrar)
	wantProblem(t, err, http.StatusServiceUnavailable, "")
	if g, _ := it.svc.GetUAS(ctx, u.ID); g.Status != StatusSuspended {
		t.Fatalf("half applied: %s", g.Status)
	}
	if _, err := it.tsAdmin.ExecContext(ctx, `ALTER TABLE proj_registry_uas DROP CONSTRAINT sc17`); err != nil {
		t.Fatal(err)
	}

	// 4. A projection row deleted by hand is restored by the re-projection.
	if _, err := it.tsAdmin.ExecContext(ctx, `DELETE FROM proj_registry_uas WHERE uas_id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.Reproject(ctx); err != nil {
		t.Fatal(err)
	}
	if s, in := it.projectedStatus(t, u.ID); s != "suspended" || !in {
		t.Fatalf("restored %q %v", s, in)
	}

	// 5. is TestIntegrationAChangeWaitsForARunningReprojection.

	// 6. The projection unreadable for a refresh: the snapshot holds.
	if _, err := it.tsAdmin.ExecContext(ctx, `REVOKE SELECT ON proj_registry_uas FROM authority_ts_reader`); err != nil {
		t.Fatal(err)
	}
	failed := it.reader.Counters.Get(CounterReaderReadFailed)
	waitUntil(t, 2*DefaultRefresh, func() bool { return it.reader.Counters.Get(CounterReaderReadFailed) > failed })
	if id := resolve(t, it.reader, serialC1, numberA); id.Status != core.IdentSuspended {
		t.Fatalf("an unreadable projection turned the aircraft %+v", id)
	}
	if _, err := it.tsAdmin.ExecContext(ctx, `GRANT SELECT ON proj_registry_uas TO authority_ts_reader`); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not reached within %s", within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
