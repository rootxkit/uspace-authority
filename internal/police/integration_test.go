package police

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/authz"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// ifix is the police realm on scratch databases of both trees: the
// ledger as the application role, the picture as the reader role, the
// police account a row of users.
type ifix struct {
	t       *testing.T
	pgURL   string
	tsURL   string
	pg      *sql.DB // the login role (superuser of the container)
	tsAdmin *sql.DB
	svc     *Service
	reg     *fakeRegistry
}

func newIfix(t *testing.T) *ifix {
	t.Helper()
	f := &ifix{t: t, pgURL: storetest.Migrated(t, migrate.Relational), tsURL: storetest.Migrated(t, migrate.Timeseries)}
	f.pg, f.tsAdmin = storetest.Open(t, f.pgURL), storetest.Open(t, f.tsURL)
	f.exec(f.pg, `INSERT INTO users (id, username, roles, realm, agency, ip_allow, created_at, created_by, updated_at, updated_by)
		VALUES ($1, 'officer.one', '{police.query}', 'police', $2, '{192.0.2.0/24}', now(), 'test', now(), 'test')`, officerID, agencyA)
	f.svc = f.service(t)
	return f
}

// service is one api replica's police realm on the fixture's databases.
func (f *ifix) service(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	db, err := pgstore.Open(ctx, store.PoolOptions{URL: f.pgURL, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: f.tsURL, ApplicationName: "uspace-authority-test-police"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	k := newKit(t)
	if f.reg == nil {
		f.reg = k.reg
	}
	purposes, _ := NewPurposes([]string{"public_order", "criminal_investigation"}, []string{"criminal_investigation"})
	return &Service{Accounts: authz.PG{DB: db}, Registry: f.reg, Telemetry: rd.Q, Ledger: PG{DB: db, Audit: audit.NewWriter(db)},
		Purposes: purposes, Budget: Budget{User: 3, Agency: 100, Window: time.Hour},
		Limits: Limits{LiveWindow: 30 * time.Second, AtWindow: time.Minute, HistoryMax: 90 * 24 * time.Hour, MaxBBoxDeg: 1,
			MaxAircraft: 10, MaxPositions: 3, MaxFleet: 10, DPOMaxRows: 100, Timeout: 10 * time.Second},
		Catalogue: audit.DefaultCatalogue(), Counters: &core.Counters{}}
}

func (f *ifix) exec(db *sql.DB, q string, args ...any) {
	f.t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		f.t.Fatalf("%v\n%s", err, q)
	}
}

func (f *ifix) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pg.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// track writes n samples of a track inside the box, the newest secondsAgo
// seconds before the telemetry database's now.
func (f *ifix) track(id, serial, reg string, n int, secondsAgo float64) {
	f.t.Helper()
	for i := range n {
		f.exec(f.tsAdmin, `INSERT INTO tracks (captured_at, track_id, dedupe_key, msg_id, rx_ts, time_source, backlog, source,
			source_instance, trust, lat_deg, lon_deg, alt_amsl_m, alt_source, emergency, ident_status, ident_reason, ident_mismatch,
			ident_basis, serial, operator_reg)
			VALUES (now() - make_interval(secs => $1), $2, $3, $3, now(), 'broadcast', false, 'direct_rid', 'rx-int', 'broadcast',
			        41.70 + $4 / 1000.0, 44.80, 600, 'geodetic', false, 'registered', 'matched', false, 'as_broadcast', $5, $6)`,
			secondsAgo+float64(n-1-i), id, fmt.Sprintf("%s-%d", id, i), float64(i), serial, reg)
	}
}

// The done-when of WP-19's record: a query is exactly one police_queries
// row and one police_query events row with its purpose; a status-only
// purpose opens no personal data, a personal-data one does; the DPO
// report lists both queries and is itself an events row.
func TestIntegrationAQueryIsOneRowAndOneEvent(t *testing.T) {
	f := newIfix(t)
	f.track("TRACK-INT-1", "TESTA0123456789", "GEOTEST00000001", 5, 1)
	f.track("TRACK-INT-OLD", "TESTB0123456789", "GEOTEST00000001", 1, 600) // outside the live window
	ctx := as(officerID, insideIP)
	out, err := f.svc.QueryAircraft(ctx, AircraftQuery{BBox: box, Purpose: "public_order", CaseRef: "CASE-INT-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Aircraft) != 1 || out.Aircraft[0].TrackId != "TRACK-INT-1" || len(out.Aircraft[0].Positions) != 3 ||
		!out.Aircraft[0].PositionsTruncated || out.Aircraft[0].Operator != nil || out.Sources.Degraded {
		t.Fatalf("answer %+v", out)
	}
	if n := f.count(`SELECT count(*) FROM police_queries`); n != 1 {
		t.Fatalf("%d police_queries rows", n)
	}
	var purpose, entity string
	if err := f.pg.QueryRow(`SELECT purpose, entity_id FROM events WHERE event_type = 'police_query'`).Scan(&purpose, &entity); err != nil ||
		purpose != "public_order" || entity != out.QueryId {
		t.Fatalf("events row %q %q %v", purpose, entity, err)
	}
	var kind, caseRef, ip string
	var count int
	var pii bool
	if err := f.pg.QueryRow(`SELECT kind, case_ref, result_count, pii, remote_ip FROM police_queries WHERE id = $1`, out.QueryId).
		Scan(&kind, &caseRef, &count, &pii, &ip); err != nil || kind != KindAircraft || caseRef != "CASE-INT-1" || count != 1 || pii || ip != insideIP {
		t.Fatalf("row %s %s %d %v %s %v", kind, caseRef, count, pii, ip, err)
	}
	if len(f.reg.reads) != 0 {
		t.Fatal("a status-only purpose opened personal data")
	}
	pi, err := f.svc.QueryAircraft(ctx, AircraftQuery{BBox: box, Purpose: "criminal_investigation", CaseRef: "CASE-INT-2"})
	if err != nil || !pi.PiiReleased || len(f.reg.reads) != 1 {
		t.Fatalf("personal-data purpose: %+v %v", pi, err)
	}
	if n := f.count(`SELECT count(*) FROM events WHERE event_type = 'police_query'`); n != 2 {
		t.Fatalf("%d police_query rows", n)
	}

	month := time.Now().UTC().Format("2006-01")
	rep, err := f.svc.DPOReport(context.Background(), audit.Actor{Type: audit.ActorUser, ID: "auditor-1", Realm: "console"}, month)
	if err != nil || len(rep.PoliceQueries) != 2 || rep.Totals.PoliceQueriesWithPii != 1 || rep.PoliceQueries[1].CaseRef != "CASE-INT-2" {
		t.Fatalf("report %+v %v", rep, err)
	}
	if n := f.count(`SELECT count(*) FROM events WHERE event_type = 'dpo_report_viewed' AND actor_id = 'auditor-1'`); n != 1 {
		t.Fatalf("%d dpo_report_viewed rows", n)
	}
	// E-02: the report of a month with nothing in it is empty, not an error.
	rep, err = f.svc.DPOReport(context.Background(), audit.Actor{Type: audit.ActorUser, ID: "auditor-1"}, "2020-01")
	if err != nil || len(rep.PoliceQueries) != 0 || len(rep.PiiViews) != 0 || rep.Truncated {
		t.Fatalf("an empty month: %+v %v", rep, err)
	}
}

// The budget is the database's: two replicas share it, a restarted one
// keeps it, and concurrent queries never write past it (the agency's
// advisory lock). The refusal is a police_query_refused row.
func TestIntegrationBudgetHoldsAcrossReplicasAndRestarts(t *testing.T) {
	f := newIfix(t)
	a, b := f.svc, f.service(t)
	ctx := as(officerID, insideIP)
	q := LookupQuery{Term: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}
	if _, err := a.QuerySerial(ctx, q); err != nil {
		t.Fatal(err)
	}
	if _, err := b.QuerySerial(ctx, q); err != nil {
		t.Fatal(err)
	}
	restarted := f.service(t)
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		svc := []*Service{a, b, restarted}[i%3]
		wg.Go(func() { _, errs[i] = svc.QuerySerial(ctx, q) })
	}
	wg.Wait()
	spent := 0
	for _, err := range errs {
		var s *BudgetSpentError
		switch {
		case errors.As(err, &s):
			spent++
			if s.Scope != "user" || s.RetryAfter < time.Second || s.RetryAfter > time.Hour {
				t.Errorf("refusal %+v", s)
			}
		case err != nil:
			t.Fatal(err)
		}
	}
	if n := f.count(`SELECT count(*) FROM police_queries`); n != 3 || spent != 5 {
		t.Fatalf("%d rows, %d refused", n, spent)
	}
	if n := f.count(`SELECT count(*) FROM events WHERE event_type = 'police_query_refused' AND payload->>'reason' = 'budget_spent_user'`); n != 5 {
		t.Fatalf("%d refusal rows", n)
	}
}

// police_queries and police_exports refuse UPDATE and DELETE for every
// role; INSERT as the application role is the one way in.
func TestIntegrationThePoliceRecordIsAppendOnly(t *testing.T) {
	f := newIfix(t)
	if _, err := f.svc.QuerySerial(as(officerID, insideIP), LookupQuery{Term: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE police_queries SET result_count = 9`, `DELETE FROM police_queries`} {
		if _, err := f.pg.Exec(q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s as the owner: %v", q, err)
		}
	}
	if n := f.count(`SELECT count(*) FROM police_queries WHERE result_count = 1`); n != 1 {
		t.Fatal("the row changed")
	}
}

// 376/2014 Art. 15(2), 16: the role the police realm works as cannot read
// the occurrence reports (permission denied), while the occurrences role
// can (E-01: the check is not blind); no police table has a constraint
// on an occurrences table.
func TestIntegrationThePoliceRealmCannotReachOccurrences(t *testing.T) {
	f := newIfix(t)
	ctx := context.Background()
	read := func(role string) error {
		conn, err := f.pg.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.ExecContext(ctx, "SET ROLE "+role); err != nil {
			t.Fatal(err)
		}
		var n int
		return conn.QueryRowContext(ctx, `SELECT count(*) FROM occurrences.occurrence_reports`).Scan(&n)
	}
	if err := read(pgstore.AppRole); err == nil || store.SQLState(err) != "42501" {
		t.Fatalf("the application role read the occurrence reports: %v", err)
	}
	if err := read("authority_occurrences"); err != nil {
		t.Fatalf("the occurrences role could not: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
		LEFT JOIN pg_class ref ON ref.oid = c.confrelid LEFT JOIN pg_namespace n ON n.oid = ref.relnamespace
		WHERE r.relname IN ('police_queries', 'police_exports') AND n.nspname = 'occurrences'`); n != 0 {
		t.Fatalf("%d police constraints reach the occurrences schema", n)
	}
	if n := f.count(`SELECT count(*) FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
		WHERE r.relname = 'police_exports' AND c.contype = 'f'`); n == 0 {
		t.Fatal("the constraint check is blind: police_exports has foreign keys")
	}
}

// The database repeats the realm rules: a police account holds
// police.query alone and names an agency; a console account neither.
func TestIntegrationUsersConstraintsFollowTheRealm(t *testing.T) {
	f := newIfix(t)
	insert := func(id, roles, realm string, agency any, allow string) error {
		_, err := f.pg.Exec(`INSERT INTO users (id, username, roles, realm, agency, ip_allow, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $1, $2::text[], $3, $4, $5::text[], now(), 't', now(), 't')`, id, roles, realm, agency, allow)
		return err
	}
	id := func(n int) string { return fmt.Sprintf("%032x", n+100) }
	for i, c := range []struct {
		roles, realm string
		agency       any
		allow        string
	}{
		{"{inspector}", "police", "A", "{192.0.2.0/24}"},
		{"{police.query}", "console", nil, "{}"},
		{"{police.query}", "police", nil, "{192.0.2.0/24}"},
		{"{viewer}", "console", "A", "{}"},
		{"{viewer}", "console", nil, "{192.0.2.0/24}"},
	} {
		if err := insert(id(i), c.roles, c.realm, c.agency, c.allow); err == nil {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
	if err := insert(id(9), "{police.query}", "police", "TEST-POLICE", "{192.0.2.0/24}"); err != nil {
		t.Fatalf("a police account: %v", err)
	}
	if err := insert(id(10), "{viewer}", "console", nil, "{}"); err != nil {
		t.Fatalf("a console account: %v", err)
	}
}

// The account's row decides the address on every query, through the
// real accounts store: an allow-list changed in the database applies
// at once.
func TestIntegrationAllowListIsReadOnEveryQuery(t *testing.T) {
	f := newIfix(t)
	ctx := as(officerID, insideIP)
	q := LookupQuery{Term: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}
	if _, err := f.svc.QuerySerial(ctx, q); err != nil {
		t.Fatal(err)
	}
	f.exec(f.pg, `UPDATE users SET ip_allow = '{203.0.113.0/24}' WHERE id = $1`, officerID)
	_, err := f.svc.QuerySerial(ctx, q)
	if p := problemOf(t, err); p.Slug() != SlugAddressNotAllowed {
		t.Fatalf("after the change: %+v", p)
	}
	if n := f.count(`SELECT count(*) FROM events WHERE event_type = 'police_query_refused' AND payload->>'reason' = 'address_not_allowed'`); n != 1 {
		t.Fatalf("%d refusal rows", n)
	}
}
