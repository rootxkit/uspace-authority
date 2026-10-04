package occurrences

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	ostore "github.com/rootxkit/uspace-authority/internal/occurrences/store"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// pgFixture is the service on a migrated scratch relational database,
// working as the authority_occurrences role; admin is the login role
// (the superuser), which sets up, inspects and tampers.
type pgFixture struct {
	svc   *Service
	db    *ostore.DB
	admin *sql.DB
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := ostore.Open(context.Background(), store.PoolOptions{URL: u, Role: ostore.Role, ApplicationName: "uspace-authority-test-occurrences"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sealer := newSealer(t, "occ-int-1")
	svc := &Service{Store: PG{DB: db, Audit: &audit.Writer{Catalogue: audit.DefaultCatalogue()}}, Sealer: sealer, PublicPart: PublicPartOf(nil),
		Deadline: 72 * time.Hour, ClockSkew: 5 * time.Minute, RiskClasses: []string{"serious_incident", "incident"},
		Exporters: DefaultExporters(), DefaultFormat: FormatECCAIRSDraft, MaxExportRecords: 100, MaxExportBytes: 1 << 20, WriteTimeout: 10 * time.Second,
		Counters: &core.Counters{}}
	return &pgFixture{svc: svc, db: db, admin: storetest.Open(t, u)}
}

func (f *pgFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	return n
}

// asRole runs q as role on a connection of its own and returns its error.
func (f *pgFixture) asRole(t *testing.T, role, q string) error {
	t.Helper()
	ctx := context.Background()
	conn, err := f.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "SET ROLE "+role); err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, q)
	if _, rerr := conn.ExecContext(ctx, "RESET ROLE"); rerr != nil {
		t.Fatal(rerr)
	}
	return err
}

// recent is a body whose times the database clock accepts.
func recent(t *testing.T, ref string, awareAgo time.Duration) string {
	t.Helper()
	now := time.Now().UTC()
	return mutate(t, anspBody, func(m map[string]any) {
		m["report_ref"] = ref
		m["occurred_at"] = now.Add(-awareAgo - time.Minute).Format(time.RFC3339Nano)
		m["became_aware_at"] = now.Add(-awareAgo).Format(time.RFC3339Nano)
		m["min_separation"] = map[string]any{"h_m": 180, "v_m": 40, "at": now.Add(-awareAgo - time.Minute).Format(time.RFC3339Nano)}
	})
}

// A-M3 intake against PostgreSQL as the occurrences role: received_at is
// the database clock and within_72h the database's computation, true
// early and false late (stored, never refused); a replay is the first
// receipt; another report under the reference is 409; the person
// reference is sealed in the row, opened for an officer with a purpose
// and audited; an export's hash is recorded where the audit log and
// deidentified_exports can be checked against the bytes.
func TestIntegrationIntakeHandlingAndExportOnPostgres(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	early, err := f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, recent(t, "ANSP-OCC-2026-0101", time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !early.Report.Within72h || early.Report.ReceivedAt.IsZero() || time.Since(early.Report.ReceivedAt) > time.Minute ||
		early.Report.Aircraft[0].OperatorReg != "FIN87astrdge12k8" || early.Report.MinSeparation == nil || *early.Report.MinSeparation.HM != 180 {
		t.Fatalf("%+v", early.Report)
	}
	late, err := f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, recent(t, "ANSP-OCC-2026-0102", 73*time.Hour)))
	if err != nil || late.Report.Within72h {
		t.Fatalf("late: %+v %v", late.Report, err)
	}
	// Another report under a held reference (recent() moves its times).
	_, err = f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, recent(t, "ANSP-OCC-2026-0101", 2*time.Hour)))
	wantProblem(t, err, 409, SlugRefConflict)
	// The exact same report again is the first receipt.
	body := recent(t, "ANSP-OCC-2026-0103", time.Hour)
	first, err := f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if rc, err := f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, body)); err != nil || !rc.Replayed || rc.Report.ID != first.Report.ID {
		t.Fatalf("replay: %+v %v", rc, err)
	}
	if n := f.count(t, `SELECT count(*) FROM occurrences.occurrence_reports`); n != 3 {
		t.Fatalf("%d reports stored", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE event_type = 'occurrence_received'`); n != 3 {
		t.Fatalf("%d occurrence_received rows", n)
	}
	if n := f.count(t, `SELECT count(*) FROM occurrences.occurrence_reports WHERE position(convert_to('staff-0042', 'UTF8') in reporter_person_enc) > 0
		OR reporter_key_id <> 'occ-int-1'`); n != 0 {
		t.Fatalf("%d rows hold the reference in clear or under another key", n)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE payload::text LIKE '%staff-0042%' OR payload::text LIKE '%Synthetic airprox%'`); n != 0 {
		t.Fatal("an events row holds the reporter or the text")
	}

	v, err := f.svc.Reporter(ctx, officer, early.Report.ID, "follow-up interview")
	if err != nil || v.PersonRef != "staff-0042" || v.ReporterOrg != "ansp-01" {
		t.Fatalf("%+v %v", v, err)
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE event_type = 'occurrence_reporter_viewed' AND purpose = 'follow-up interview'
		AND actor_id = 'officer-1' AND entity_id = $1`, early.Report.ID); n != 1 {
		t.Fatalf("%d reporter reads audited", n)
	}
	if _, err := f.svc.Classify(ctx, officer, early.Report.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	st := func(s string) *string { return &s }
	r, err := f.svc.UpdateAnalysis(ctx, officer, early.Report.ID, AnalysisPatch{Analysis: st("Analysed."), State: st(StateAnalysed)})
	if err != nil || r.State != StateAnalysed || r.UpdatedBy != "officer-1" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = f.svc.UpdateAnalysis(ctx, officer, early.Report.ID, AnalysisPatch{State: st(StateClosed)}); err != nil || r.ClosedAt == nil {
		t.Fatalf("closed: %+v %v", r, err)
	}
	page, err := f.svc.List(ctx, Filter{State: StateClosed, Limit: 10})
	if err != nil || len(page) != 1 || page[0].ID != early.Report.ID {
		t.Fatalf("list: %+v %v", page, err)
	}

	res, err := f.svc.Export(ctx, officer, ExportRequest{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Minute)})
	if err != nil || res.Export.RecordCount != 3 {
		t.Fatalf("export: %+v %v", res.Export, err)
	}
	sum := sha256.Sum256(res.Content)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	if n := f.count(t, `SELECT count(*) FROM occurrences.deidentified_exports WHERE export_id = $1 AND content_hash = $2 AND size_bytes = $3
		AND format = 'eccairs-compatible-draft' AND record_count = 3`, res.Export.ID, hash, len(res.Content)); n != 1 {
		t.Fatal("the export is not recorded with its hash")
	}
	if n := f.count(t, `SELECT count(*) FROM events WHERE event_type = 'occurrence_export_created' AND entity_id = $1
		AND payload->>'content_hash' = $2`, res.Export.ID, hash); n != 1 {
		t.Fatal("the export's events row does not hold its hash")
	}
	if strings.Contains(string(res.Content), "staff-0042") || strings.Contains(string(res.Content), "ANSP-OCC-2026") {
		t.Fatal("the export holds the reporter")
	}
	// The exports refuse change (no grant): the record stays the record.
	if err := f.asRole(t, ostore.Role, `UPDATE occurrences.deidentified_exports SET content_hash = content_hash`); store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("update of an export: %v", err)
	}
	if err := f.asRole(t, ostore.Role, `DELETE FROM occurrences.occurrence_reports`); store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("delete of a report: %v", err)
	}
}

// A-M3 export byte bound against PostgreSQL, both sides: under the
// bound the export is built, recorded in deidentified_exports and
// audited; over it the same window is refused export_too_large and
// leaves neither an export row nor an events row.
func TestIntegrationExportByteBoundOnPostgres(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	for _, ref := range []string{"ANSP-OCC-2026-0201", "ANSP-OCC-2026-0202"} {
		if _, err := f.svc.Intake(ctx, ClientOrigin(anspActor), input(t, recent(t, ref, time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	w := ExportRequest{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Minute)}
	exports := func() int { return f.count(t, `SELECT count(*) FROM occurrences.deidentified_exports`) }
	audited := func() int {
		return f.count(t, `SELECT count(*) FROM events WHERE event_type = 'occurrence_export_created'`)
	}

	under, err := f.svc.Export(ctx, officer, w)
	if err != nil || under.Export.RecordCount != 2 || int64(len(under.Content)) > f.svc.MaxExportBytes {
		t.Fatalf("under the bound: %+v %v", under.Export, err)
	}
	if exports() != 1 || audited() != 1 {
		t.Fatalf("under the bound: %d exports, %d audited", exports(), audited())
	}

	f.svc.MaxExportBytes = under.Export.SizeBytes / 2
	_, err = f.svc.Export(ctx, officer, w)
	wantProblem(t, err, 400, SlugExportTooLarge)
	wantField(t, err, "to")
	if exports() != 1 || audited() != 1 {
		t.Fatalf("over the bound: %d exports, %d audited", exports(), audited())
	}
}

// within_72h is computed by the database and never edited: exactly at
// the deadline it is true, a microsecond past it false (E-01 both sides,
// the rule Within restates), and the column cannot be written.
func TestIntegrationWithin72hAtTheBoundary(t *testing.T) {
	f := newPGFixture(t)
	insert := func(id string, received string) bool {
		t.Helper()
		var within bool
		err := f.admin.QueryRow(`INSERT INTO occurrences.occurrence_reports (occurrence_id, reporter_org, report_ref, channel, origin,
			occurred_at, became_aware_at, received_at, report_deadline_s, category, content_hash)
			VALUES ($1, 'ussp-tst-01', $1, 'mandatory', 'client', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', $2::timestamptz, 259200,
			'other', 'sha256:'||repeat('0', 64)) RETURNING within_72h`, id, received).Scan(&within)
		if err != nil {
			t.Fatal(err)
		}
		return within
	}
	if !insert(ulidOf(1), "2026-10-04T00:00:00Z") {
		t.Fatal("received exactly 72 h after awareness is late")
	}
	if insert(ulidOf(2), "2026-10-04T00:00:00.000001Z") {
		t.Fatal("received a microsecond past 72 h is within")
	}
	if !Within(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), 72*time.Hour) {
		t.Fatal("Within disagrees with the column")
	}
	if _, err := f.admin.Exec(`UPDATE occurrences.occurrence_reports SET within_72h = true WHERE occurrence_id = $1`, ulidOf(2)); err == nil {
		t.Fatal("within_72h was edited")
	}
}

// crossSchemaDependencies lists every pg_depend edge between an object
// of the occurrences schema and an object of another schema (tables,
// views and their rules, constraints, triggers, defaults, functions,
// types), the catalogues and a table's own TOAST storage excepted.
const crossSchemaDependencies = `
WITH objs AS (
  SELECT 'pg_class'::regclass AS classid, c.oid AS objid, c.relnamespace AS ns FROM pg_class c
  UNION ALL SELECT 'pg_constraint'::regclass, o.oid, o.connamespace FROM pg_constraint o
  UNION ALL SELECT 'pg_proc'::regclass, p.oid, p.pronamespace FROM pg_proc p
  UNION ALL SELECT 'pg_type'::regclass, ty.oid, ty.typnamespace FROM pg_type ty
  UNION ALL SELECT 'pg_rewrite'::regclass, r.oid, c.relnamespace FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
  UNION ALL SELECT 'pg_trigger'::regclass, g.oid, c.relnamespace FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid
  UNION ALL SELECT 'pg_attrdef'::regclass, a.oid, c.relnamespace FROM pg_attrdef a JOIN pg_class c ON c.oid = a.adrelid
)
SELECT pg_describe_object(d.classid, d.objid, d.objsubid) || ' -> ' || pg_describe_object(d.refclassid, d.refobjid, d.refobjsubid)
FROM pg_depend d
JOIN objs a ON a.classid = d.classid AND a.objid = d.objid
JOIN objs b ON b.classid = d.refclassid AND b.objid = d.refobjid
JOIN pg_namespace na ON na.oid = a.ns
JOIN pg_namespace nb ON nb.oid = b.ns
WHERE (na.nspname = 'occurrences') <> (nb.nspname = 'occurrences')
  AND na.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND nb.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY 1`

func (f *pgFixture) strings(t *testing.T, q string) []string {
	t.Helper()
	rows, err := f.admin.Query(q)
	if err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// 376/2014 Art. 15-16 against the live catalogue: no column links the
// two sides, pg_depend holds no edge between the occurrences schema and
// any other, the application role cannot read a report, and the
// occurrences role cannot read a violation or an incident. Each absence
// is paired with its presence: the role that may read does, and a view
// and a foreign key planted across the schemas are found (E-01).
func TestIntegrationNoPathJoinsAnOccurrenceToAViolation(t *testing.T) {
	f := newPGFixture(t)
	if cols := f.strings(t, `SELECT table_schema || '.' || table_name || '.' || column_name FROM information_schema.columns
		WHERE (table_schema = 'occurrences' AND (column_name LIKE '%violation%' OR column_name LIKE '%incident%'))
		   OR (table_schema = 'public' AND table_name IN ('incidents', 'incident_aircraft', 'incident_notes', 'evidence_packs', 'violations')
		       AND column_name LIKE '%occurrence%')`); len(cols) != 0 {
		t.Fatalf("link columns: %v", cols)
	}
	if n := f.count(t, `SELECT count(*) FROM information_schema.columns WHERE table_schema = 'occurrences'`); n < 20 {
		t.Fatalf("the column check saw %d occurrence columns", n)
	}
	if deps := f.strings(t, crossSchemaDependencies); len(deps) != 0 {
		t.Fatalf("cross-schema dependencies: %v", deps)
	}

	// The roles: absence beside presence.
	if err := f.asRole(t, "authority_app", `SELECT 1 FROM occurrences.occurrence_reports`); store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("authority_app reads a report: %v", err)
	}
	if err := f.asRole(t, "authority_app", `SELECT 1 FROM violations`); err != nil {
		t.Fatalf("authority_app cannot read violations: %v", err)
	}
	for _, table := range []string{"violations", "incidents", "incident_aircraft", "evidence_packs", "uas_operators"} {
		if err := f.asRole(t, ostore.Role, "SELECT 1 FROM "+table); store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Errorf("%s reads %s: %v", ostore.Role, table, err)
		}
	}
	if err := f.asRole(t, ostore.Role, `SELECT 1 FROM occurrences.occurrence_reports`); err != nil {
		t.Fatalf("%s cannot read its reports: %v", ostore.Role, err)
	}

	// E-01: a view and a foreign key across the schemas are found.
	if _, err := f.admin.Exec(`CREATE VIEW public.planted_join AS SELECT o.occurrence_id, v.violation_id
		FROM occurrences.occurrence_reports o CROSS JOIN violations v`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(`CREATE TABLE public.planted_link (occurrence_id text REFERENCES occurrences.occurrence_reports (occurrence_id))`); err != nil {
		t.Fatal(err)
	}
	deps := f.strings(t, crossSchemaDependencies)
	joined := strings.Join(deps, "\n")
	if !strings.Contains(joined, "planted_join") || !strings.Contains(joined, "planted_link") {
		t.Fatalf("the planted view and key were not found:\n%s", joined)
	}
	t.Log(joined)
}
