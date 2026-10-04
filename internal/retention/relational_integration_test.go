package retention

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// violation inserts a violation closed at closed (open when zero), as
// the superuser (internal/violations' own tests cover raising one).
func (f *fixture) violation(t *testing.T, opened, closed time.Time, trackID, serial string) string {
	t.Helper()
	id := bus.NewULID(opened.Add(time.Duration(f.next()) * time.Millisecond))
	state, reason := "raised", any(nil)
	var closedAt any
	if !closed.IsZero() {
		state, reason, closedAt = "cleared", "left_zone", closed
	}
	var s any
	if serial != "" {
		s = serial
	}
	if _, err := f.pgAdmin.Exec(`INSERT INTO violations (violation_id, kind, severity, alert_key, track_id, serial, detector_state,
		opened_at, closed_at, clear_reason, last_captured_at, policy_version, evidence_trust, cell5)
		VALUES ($1, 'zone_incursion', 'warning', $1, $2, $3, $4, $5, $6, $7, $5, 1, 'broadcast', 'c5:1:1')`,
		id, trackID, s, state, opened, closedAt, reason); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) violationExists(t *testing.T, id string) bool {
	t.Helper()
	return f.count(t, f.pgAdmin, `SELECT count(*) FROM violations WHERE violation_id = $1`, id) == 1
}

// E-01: violations closed more than five years ago go, in bounded
// batches, each batch an events row naming its ids (presence); beside
// them every held one stays (absence): one a legal hold names, one an
// incident was opened from, one whose aircraft an open incident names,
// one inside a hold's window, one still open, and one closed four years
// ago.
func TestIntegrationExpiredViolationsGoAndHeldOnesStay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sixYears := time.Now().AddDate(-6, 0, 0)
	var expired []string
	for range 5 {
		expired = append(expired, f.violation(t, sixYears, sixYears.Add(time.Minute), "track-free", ""))
	}
	named := f.violation(t, sixYears, sixYears.Add(time.Minute), "track-free", "")
	f.hold(t, HoldInput{CaseRef: "CASE-V", Reason: "appeal", ViolationIDs: []string{named}})
	escalated := f.violation(t, sixYears, sixYears.Add(time.Minute), "track-free", "")
	if _, err := f.pgAdmin.Exec(`INSERT INTO incidents (incident_id, kind, occurred_at, opened_from, source_violation_id, severity, status, closed_at, opened_by)
		VALUES ($1, 'violation_escalated', $2, 'violation', $3, 'warning', 'closed', now(), 'officer-1')`,
		bus.NewULID(time.Now()), sixYears, escalated); err != nil {
		t.Fatal(err)
	}
	ofIncident := f.violation(t, sixYears, sixYears.Add(time.Minute), "track-inc", "TESTSERIAL0000000009")
	f.incident(t, "assigned", time.Now(), "TESTSERIAL0000000009", nil)
	windowFrom, windowTo := sixYears.Add(-time.Hour), sixYears.Add(time.Hour)
	inWindow := f.violation(t, sixYears, sixYears.Add(time.Minute), "track-win", "")
	f.hold(t, HoldInput{CaseRef: "CASE-W", Reason: "inquiry", WindowFrom: &windowFrom, WindowTo: &windowTo, TrackIDs: []string{"track-win"}})
	open := f.violation(t, sixYears, time.Time{}, "track-free", "")
	recent := f.violation(t, time.Now().AddDate(-4, 0, 0), time.Now().AddDate(-4, 0, 0), "track-free", "")

	svc := f.service(f.dir)
	svc.BatchRows = 2
	sum, err := svc.DeleteViolations(ctx)
	if err != nil || sum["deleted"] != 5 || sum["batches"] != 3 || sum["left_for_next_run"] != false {
		t.Fatalf("%v %v", sum, err)
	}
	for _, id := range expired {
		if f.violationExists(t, id) {
			t.Errorf("expired %s stays", id)
		}
	}
	for name, id := range map[string]string{"named by a hold": named, "escalated": escalated, "open incident's aircraft": ofIncident,
		"inside a hold's window": inWindow, "still open": open, "four years old": recent} {
		if !f.violationExists(t, id) {
			t.Errorf("%s (%s) was deleted", name, id)
		}
	}
	// Every deleted id is in exactly one batch's events row.
	rows, err := f.pgAdmin.Query(`SELECT payload FROM events WHERE event_type = $1 ORDER BY id`, audit.EventRetentionRowsDeleted)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var logged []string
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		var p struct {
			Rows int      `json:"rows"`
			IDs  []string `json:"violation_ids"`
		}
		if err := json.Unmarshal(b, &p); err != nil || p.Rows != len(p.IDs) || p.Rows > 2 {
			t.Fatalf("batch row %s %v", b, err)
		}
		logged = append(logged, p.IDs...)
	}
	slices.Sort(logged)
	slices.Sort(expired)
	if !slices.Equal(logged, expired) {
		t.Fatalf("audited %v, deleted %v", logged, expired)
	}

	// The bound: one batch per run leaves the rest for the next run, said.
	more := []string{f.violation(t, sixYears, sixYears, "track-free", ""), f.violation(t, sixYears, sixYears, "track-free", ""),
		f.violation(t, sixYears, sixYears, "track-free", "")}
	svc.MaxBatches = 1
	sum, err = svc.DeleteViolations(ctx)
	if err != nil || sum["deleted"] != 2 || sum["left_for_next_run"] != true {
		t.Fatalf("bounded %v %v", sum, err)
	}
	if n := f.count(t, f.pgAdmin, `SELECT count(*) FROM violations WHERE violation_id = ANY($1)`, "{"+strings.Join(more, ",")+"}"); n != 1 {
		t.Fatalf("%d left", n)
	}
	// The floor: the database refuses a cutoff inside 30 days whatever
	// the caller asks.
	err = f.db.WithTx(ctx, func(q *gen.Queries) error {
		_, err := q.DeleteExpiredViolations(ctx, gen.DeleteExpiredViolationsParams{Years: 0, MaxRows: 10})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "30-day floor") {
		t.Fatalf("floor: %v", err)
	}
}

// The audit log: the oldest months past ten years are dropped oldest
// first, each with its anchor, and the chain still verifies across the
// gap (presence); a held month stays, and stops the months after it
// (absence); once released it goes. The database refuses a month that
// is not the oldest, and a cutoff inside its one-year floor.
func TestIntegrationAuditMonthsGoOldestFirstAndTheChainStillVerifies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m1 := time.Date(time.Now().UTC().Year()-12, 3, 10, 12, 0, 0, 0, time.UTC)
	m2 := m1.AddDate(0, 1, 0)
	record := func(at time.Time) audit.Recorded {
		var rec audit.Recorded
		if err := f.db.WithTx(ctx, func(q *gen.Queries) error {
			var err error
			rec, err = f.w.Record(ctx, q, audit.Event{TS: at, Actor: audit.SystemActor("test"), EntityType: "test", EventType: audit.EventPolicyCreated})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	record(m1)
	record(m1.Add(time.Hour))
	last2 := record(m2)
	m2From, m2To := m2.Add(-time.Hour), m2.Add(time.Hour)
	hold := f.hold(t, HoldInput{CaseRef: "CASE-A", Reason: "records request", WindowFrom: &m2From, WindowTo: &m2To})
	now := time.Now().UTC()

	if err := f.db.WithTx(ctx, func(q *gen.Queries) error {
		_, err := q.DropEventsMonth(ctx, gen.DropEventsMonthParams{MonthStart: audit.MonthStart(m2), Years: 10})
		return err
	}); err == nil || !strings.Contains(err.Error(), "not the oldest") {
		t.Fatalf("a month that is not the oldest: %v", err)
	}
	if err := f.db.WithTx(ctx, func(q *gen.Queries) error {
		_, err := q.DropEventsMonth(ctx, gen.DropEventsMonthParams{MonthStart: audit.MonthStart(m1), Years: 0})
		return err
	}); err == nil || !strings.Contains(err.Error(), "one-year floor") {
		t.Fatalf("the floor: %v", err)
	}

	sum, err := f.svc.DropAuditMonths(ctx)
	if err != nil || !slices.Equal(sum["dropped"].([]string), []string{m1.Format("2006-01")}) || sum["held"] != m2.Format("2006-01") {
		t.Fatalf("%v %v", sum, err)
	}
	if f.events(t, audit.EventAuditMonthDropped) != 1 {
		t.Fatal("the drop is not audited")
	}
	v := audit.NewChainVerifier(f.w, nil, nil)
	res, _, err := v.VerifyMonth(ctx, audit.SystemActor("test"), m2, audit.ViaRequest)
	if err != nil || res.Broken != nil || res.Rows != 1 || res.AnchoredTo != m1.Format("2006-01") {
		t.Fatalf("the month after the gap: %+v %v", res, err)
	}

	if _, err := f.holds.Release(ctx, officer, hold, "answered"); err != nil {
		t.Fatal(err)
	}
	sum, err = f.svc.DropAuditMonths(ctx)
	if err != nil || !slices.Equal(sum["dropped"].([]string), []string{m2.Format("2006-01")}) || sum["held"] != "" {
		t.Fatalf("after release %v %v", sum, err)
	}
	// This month's first row linked to m2's last; with m2 gone it links
	// to the anchor, and the month verifies.
	res, _, err = v.VerifyMonth(ctx, audit.SystemActor("test"), now, audit.ViaRequest)
	if err != nil || res.Broken != nil || res.AnchoredTo != m2.Format("2006-01") {
		t.Fatalf("this month: %+v %v", res, err)
	}
	var anchor string
	if err := f.pgAdmin.QueryRow(`SELECT last_hash FROM audit_dropped_months WHERE month = $1`, audit.MonthStart(m2)).Scan(&anchor); err != nil || anchor != last2.Hash {
		t.Fatalf("anchor %q, want %q: %v", anchor, last2.Hash, err)
	}
	// Nothing older is left: a run drops nothing and fails nothing.
	sum, err = f.svc.DropAuditMonths(ctx)
	if err != nil || len(sum["dropped"].([]string)) != 0 {
		t.Fatalf("third run %v %v", sum, err)
	}
}

// A hold without a window that names only aircraft covers them at any
// time, their audit rows too: a month with a row naming a held track (in
// its payload) or a held serial (as its entity) stays, and stops the
// months after it (absence); a hold naming other aircraft holds nothing,
// and once each matching hold is released its month goes (presence).
func TestIntegrationAuditMonthsStayForHoldsNamingOnlyAircraft(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m1 := time.Date(time.Now().UTC().Year()-12, 3, 10, 12, 0, 0, 0, time.UTC)
	m2 := m1.AddDate(0, 1, 0)
	record := func(at time.Time, entityID string, payload any) {
		if err := f.db.WithTx(ctx, func(q *gen.Queries) error {
			_, err := f.w.Record(ctx, q, audit.Event{TS: at, Actor: audit.SystemActor("test"), EntityType: "test", EntityID: entityID,
				EventType: audit.EventPolicyCreated, Payload: payload})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	record(m1, "", map[string]any{"violation": map[string]any{"track_id": "track-held"}})
	record(m2, "TESTSERIALHELD000001", nil)
	byTrack := f.hold(t, HoldInput{CaseRef: "CASE-T", Reason: "track inquiry", TrackIDs: []string{"track-held"}})
	bySerial := f.hold(t, HoldInput{CaseRef: "CASE-S", Reason: "serial inquiry", Serials: []string{"TESTSERIALHELD000001"}})
	f.hold(t, HoldInput{CaseRef: "CASE-O", Reason: "another aircraft", TrackIDs: []string{"track-other"}, Serials: []string{"TESTSERIALOTHER00001"}})

	sum, err := f.svc.DropAuditMonths(ctx)
	if err != nil || len(sum["dropped"].([]string)) != 0 || sum["held"] != m1.Format("2006-01") {
		t.Fatalf("held by the track %v %v", sum, err)
	}
	if _, err := f.holds.Release(ctx, officer, byTrack, "answered"); err != nil {
		t.Fatal(err)
	}
	sum, err = f.svc.DropAuditMonths(ctx)
	if err != nil || !slices.Equal(sum["dropped"].([]string), []string{m1.Format("2006-01")}) || sum["held"] != m2.Format("2006-01") {
		t.Fatalf("held by the serial %v %v", sum, err)
	}
	if _, err := f.holds.Release(ctx, officer, bySerial, "answered"); err != nil {
		t.Fatal(err)
	}
	sum, err = f.svc.DropAuditMonths(ctx)
	if err != nil || !slices.Equal(sum["dropped"].([]string), []string{m2.Format("2006-01")}) || sum["held"] != "" {
		t.Fatalf("with only the other aircraft's hold %v %v", sum, err)
	}
}

// The archive period: a dropped chunk's object older than two years is
// deleted with its manifest and an events row (presence); a hold
// naming one of its aircraft (read from the manifest) keeps it, a hold
// naming another does not, an open incident in its range keeps it
// (absence). A USSP bundle past the period goes the same way.
func TestIntegrationExpiredArchiveObjectsGoAndHeldOnesStay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := dayAgo(3 * 366)
	f.track(t, old, "track-a", "TESTSERIAL00000000AA")
	if sum, err := f.svc.ArchiveTelemetry(ctx); err != nil || sum["dropped"] != int64(1) {
		t.Fatalf("archive %v %v", sum, err)
	}
	rec := f.ledger(t, "tracks")[0]
	from, to := old.Add(-time.Hour), old.Add(time.Hour)

	other := f.hold(t, HoldInput{CaseRef: "CASE-O", Reason: "other aircraft", WindowFrom: &from, WindowTo: &to, TrackIDs: []string{"track-z"}})
	mine := f.hold(t, HoldInput{CaseRef: "CASE-M", Reason: "this aircraft", Serials: []string{"TESTSERIAL00000000AA"}})
	sum, err := f.svc.ExpireArchive(ctx)
	if err != nil || len(sum["deleted"].([]string)) != 0 || len(sum["held"].(map[string]string)) != 1 {
		t.Fatalf("held %v %v", sum, err)
	}
	if r, err := f.dir.Open(rec.ObjectKey); err != nil {
		t.Fatalf("the held object is gone: %v", err)
	} else {
		_ = r.Close()
	}
	if _, err := f.holds.Release(ctx, officer, mine, "done"); err != nil {
		t.Fatal(err)
	}
	inc := f.incident(t, "open", old, "", []string{"track-q"})
	if sum, err := f.svc.ExpireArchive(ctx); err != nil || len(sum["held"].(map[string]string)) != 1 {
		t.Fatalf("open incident %v %v", sum, err)
	}
	if _, err := f.pgAdmin.Exec(`UPDATE incidents SET status = 'closed', closed_at = now() WHERE incident_id = $1`, inc); err != nil {
		t.Fatal(err)
	}
	sum, err = f.svc.ExpireArchive(ctx)
	if err != nil || len(sum["deleted"].([]string)) != 1 {
		t.Fatalf("delete %v %v (the hold %s names another aircraft)", sum, err, other)
	}
	for _, k := range []string{rec.ObjectKey, rec.ManifestKey} {
		if _, err := f.dir.Open(k); !errors.Is(err, archive.ErrNotFound) {
			t.Fatalf("%s: %v", k, err)
		}
	}
	if rec := f.ledger(t, "tracks")[0]; rec.ObjectDeletedAt == nil || !rec.DeleteAudited {
		t.Fatalf("ledger %+v", rec)
	}
	if f.events(t, audit.EventArchiveObjectDeleted) != 1 {
		t.Fatal("the deletion is not audited")
	}

	// A USSP daily bundle past the period. A bundle is opaque, so any
	// hold naming aircraft on its day keeps it; the other hold goes first.
	if _, err := f.holds.Release(ctx, officer, other, "done"); err != nil {
		t.Fatal(err)
	}
	day := time.Date(old.Year(), old.Month(), old.Day(), 0, 0, 0, 0, time.UTC)
	key := "ussp-records/ABC/" + day.Format("2006/01") + "/" + day.Format(time.DateOnly) + "-00.json"
	if err := archive.Put(f.dir, key, []byte(`{"flights":[]}`)); err != nil {
		t.Fatal(err)
	}
	sha, size := archive.Hash([]byte(`{"flights":[]}`)), int64(14)
	if err := f.db.Queries().RecordUSSPDayFetched(ctx, gen.RecordUSSPDayFetchedParams{UsspCode: "ABC", Day: day, Sha256: &sha, SizeBytes: &size, ArchiveKey: &key}); err != nil {
		t.Fatal(err)
	}
	dayFrom, dayTo := day, day.AddDate(0, 0, 1)
	h := f.hold(t, HoldInput{CaseRef: "CASE-U", Reason: "records", WindowFrom: &dayFrom, WindowTo: &dayTo, Serials: []string{"TESTSERIAL00000000QQ"}})
	if sum, err := f.svc.ExpireArchive(ctx); err != nil || len(sum["held"].(map[string]string)) != 1 {
		t.Fatalf("held bundle %v %v", sum, err)
	}
	if _, err := f.holds.Release(ctx, officer, h, "done"); err != nil {
		t.Fatal(err)
	}
	if sum, err := f.svc.ExpireArchive(ctx); err != nil || len(sum["deleted"].([]string)) != 1 {
		t.Fatalf("bundle %v %v", sum, err)
	}
	if _, err := f.dir.Open(key); !errors.Is(err, archive.ErrNotFound) {
		t.Fatalf("bundle kept: %v", err)
	}
}

// Holds: placed and released with their events rows; a release of a
// released hold is 409, of none 404; an invalid hold is refused before
// anything is written; the table refuses a change of anything but the
// release and refuses DELETE, for the owner too.
func TestIntegrationHoldsArePlacedReleasedAndNeverRewritten(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.holds.Place(ctx, officer, HoldInput{CaseRef: "C", Reason: "r"}); err == nil {
		t.Fatal("a hold naming nothing was placed")
	}
	if f.count(t, f.pgAdmin, `SELECT count(*) FROM legal_holds`) != 0 || f.events(t, audit.EventLegalHoldPlaced) != 0 {
		t.Fatal("a refused hold wrote something")
	}
	id := f.hold(t, HoldInput{CaseRef: "CASE-H", Reason: "court order", TrackIDs: []string{"track-a", "track-a"}})
	if rows, trunc, err := f.holds.List(ctx, officer, false, 10); err != nil || len(rows) != 1 || trunc || len(rows[0].TrackIds) != 1 {
		t.Fatalf("list %v %v %v", rows, trunc, err)
	}
	if _, err := f.pgAdmin.Exec(`UPDATE legal_holds SET case_ref = 'X' WHERE hold_id = $1`, id); err == nil {
		t.Fatal("the case reference was rewritten")
	}
	if _, err := f.pgAdmin.Exec(`DELETE FROM legal_holds WHERE hold_id = $1`, id); err == nil {
		t.Fatal("a hold was deleted")
	}
	if _, err := f.holds.Release(ctx, officer, id, "case closed"); err != nil {
		t.Fatal(err)
	}
	_, err := f.holds.Release(ctx, officer, id, "again")
	var pe *httpx.ProblemError
	if !errors.As(err, &pe) || pe.Problem.Status != http.StatusConflict {
		t.Fatalf("second release %v", err)
	}
	if _, err := f.holds.Release(ctx, officer, bus.NewULID(time.Now()), "x"); !errors.As(err, &pe) || pe.Problem.Status != http.StatusNotFound {
		t.Fatalf("release of none %v", err)
	}
	if rows, _, err := f.holds.List(ctx, officer, false, 10); err != nil || len(rows) != 0 {
		t.Fatalf("active after release %v %v", rows, err)
	}
	if rows, _, err := f.holds.List(ctx, officer, true, 10); err != nil || len(rows) != 1 || rows[0].ReleasedBy == nil {
		t.Fatalf("with released %v %v", rows, err)
	}
	if f.events(t, audit.EventLegalHoldPlaced) != 1 || f.events(t, audit.EventLegalHoldReleased) != 1 || f.events(t, audit.EventLegalHoldsViewed) != 3 {
		t.Fatal("holds not audited")
	}
}

// The job ledger is on the database clock and survives a restart: a run
// recorded ok is not due again within its period, also for a second
// scheduler (api after a restart); a failed run is due again only after
// the retry wait; a monthly job runs once in the month. An interrupted
// run (no end recorded) is retried after the wait.
func TestIntegrationTheJobLedgerSurvivesARestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	runs, fail := 0, false
	jobs := []Job{
		{Name: "daily", Every: time.Hour, Run: func(context.Context) (map[string]any, error) {
			runs++
			if fail {
				return map[string]any{"n": runs}, errors.New("test: failed")
			}
			return map[string]any{"n": runs}, nil
		}},
		{Name: "monthly", Monthly: true, Run: func(context.Context) (map[string]any, error) { return map[string]any{}, nil }},
	}
	sched := func() *Scheduler { return &Scheduler{DB: f.db, Jobs: jobs, Retry: time.Hour} }
	s := sched()
	if r, err := s.RunJob(ctx, "daily", false); err != nil || r.Outcome != "ok" {
		t.Fatalf("first %+v %v", r, err)
	}
	if _, err := s.RunJob(ctx, "daily", false); !errors.Is(err, ErrNotDue) {
		t.Fatalf("second %v", err)
	}
	if _, err := sched().RunJob(ctx, "daily", false); !errors.Is(err, ErrNotDue) || runs != 1 {
		t.Fatalf("after a restart %v (runs %d)", err, runs)
	}
	if _, err := s.RunJob(ctx, "monthly", false); err != nil {
		t.Fatal(err)
	}
	if _, err := sched().RunJob(ctx, "monthly", false); !errors.Is(err, ErrNotDue) {
		t.Fatalf("monthly again %v", err)
	}
	// A failed run: recorded failed with its error; not due again inside
	// the retry wait even though no ok run is inside the period.
	if _, err := f.pgAdmin.Exec(`UPDATE job_runs SET started_at = started_at - interval '2 hours' WHERE job = 'daily'`); err != nil {
		t.Fatal(err)
	}
	fail = true
	if r, err := s.RunJob(ctx, "daily", false); err == nil || r.Outcome != "failed" {
		t.Fatalf("failed run %+v %v", r, err)
	}
	if _, err := sched().RunJob(ctx, "daily", false); !errors.Is(err, ErrNotDue) {
		t.Fatalf("inside the retry wait %v", err)
	}
	var outcome, summary string
	if err := f.pgAdmin.QueryRow(`SELECT outcome, summary::text FROM job_runs WHERE job = 'daily' ORDER BY run_id DESC LIMIT 1`).Scan(&outcome, &summary); err != nil ||
		outcome != "failed" || !strings.Contains(summary, "test: failed") {
		t.Fatalf("ledger %q %q %v", outcome, summary, err)
	}
	// An interrupted run (started, never finished) past the wait is due.
	if _, err := f.pgAdmin.Exec(`UPDATE job_runs SET started_at = started_at - interval '2 hours' WHERE job = 'daily'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Queries().StartJobRun(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pgAdmin.Exec(`UPDATE job_runs SET started_at = started_at - interval '2 hours' WHERE job = 'daily' AND finished_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	fail = false
	if r, err := sched().RunJob(ctx, "daily", false); err != nil || r.Outcome != "ok" {
		t.Fatalf("after an interrupted run %+v %v", r, err)
	}
	// The status reads the ledger.
	st, err := f.svc.Status(ctx)
	if err != nil || len(st.Jobs) != 2 || !st.Periods.PendingGcaa || st.Periods.OnlineDays != 90 {
		t.Fatalf("status %+v %v", st, err)
	}
}
