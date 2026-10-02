package violations

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

var inspector = audit.Actor{Type: audit.ActorUser, ID: "inspector-1", Realm: audit.RealmConsole}

type pgFixture struct {
	svc   *Service
	admin *sql.DB
}

func newPG(t *testing.T) *pgFixture {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &pgFixture{
		svc:   &Service{DB: db, Audit: audit.NewWriter(db), MaxExcerptSamples: 4, WriteTimeout: 10 * time.Second, Counters: &core.Counters{}},
		admin: storetest.Open(t, u),
	}
}

// events are the event types recorded for a violation, in order.
func (f *pgFixture) events(t *testing.T, id string) []string {
	t.Helper()
	rows, err := f.admin.Query(`SELECT event_type FROM events WHERE entity_type = 'violation' AND entity_id = $1 ORDER BY id`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

var idSeq = 0

func newID() string {
	idSeq++
	return bus.NewULID(time.Now().Add(time.Duration(idSeq) * time.Millisecond))
}

func msg(id string, state violation.State, sev core.Severity, samples int, lat, lon float64) *violation.Message {
	ts := bus.Stamp(time.Now())
	b := violation.Body{
		ViolationID: id, Kind: violation.KindZoneIncursion, State: state, Severity: sev, AlertKey: "zone:GEO:Z1:" + id, TrackRef: "T-" + id,
		ZoneID: strp("GEO/Z1"), CapturedAt: ts, OpenedAt: ts, PolicyVersion: 1, Detail: map[string]any{"identifier": "Z1"},
		EvidenceTrust: core.TrustBroadcast, Cell5: "c5:1317:2248",
		EvidenceRefs: []violation.EvidenceRef{{Type: violation.RefTrack, ID: "T-" + id}, {Type: violation.RefReceiver, ID: "rx-1"}},
	}
	for i := range samples {
		b.EvidenceExcerpt = append(b.EvidenceExcerpt, violation.Sample{MsgID: bus.NewULID(time.Now()), CapturedAt: ts, RxTS: ts,
			Lat: lat, Lng: lon + float64(i)*1e-5, AltSource: core.AltGeodetic})
	}
	if state == violation.StateCleared {
		b.ClearReason, b.ClosedAt = strp("resolved"), strp(ts)
	}
	m := bus.SystemEnvelope(violation.Schema, violation.Producer, time.Now(), b)
	return &m
}

func strp(s string) *string { return &s }

// Persistence is idempotent on violation_id and every transition is an
// events row: a raise inserts (raised), its redelivery writes nothing, a
// severity change is recorded, samples are appended up to the bound, a
// clear closes (cleared), nothing reopens it, and an update of an
// unknown id inserts it (a lost raise repaired).
func TestIntegrationApplyIsIdempotentAndAuditsEveryTransition(t *testing.T) {
	f := newPG(t)
	ctx := context.Background()
	id := newID()
	steps := []struct {
		m    *violation.Message
		want Outcome
	}{
		{msg(id, violation.StateRaised, core.SeverityWarning, 2, 41.7, 44.8), OutcomeInserted},
		{msg(id, violation.StateRaised, core.SeverityWarning, 2, 41.7, 44.8), OutcomeDuplicate},
		{msg(id, violation.StateUpdated, core.SeverityCritical, 3, 41.7, 44.8), OutcomeUpdated},
		{msg(id, violation.StateCleared, core.SeverityCritical, 0, 41.7, 44.8), OutcomeUpdated},
		{msg(id, violation.StateUpdated, core.SeverityCritical, 1, 41.7, 44.8), OutcomeAfterClose},
	}
	for i, s := range steps {
		got, err := f.svc.Apply(ctx, s.m)
		if err != nil || got != s.want {
			t.Fatalf("step %d: %v %v, want %v", i, got, err, s.want)
		}
	}
	row, err := f.svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.ClosedAt == nil || *row.ClearReason != "resolved" || row.Severity != "critical" || row.ExcerptSamples != 4 ||
		!row.ExcerptTruncated || row.Status != "new" || row.DetectorState != "cleared" || !slices.Equal(row.EvidenceTrackIds, []string{"T-" + id}) {
		t.Fatalf("row %+v", row)
	}
	if got, want := f.events(t, id), []string{"violation_raised", "violation_severity_changed", "violation_cleared"}; !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	if f.svc.Counters.Get(CounterExcerptTruncated) != 1 || f.svc.Counters.Get(CounterDuplicate) != 1 {
		t.Fatal(f.svc.Counters.Snapshot())
	}
	lost := newID()
	if got, err := f.svc.Apply(ctx, msg(lost, violation.StateUpdated, core.SeverityCritical, 1, 41.7, 44.8)); err != nil || got != OutcomeInserted {
		t.Fatalf("lost raise: %v %v", got, err)
	}
	if got := f.events(t, lost); !slices.Equal(got, []string{"violation_raised"}) {
		t.Fatalf("lost raise events %v", got)
	}
	bad := msg(newID(), violation.StateRaised, core.SeverityCritical, 0, 0, 0)
	bad.Body.CapturedAt = "yesterday"
	if _, err := f.svc.Apply(ctx, bad); err == nil {
		t.Fatal("an unreadable time was stored")
	}
}

func status(err error) int {
	if err == nil {
		return 0
	}
	return httpx.ProblemFromError(err).Status
}

// The review workflow (06 §2 T1): reviewed, then escalated; broadcast
// evidence is not escalated without a note; a final decision is not
// reviewed again; each decision and the incident request are events.
func TestIntegrationReviewWorkflow(t *testing.T) {
	f := newPG(t)
	ctx := context.Background()
	id := newID()
	if _, err := f.svc.Apply(ctx, msg(id, violation.StateRaised, core.SeverityCritical, 1, 41.7, 44.8)); err != nil {
		t.Fatal(err)
	}
	if r, err := f.svc.Review(ctx, inspector, id, DecisionReviewed, nil); err != nil || r.Status != "reviewed" || *r.ReviewedBy != "inspector-1" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := f.svc.Review(ctx, inspector, id, DecisionEscalated, nil); status(err) != http.StatusBadRequest {
		t.Fatalf("escalated broadcast evidence without a note: %v", err)
	}
	note := "operator contacted; flight log requested"
	r, err := f.svc.Review(ctx, inspector, id, DecisionEscalated, &note)
	if err != nil || r.Status != "escalated" || !r.IncidentRequested || *r.ReviewNote != note {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := f.svc.Review(ctx, inspector, id, DecisionDismissed, nil); status(err) != http.StatusConflict {
		t.Fatalf("a final decision reviewed again: %v", err)
	}
	if _, err := f.svc.Review(ctx, inspector, newID(), DecisionReviewed, nil); status(err) != http.StatusNotFound {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := f.svc.Review(ctx, inspector, id, "approved", nil); status(err) != http.StatusBadRequest {
		t.Fatalf("unknown decision: %v", err)
	}
	want := []string{"violation_raised", "violation_reviewed", "violation_escalated", "incident_requested"}
	if got := f.events(t, id); !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
}

// The list filters by status, kind and bbox (PostGIS on the first
// position) and pages by cursor, newest first.
func TestIntegrationListFiltersAndPages(t *testing.T) {
	f := newPG(t)
	ctx := context.Background()
	var ids []string
	for _, pos := range [][2]float64{{41.7, 44.8}, {41.71, 44.81}, {42.5, 45.5}} {
		id := newID()
		ids = append(ids, id)
		if _, err := f.svc.Apply(ctx, msg(id, violation.StateRaised, core.SeverityCritical, 1, pos[0], pos[1])); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := f.svc.Review(ctx, inspector, ids[0], DecisionDismissed, nil); err != nil {
		t.Fatal(err)
	}
	list := func(p pggen.ListViolationsParams) []string {
		t.Helper()
		p.Lim = 10
		rows, err := f.svc.List(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.ViolationID)
		}
		return out
	}
	minLon, minLat, maxLon, maxLat := 44.7, 41.6, 44.9, 41.8
	if got := list(pggen.ListViolationsParams{MinLon: &minLon, MinLat: &minLat, MaxLon: &maxLon, MaxLat: &maxLat}); len(got) != 2 ||
		slices.Contains(got, ids[2]) {
		t.Fatalf("bbox %v", got)
	}
	st := "dismissed"
	if got := list(pggen.ListViolationsParams{Status: &st}); !slices.Equal(got, []string{ids[0]}) {
		t.Fatalf("status %v", got)
	}
	k := "height_120m"
	if got := list(pggen.ListViolationsParams{Kind: &k}); len(got) != 0 {
		t.Fatalf("kind %v", got)
	}
	all := list(pggen.ListViolationsParams{})
	if len(all) != 3 || all[0] != ids[2] {
		t.Fatalf("newest first %v", all)
	}
	first, err := f.svc.List(ctx, pggen.ListViolationsParams{Lim: 1})
	if err != nil {
		t.Fatal(err)
	}
	at, cid := first[0].OpenedAt, first[0].ViolationID
	if got := list(pggen.ListViolationsParams{CursorOpened: &at, CursorID: &cid}); len(got) != 2 || slices.Contains(got, cid) {
		t.Fatalf("after the cursor %v", got)
	}
}

// Silence: an open violation detect no longer republishes is closed
// detector_silent with its event; one republished recently, and one
// already closed, are not touched (E-01).
func TestIntegrationSilentViolationsAreClosedNotLeftOpen(t *testing.T) {
	f := newPG(t)
	ctx := context.Background()
	silent, fresh := newID(), newID()
	for _, id := range []string{silent, fresh} {
		if _, err := f.svc.Apply(ctx, msg(id, violation.StateRaised, core.SeverityCritical, 1, 41.7, 44.8)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(`UPDATE violations SET last_message_at = now() - interval '5 minutes' WHERE violation_id = $1`, silent); err != nil {
		t.Fatal(err)
	}
	n, err := f.svc.CloseSilent(ctx, time.Minute, 100)
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	r, _ := f.svc.Get(ctx, silent)
	if r.ClosedAt == nil || *r.ClearReason != ClearReasonDetectorSilent {
		t.Fatalf("silent %+v", r)
	}
	if got := f.events(t, silent); !slices.Equal(got, []string{"violation_raised", "violation_cleared"}) {
		t.Fatalf("events %v", got)
	}
	r, _ = f.svc.Get(ctx, fresh)
	if r.ClosedAt != nil {
		t.Fatal("a fresh violation was closed")
	}
	if n, err := f.svc.CloseSilent(ctx, time.Minute, 100); err != nil || n != 0 {
		t.Fatalf("second pass %d %v", n, err)
	}
}
