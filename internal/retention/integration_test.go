package retention

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// E-01, the presence half: every chunk of the three hypertables beyond
// the online window is archived, read back, and dropped, with the
// numbers, the names and the events rows; the remote pilot position is
// removed from the archived System frame (06 §5) and nothing else; the
// archived rows restore with jsonb_populate_record (the runbook's
// recipe). The absence half beside it: the rows inside the window stay,
// and a second run finds nothing to do and says 0.
func TestIntegrationArchiveDropsExpiredChunksAndKeepsRecentOnes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old, recent := dayAgo(200), dayAgo(10)
	f.track(t, old, "track-a", "TESTSERIAL0000000001")
	f.track(t, old, "track-a", "TESTSERIAL0000000001")
	f.track(t, old, "track-b", "")
	f.track(t, recent, "track-a", "TESTSERIAL0000000001")
	sys := systemFrame(t)
	f.frame(t, old, "aa:bb:cc:dd:ee:01", "TESTSERIAL0000000001", sys)
	f.frame(t, old, "aa:bb:cc:dd:ee:01", "TESTSERIAL0000000001", locationFrame(t))
	f.frame(t, recent, "aa:bb:cc:dd:ee:01", "TESTSERIAL0000000001", sys)
	f.manned(t, old, "4b1234")
	f.manned(t, recent, "4b1234")
	window := time.Now().AddDate(0, 0, -90)

	sum, err := f.svc.ArchiveTelemetry(ctx)
	if err != nil {
		t.Fatalf("run: %v %v", err, sum)
	}
	if sum["archived"] != int64(3) || sum["dropped"] != int64(3) || sum["rows_exported"] != int64(6) || sum["frames_pii_redacted"] != int64(1) {
		t.Fatalf("summary %v", sum)
	}
	if got := sum["dropped_chunks"].([]string); len(got) != 3 || !strings.HasPrefix(got[0], "rid_observations/") {
		t.Fatalf("dropped chunks named %v", got)
	}
	for table, col := range map[string]string{"tracks": "captured_at", "rid_observations": "ingest_ts", "manned_tracks": "source_captured_at"} {
		if n := f.rows(t, table, col, window); n != 0 {
			t.Errorf("%s: %d rows older than the online window remain", table, n)
		}
		if n := f.count(t, f.tsAdmin, "SELECT count(*) FROM "+table); n == 0 {
			t.Errorf("%s: the rows inside the online window are gone", table)
		}
		recs := f.ledger(t, table)
		if len(recs) != 1 || recs[0].State != ts.ChunkDropped || !recs[0].ArchiveAudited || !recs[0].DropAudited || recs[0].SHA256 == nil {
			t.Errorf("%s ledger %+v", table, recs)
		}
	}
	if f.events(t, audit.EventArchiveChunkArchived) != 3 || f.events(t, audit.EventArchiveChunkDropped) != 3 {
		t.Fatal("the archive steps are not audited")
	}

	// The rid_observations object: the System frame lost the position
	// and is marked, the Location frame is as received.
	rec := f.ledger(t, "rid_observations")[0]
	m := manifestOf(t, f.dir, rec.ManifestKey)
	if m.Rows != 2 || m.SHA256 != *rec.SHA256 || m.PIIRedacted != 1 || !m.AircraftComplete || !m.PendingGCAA ||
		!slices.Contains(m.Serials, "TESTSERIAL0000000001") {
		t.Fatalf("manifest %+v", m)
	}
	lines := objectLines(t, f.dir, rec.ObjectKey)
	if len(lines) != 2 {
		t.Fatalf("%d rows in the object", len(lines))
	}
	redacted := 0
	for _, l := range lines {
		raw, err := hex.DecodeString(strings.TrimPrefix(l["payload"].(string), `\x`))
		if err != nil {
			t.Fatal(err)
		}
		mt, _ := odid.TypeOf(raw)
		switch mt { //nolint:exhaustive // the fixture holds a System and a Location frame
		case odid.TypeSystem:
			ms, err := odid.Decode(raw, odid.DecodeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if s := ms[0].(odid.System); s.OperatorLatDeg != nil || s.OperatorAltHAEM != nil || l["archive_redaction"] != RedactionPositionRemoved {
				t.Fatalf("archived System frame %+v %v", s, l["archive_redaction"])
			}
			redacted++
		default:
			if _, marked := l["archive_redaction"]; marked || hex.EncodeToString(raw) != hex.EncodeToString(locationFrame(t)) {
				t.Fatalf("a frame without a position was changed: %v", l)
			}
		}
	}
	if redacted != 1 {
		t.Fatalf("%d redacted frames", redacted)
	}

	// Nothing left to do: the run says 0 and fails nothing.
	sum, err = f.svc.ArchiveTelemetry(ctx)
	if err != nil || sum["archived"] != int64(0) || sum["dropped"] != int64(0) {
		t.Fatalf("second run %v %v", sum, err)
	}

	// The runbook's restore: each line through jsonb_populate_record.
	trk := f.ledger(t, "tracks")[0]
	for _, l := range objectLines(t, f.dir, trk.ObjectKey) {
		b, _ := json.Marshal(l)
		if _, err := f.tsAdmin.Exec(`INSERT INTO tracks SELECT * FROM jsonb_populate_record(NULL::tracks, $1::jsonb)`, string(b)); err != nil {
			t.Fatalf("restore: %v", err)
		}
	}
	if n := f.rows(t, "tracks", "captured_at", window); n != 3 {
		t.Fatalf("%d rows restored", n)
	}
}

// E-01 beside the success: an upload that fails leaves the chunk online,
// named in the run's failures with the reason, the ledger at exporting
// with the error; a store that hands back other bytes fails the
// verification the same way. After a restart (a new Service, the
// databases and the archive kept) the export is attempted again and
// succeeds.
func TestIntegrationAFailedUploadLeavesTheChunkAndIsRetriedAfterARestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := dayAgo(120)
	f.track(t, old, "track-a", "")
	f.track(t, old, "track-b", "")
	window := time.Now().AddDate(0, 0, -90)

	// With no archive store nothing is dropped, and the run fails saying
	// so (a cleanup that reports success while doing nothing is worse,
	// E-02).
	if _, err := f.service(nil).ArchiveTelemetry(ctx); !errors.Is(err, archive.ErrNotConfigured) {
		t.Fatalf("no store: %v", err)
	}
	if n := f.rows(t, "tracks", "captured_at", window); n != 2 {
		t.Fatalf("no store: %d rows", n)
	}
	for name, st := range map[string]failingStore{
		"upload fails":   {Store: f.dir, failCommit: true},
		"read back lies": {Store: f.dir, corrupt: true},
	} {
		svc := f.service(st)
		sum, err := svc.ArchiveTelemetry(ctx)
		if err == nil {
			t.Fatalf("%s: the run succeeded: %v", name, sum)
		}
		failed := sum["failed"].(map[string]string)
		if len(failed) != 1 || sum["dropped"] != int64(0) {
			t.Fatalf("%s: summary %v", name, sum)
		}
		for chunk, why := range failed {
			if !strings.HasPrefix(chunk, "tracks/") || why == "" {
				t.Fatalf("%s: failure %q %q", name, chunk, why)
			}
		}
		if n := f.rows(t, "tracks", "captured_at", window); n != 2 {
			t.Fatalf("%s: %d rows left online, want 2", name, n)
		}
		recs := f.ledger(t, "tracks")
		if len(recs) != 1 || recs[0].State != ts.ChunkExporting || recs[0].LastError == nil {
			t.Fatalf("%s: ledger %+v", name, recs)
		}
	}
	if f.events(t, audit.EventArchiveChunkDropped) != 0 {
		t.Fatal("a drop was recorded")
	}
	if f.counters.Get(CounterChunksFailed) < 2 {
		t.Fatalf("failures not counted: %v", f.counters.Snapshot())
	}

	restarted := f.service(f.dir)
	sum, err := restarted.ArchiveTelemetry(ctx)
	if err != nil || sum["dropped"] != int64(1) {
		t.Fatalf("after the restart %v %v", sum, err)
	}
	recs := f.ledger(t, "tracks")
	if recs[0].State != ts.ChunkDropped || recs[0].Attempts != 3 || recs[0].LastError != nil {
		t.Fatalf("ledger %+v", recs[0])
	}
	if n := f.rows(t, "tracks", "captured_at", window); n != 0 {
		t.Fatalf("%d rows left", n)
	}
}

// E-01, the absence half: a chunk under a legal hold on one of its
// tracks, a chunk of a window a hold covers whole (every table), and a
// chunk holding the aircraft of an open incident are archived and stay
// online, each naming what holds it; the presence half beside them: a
// hold naming another aircraft holds nothing, and once the hold is
// released and the incident closed their chunks are dropped. One
// fixture, one day per case.
func TestIntegrationHeldChunksStayAndReleasedOnesGo(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	window := time.Now().AddDate(0, 0, -90)
	span := func(at time.Time) (*time.Time, *time.Time) {
		from, to := at.Add(-12*time.Hour), at.Add(12*time.Hour)
		return &from, &to
	}
	onTrack, other, whole, ofIncident := dayAgo(100), dayAgo(103), dayAgo(106), dayAgo(109)
	f.track(t, onTrack, "track-a", "")
	f.track(t, onTrack, "track-b", "")
	f.track(t, other, "track-c", "")
	f.track(t, whole, "track-d", "")
	f.manned(t, whole, "4b1234")
	f.frame(t, ofIncident, "aa:bb:cc:dd:ee:02", "TESTSERIAL0000000002", locationFrame(t))
	from, to := span(onTrack)
	trackHold := f.hold(t, HoldInput{CaseRef: "CASE-1", Reason: "court order", WindowFrom: from, WindowTo: to, TrackIDs: []string{"track-a"}})
	from, to = span(other)
	f.hold(t, HoldInput{CaseRef: "CASE-2", Reason: "another case", WindowFrom: from, WindowTo: to, TrackIDs: []string{"track-z"}, Serials: []string{"TESTSERIALZZZZ"}})
	from, to = span(whole)
	wholeHold := f.hold(t, HoldInput{CaseRef: "CASE-3", Reason: "airspace inquiry", WindowFrom: from, WindowTo: to})
	inc := f.incident(t, "open", ofIncident, "TESTSERIAL0000000002", nil)

	sum, err := f.svc.ArchiveTelemetry(ctx)
	if err != nil || sum["archived"] != int64(5) || sum["dropped"] != int64(1) {
		t.Fatalf("held run %v %v", sum, err)
	}
	held := sum["held"].(map[string]string)
	if len(held) != 4 {
		t.Fatalf("held %v", held)
	}
	by := map[string]int{}
	for _, why := range held {
		for _, id := range []string{trackHold, wholeHold, inc} {
			if strings.Contains(why, id) {
				by[id]++
			}
		}
	}
	if by[trackHold] != 1 || by[wholeHold] != 2 || by[inc] != 1 {
		t.Fatalf("held by %v: %v", by, held)
	}
	if n := f.rows(t, "tracks", "captured_at", window); n != 3 {
		t.Fatalf("%d tracks online, want 3 (the other aircraft's chunk is dropped)", n)
	}

	if _, err := f.holds.Release(ctx, officer, trackHold, "case closed"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pgAdmin.Exec(`UPDATE incidents SET status = 'closed', closed_at = now() WHERE incident_id = $1`, inc); err != nil {
		t.Fatal(err)
	}
	sum, err = f.svc.ArchiveTelemetry(ctx)
	if err != nil || sum["dropped"] != int64(2) || sum["archived"] != int64(0) || len(sum["held"].(map[string]string)) != 2 {
		t.Fatalf("after release %v %v", sum, err)
	}
	if n := f.rows(t, "tracks", "captured_at", window); n != 1 {
		t.Fatalf("%d tracks online after release, want the whole-window hold's 1", n)
	}
	if n := f.rows(t, "rid_observations", "ingest_ts", window); n != 0 {
		t.Fatalf("%d frames online after the incident closed", n)
	}
}

// 06 §5: the remote pilot position stays in the archive for an aircraft
// an incident (closed or not) references in the window, and only for
// it; another aircraft's position in the same chunk is removed.
func TestIntegrationPositionsAreKeptOnlyForAnIncidentsAircraft(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := dayAgo(100)
	f.frame(t, old, "aa:bb:cc:dd:ee:03", "TESTSERIAL0000000003", systemFrame(t))
	f.frame(t, old, "aa:bb:cc:dd:ee:04", "TESTSERIAL0000000004", systemFrame(t))
	f.incident(t, "closed", old.Add(time.Hour), "TESTSERIAL0000000003", nil)
	sum, err := f.svc.ArchiveTelemetry(ctx)
	if err != nil || sum["dropped"] != int64(1) || sum["frames_pii_redacted"] != int64(1) {
		t.Fatalf("%v %v", sum, err)
	}
	rec := f.ledger(t, "rid_observations")[0]
	if m := manifestOf(t, f.dir, rec.ManifestKey); m.PositionsKept != 1 || m.PIIRedacted != 1 || len(m.KeptFor) == 0 {
		t.Fatalf("manifest %+v", m)
	}
	for _, l := range objectLines(t, f.dir, rec.ObjectKey) {
		_, marked := l["archive_redaction"]
		switch l["serial"] {
		case "TESTSERIAL0000000003":
			if marked || l["payload"] != `\x`+hex.EncodeToString(systemFrame(t)) {
				t.Fatalf("the incident aircraft's frame was changed: %v", l)
			}
		case "TESTSERIAL0000000004":
			if !marked {
				t.Fatalf("the other aircraft's position was kept: %v", l)
			}
		default:
			t.Fatalf("unexpected row %v", l)
		}
	}
}

// A drop committed in the telemetry database whose events row was not
// written (a restart between the two commits) is recorded by the next
// run, once.
func TestIntegrationAStepCommittedBeforeARestartIsAuditedOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.track(t, dayAgo(100), "track-a", "")
	chunks, err := f.arch.ExpiredChunks(ctx, "tracks", 90, 10)
	if err != nil || len(chunks) != 1 {
		t.Fatal(chunks, err)
	}
	e, err := f.svc.export(ctx, chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	// The drop, without the relational side.
	if _, err := f.arch.Drop(ctx, "tracks", chunks[0].Name, e.Rows); err != nil {
		t.Fatal(err)
	}
	if f.events(t, audit.EventArchiveChunkDropped) != 0 {
		t.Fatal("recorded already")
	}
	for range 2 {
		if _, err := f.svc.ArchiveTelemetry(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.events(t, audit.EventArchiveChunkDropped); n != 1 {
		t.Fatalf("%d drop rows", n)
	}
	if rec := f.ledger(t, "tracks")[0]; !rec.DropAudited {
		t.Fatalf("ledger %+v", rec)
	}
}

// The database refuses a drop the ledger does not support: a chunk not
// archived, a row count that changed since the export (a late row), a
// chunk inside the 30-day floor. Beside each, the drop it accepts.
func TestIntegrationTheDatabaseRefusesAnUnarchivedDrop(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := dayAgo(100)
	f.track(t, old, "track-a", "")
	chunks, err := f.arch.ExpiredChunks(ctx, "tracks", 90, 10)
	if err != nil || len(chunks) != 1 {
		t.Fatal(chunks, err)
	}
	c := chunks[0]
	if _, err := f.arch.Drop(ctx, "tracks", c.Name, 1); err == nil {
		t.Fatal("an unarchived chunk was dropped")
	}
	e, err := f.svc.export(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	f.track(t, old.Add(time.Minute), "track-late", "")
	if _, err := f.arch.Drop(ctx, "tracks", c.Name, e.Rows); err == nil {
		t.Fatal("a chunk that gained a row after its export was dropped")
	}
	// The run's drop is refused the same way, it says so and puts the
	// chunk back to exporting; the next run exports it whole and drops.
	sum, err := f.svc.ArchiveTelemetry(ctx)
	if err == nil || sum["dropped"] != int64(0) || len(sum["failed"].(map[string]string)) != 1 {
		t.Fatalf("%v %v", sum, err)
	}
	if rec := f.ledger(t, "tracks")[0]; rec.State != ts.ChunkExporting {
		t.Fatalf("ledger %+v", rec)
	}
	sum, err = f.svc.ArchiveTelemetry(ctx)
	if err != nil || sum["dropped"] != int64(1) || sum["rows_exported"] != int64(2) {
		t.Fatalf("%v %v", sum, err)
	}
	// The floor: a chunk ended 10 days ago is listed with a window of
	// 1 day, and its drop is still refused.
	f.track(t, dayAgo(10), "track-recent", "")
	recent, err := f.arch.ExpiredChunks(ctx, "tracks", 1, 10)
	if err != nil || len(recent) != 1 {
		t.Fatal(recent, err)
	}
	short := f.service(f.dir)
	short.Periods.OnlineDays = 1
	if _, err := short.ArchiveTelemetry(ctx); err == nil {
		t.Fatal("a chunk inside the 30-day floor was dropped")
	}
	if n := f.count(t, f.tsAdmin, `SELECT count(*) FROM tracks`); n != 1 {
		t.Fatalf("%d rows", n)
	}
}

// COPY's text format round-trips through the database: a serial with a
// tab, a newline and a backslash exports as stored (LESSONS E-03).
func TestIntegrationExportRoundTripsEscapedText(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	odd := "TEST\t1\n2\\3\r\b\f\v"
	f.track(t, dayAgo(100), "track-\\odd", odd)
	chunks, err := f.arch.ExpiredChunks(ctx, "tracks", 90, 10)
	if err != nil || len(chunks) != 1 {
		t.Fatal(chunks, err)
	}
	var got []ts.ExportRow
	n, err := f.arch.Export(ctx, chunks[0], nil, func(r ts.ExportRow) error { got = append(got, r); return nil })
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if got[0].Serial != odd || got[0].Ident != "track-\\odd" {
		t.Fatalf("%q %q", got[0].Serial, got[0].Ident)
	}
	var doc map[string]any
	if err := json.Unmarshal(got[0].Doc, &doc); err != nil || doc["serial"] != odd {
		t.Fatalf("%v %v", doc["serial"], err)
	}
}
