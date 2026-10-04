package retention

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Validate before any side effect (E-01 pairs): each refused hold names
// its field; the valid twin is accepted and its lists deduplicated.
func TestHoldInputCheck(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	long := strings.Repeat("x", 300)
	cases := []struct {
		name  string
		in    HoldInput
		field string
	}{
		{"no case", HoldInput{Reason: "r", TrackIDs: []string{"a"}}, "case_ref"},
		{"no reason", HoldInput{CaseRef: "c", TrackIDs: []string{"a"}}, "reason"},
		{"names nothing", HoldInput{CaseRef: "c", Reason: "r"}, "window_from"},
		{"half a window", HoldInput{CaseRef: "c", Reason: "r", WindowFrom: &from}, "window_to"},
		{"backwards window", HoldInput{CaseRef: "c", Reason: "r", WindowFrom: &to, WindowTo: &from}, "window_to"},
		{"long track id", HoldInput{CaseRef: "c", Reason: "r", TrackIDs: []string{long}}, "track_ids[0]"},
		{"empty serial", HoldInput{CaseRef: "c", Reason: "r", Serials: []string{" "}}, "serials[0]"},
		{"not a violation id", HoldInput{CaseRef: "c", Reason: "r", ViolationIDs: []string{"nope"}}, "violation_ids[0]"},
		{"too many", HoldInput{CaseRef: "c", Reason: "r", TrackIDs: make([]string, MaxHoldList+1)}, "track_ids"},
	}
	for _, c := range cases {
		err := c.in.Check()
		var pe *httpx.ProblemError
		if !errors.As(err, &pe) || pe.Problem.Status != http.StatusBadRequest || !strings.Contains(err.Error()+problemFields(pe), c.field) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	ok := []HoldInput{
		{CaseRef: " c ", Reason: "r", WindowFrom: &from, WindowTo: &to},
		{CaseRef: "c", Reason: "r", TrackIDs: []string{"a", "a", " b"}},
		{CaseRef: "c", Reason: "r", ViolationIDs: []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV"}},
	}
	for i := range ok {
		if err := ok[i].Check(); err != nil {
			t.Errorf("valid %d refused: %v", i, err)
		}
	}
	if ok[0].CaseRef != "c" || len(ok[1].TrackIDs) != 2 || ok[1].TrackIDs[1] != "b" {
		t.Fatalf("normalised %+v %+v", ok[0], ok[1])
	}
}

func problemFields(pe *httpx.ProblemError) string {
	b, _ := json.Marshal(pe.Problem)
	return string(b)
}

func TestHeldSetMatchesByTrackOrSerial(t *testing.T) {
	var h heldSet
	h.addTracks("hold 1", "track-a", "", "track-a")
	h.addSerials("hold 2", "S1")
	if len(h.TrackIDs) != 1 || len(h.Why) != 2 {
		t.Fatalf("%+v", h)
	}
	if !h.matches([]string{"track-a"}, nil) || !h.matches(nil, []string{"S1"}) {
		t.Fatal("a named aircraft does not match")
	}
	if h.matches([]string{"track-b"}, []string{"S2"}) {
		t.Fatal("another aircraft matches")
	}
	if !overlaps(time.Unix(0, 0), time.Unix(10, 0), time.Unix(9, 0), time.Unix(20, 0)) || overlaps(time.Unix(0, 0), time.Unix(10, 0), time.Unix(10, 0), time.Unix(20, 0)) {
		t.Fatal("overlaps is not half-open")
	}
}

// The archive keys are valid keys of the store, by table and day.
func TestObjectKeysAreArchiveKeys(t *testing.T) {
	c := ts.Chunk{Table: "rid_observations", Name: "_timescaledb_internal._hyper_1_42_chunk",
		RangeStart: time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC), RangeEnd: time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)}
	obj, man := ObjectKeys(c)
	if obj != "telemetry/rid_observations/2026/03/04/20260304T000000Z__hyper_1_42_chunk.ndjson.gz" || !strings.HasSuffix(man, ".manifest.json") {
		t.Fatalf("%s %s", obj, man)
	}
	for _, k := range []string{obj, man} {
		if err := archive.CheckKey(k); err != nil {
			t.Fatal(err)
		}
	}
}

// The aircraft of a raw frame are named as core names them: the
// unidentified id of its transmitter, and the aircraft id of its serial.
func TestAircraftOfARawFrameUsesCoresIDs(t *testing.T) {
	tr, se := aircraftOf(ts.TableRIDObservations, &ts.ExportRow{Serial: "TEST1", Ident: "aa:bb", IDType: int(odid.IDTypeSerial)})
	if len(tr) != 2 || tr[0] != rid.UnidentifiedID("aa:bb") || tr[1] != rid.AircraftID(odid.IDTypeSerial, "TEST1") || se[0] != "TEST1" {
		t.Fatalf("%v %v", tr, se)
	}
	tr, se = aircraftOf(ts.TableTracks, &ts.ExportRow{Ident: "track-a", IDType: -1})
	if len(tr) != 1 || tr[0] != "track-a" || se != nil {
		t.Fatalf("%v %v", tr, se)
	}
}

func TestRedactDocMarksWhatItChanged(t *testing.T) {
	sys, err := odid.Encode(odid.System{OperatorLocationType: 1, OperatorLatDeg: f64(41.7), OperatorLonDeg: f64(44.8), TimestampS: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := func(p []byte) []byte {
		return []byte(`{"serial": "S", "payload": "\\x` + hex.EncodeToString(p) + `", "sent_at_ms": 12345678901234}`)
	}
	out, red, err := redactDoc(doc(sys[:]))
	if err != nil || red != archive.Redacted {
		t.Fatal(red, err)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(out)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m[redactionKey] != RedactionPositionRemoved || m["sent_at_ms"].(json.Number).String() != "12345678901234" {
		t.Fatalf("%s %v", out, err)
	}
	out, red, err = redactDoc(doc([]byte{0xF2, 25, 9}))
	if err != nil || red != archive.Undecodable || !strings.Contains(string(out), RedactionPayloadRemoved) || !strings.Contains(string(out), `"payload":"\\x"`) {
		t.Fatalf("undecodable %s %v %v", out, red, err)
	}
	loc, _ := odid.Encode(odid.Location{Status: odid.StatusAirborne, LatDeg: f64(41.7), LonDeg: f64(44.8)})
	in := doc(loc[:])
	if out, red, err := redactDoc(in); err != nil || red != archive.Unchanged || !bytes.Equal(out, in) {
		t.Fatalf("unchanged %s %v %v", out, red, err)
	}
	if _, _, err := redactDoc([]byte(`{"payload": "not hex"}`)); err == nil {
		t.Fatal("a payload that is not bytea hex was accepted")
	}
}

func TestSummariseCountsAndNames(t *testing.T) {
	sum, failed := summarise([]chunkOutcome{
		{name: "tracks/a", archived: true, dropped: true, exported: ts.Exported{Rows: 3, Bytes: 10, PIIRedacted: 1}},
		{name: "tracks/b", archived: true, held: "hold 1", exported: ts.Exported{Rows: 2}},
		{name: "tracks/c", failed: "upload"},
	})
	if failed != 1 || sum["archived"] != int64(2) || sum["dropped"] != int64(1) || sum["rows_exported"] != int64(5) ||
		sum["held"].(map[string]string)["tracks/b"] != "hold 1" || sum["failed"].(map[string]string)["tracks/c"] != "upload" {
		t.Fatalf("%v %d", sum, failed)
	}
}

func TestStatusAttrsSayThePeriodsArePendingGCAA(t *testing.T) {
	s := &Service{Periods: Periods{OnlineDays: 90, ArchiveYears: 2, ViolationsYears: 5, AuditYears: 10, Incidents: "indefinite"}}
	got := map[string]string{}
	for _, a := range s.StatusAttrs() {
		got[a.Key] = a.Value.String()
	}
	if got["retention_pending_gcaa"] != "true" || got["archive_store"] != "none" || got["retention_online_days"] != "90" {
		t.Fatalf("%v", got)
	}
}

// The plan's Q-A15 row says what PendingGCAA says: while the periods are
// the spec's defaults, the owner's acknowledgement (periods in config)
// and that GCAA has not answered are both on the row.
func TestPlanQA15SaysThePeriodsArePendingGCAA(t *testing.T) {
	b, err := os.ReadFile("../../docs/PLAN.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "| Q-A15 |") {
			row = line
		}
	}
	cells := strings.Split(row, "|")
	if len(cells) < 5 {
		t.Fatalf("no Q-A15 row in docs/PLAN.md: %q", row)
	}
	status := strings.TrimSpace(cells[len(cells)-2])
	if PendingGCAA && !strings.Contains(status, "owner acknowledged 2026-10-04: periods in config, pending GCAA") {
		t.Fatalf("Q-A15 status %q does not say the periods are in config pending GCAA", status)
	}
}
