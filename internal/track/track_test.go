package track

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func strs(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	slices.Sort(out)
	return out
}

func f(v float64) *float64 { return &v }

// full is a valid direct Remote ID track with every optional value set.
func full(t *testing.T) *Message {
	t.Helper()
	ref, st := f3411.TakeoffLocation, f3411.Airborne
	sn, op, uas := "TESTREG0001", "GEOTEST00000001", "uas-1"
	at := time.Date(2026, 10, 2, 9, 15, 4, 0, time.UTC)
	m, err := New("authority/rid-ingest", core.Times{TS: &at, RxTS: at.Add(410 * time.Millisecond), CapturedAt: at, Source: core.TimeBroadcast},
		Body{
			TrackID: "6f1c7d52-0000-5000-8000-000000000001", Trust: core.TrustBroadcast, Source: SourceDirectRID, SourceInstance: "rx-1",
			Position: Position{Lat: 41.7151, Lng: 44.8271}, AltWGS84M: f(520), AltAMSLM: f(504.1), AltSource: core.AltGeodetic,
			AltPressureM: f(507.5), HeightM: f(80), HeightRef: &ref, SpeedMS: f(10), TrackDeg: f(90), VSpeedMS: f(1.5),
			AccuracyHM: f(3), AccuracyVM: f(4), Status: &st,
			Identification: core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched, Serial: &sn,
				OperatorReg: &op, RegistryUASID: &uas, Basis: core.BasisAsBroadcast},
		})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The struct's JSON is the lab's track/telemetry/v1 (testdata, a verbatim
// copy at the commit in testdata/SOURCE): every required member is
// written, and nothing the schema does not name.
func TestMessageIsTheLabSchema(t *testing.T) {
	schema := readJSON(t, "testdata/track/telemetry/v1.json")
	env := readJSON(t, "testdata/envelope/v1.json")
	raw, err := full(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// ts is optional in the envelope and always written, null or a time.
	want := append(strs(env["required"]), "ts")
	slices.Sort(want)
	if !slices.Equal(keys(got), want) {
		t.Fatalf("envelope %v, want %v", keys(got), want)
	}
	defs := schema["$defs"].(map[string]any)
	bodySchema := defs["body"].(map[string]any)
	body := got["body"].(map[string]any)
	if props := keys(bodySchema["properties"].(map[string]any)); !slices.Equal(keys(body), props) {
		t.Fatalf("body %v, schema %v", keys(body), props)
	}
	for _, r := range strs(bodySchema["required"]) {
		if _, ok := body[r]; !ok {
			t.Errorf("required %s not written", r)
		}
	}
	idSchema := defs["identification"].(map[string]any)
	id := body["identification"].(map[string]any)
	if props := keys(idSchema["properties"].(map[string]any)); !slices.Equal(keys(id), props) {
		t.Fatalf("identification %v, schema %v", keys(id), props)
	}
	// Null, not absent and not zero, for what the source did not give.
	m := full(t)
	m.Body.AltAMSLM, m.Body.SpeedMS = nil, nil
	raw, _ = m.Marshal()
	if !bytes.Contains(raw, []byte(`"alt_amsl_m":null`)) || !bytes.Contains(raw, []byte(`"speed_ms":null`)) {
		t.Fatalf("unknown values not null: %s", raw)
	}
}

// The lab's examples: each valid one is read and validates, each invalid
// one is refused by Validate (or cannot be read into the struct).
func TestLabExamples(t *testing.T) {
	for _, dir := range []string{"testdata/examples", "testdata/examples/invalid"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, file := range files {
			raw, _ := os.ReadFile(file)
			var m Message
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			err := dec.Decode(&m)
			if err == nil {
				err = m.Validate()
			}
			valid := dir == "testdata/examples"
			if valid && err != nil {
				t.Errorf("%s: %v", file, err)
			}
			if !valid && err == nil {
				t.Errorf("%s: accepted", file)
			}
		}
	}
}

// T11: trust simulated and source sitl are refused; their production
// twins are accepted (E-01).
func TestSimulatedAndSITLRefused(t *testing.T) {
	m := full(t)
	if err := m.Validate(); err != nil {
		t.Fatalf("broadcast/direct_rid refused: %v", err)
	}
	m.Body.Trust = core.TrustSimulated
	var fe *core.FieldError
	if err := m.Validate(); !errors.As(err, &fe) || fe.Field != "body.trust" {
		t.Fatalf("simulated: %v", err)
	}
	m = full(t)
	m.Body.Source = SourceSITL
	if err := m.Validate(); !errors.As(err, &fe) || fe.Field != "body.source" {
		t.Fatalf("sitl: %v", err)
	}
}

// Every refusal names its field, beside a message that passes.
func TestValidateNamesTheField(t *testing.T) {
	cases := map[string]func(m *Message){
		"schema":                       func(m *Message) { m.Schema = "track/telemetry/v2" },
		"msg_id":                       func(m *Message) { m.MsgID = "x" },
		"producer":                     func(m *Message) { m.Producer = "authority" },
		"ts":                           func(m *Message) { s := "2026-10-02T09:15:04Z"; m.TS = &s },
		"rx_ts":                        func(m *Message) { m.RxTS = "" },
		"captured_at":                  func(m *Message) { m.CapturedAt = "2026-13-02T09:15:04.000Z" },
		"time_source":                  func(m *Message) { m.TimeSource = "guess" },
		"body.track_id":                func(m *Message) { m.Body.TrackID = "" },
		"body.source_instance":         func(m *Message) { m.Body.SourceInstance = "" },
		"body.position.lat":            func(m *Message) { m.Body.Position.Lat = 91 },
		"body.position.lng":            func(m *Message) { m.Body.Position.Lng = -181 },
		"body.alt_amsl_m":              func(m *Message) { v := 0.0; v /= v; m.Body.AltAMSLM = &v },
		"body.speed_ms":                func(m *Message) { m.Body.SpeedMS = f(-1) },
		"body.alt_source":              func(m *Message) { m.Body.AltSource = "guess" },
		"body.height_ref":              func(m *Message) { m.Body.HeightRef = nil },
		"body.track_deg":               func(m *Message) { m.Body.TrackDeg = f(360) },
		"body.status":                  func(m *Message) { s := f3411.RIDOperationalStatus("Flying"); m.Body.Status = &s },
		"body.cell":                    func(m *Message) { m.Body.Cell = "c5:0131:2248" },
		"body.identification.status":   func(m *Message) { m.Body.Identification.Status = "" },
		"body.identification.reason":   func(m *Message) { m.Body.Identification.Reason = "" },
		"body.identification.basis":    func(m *Message) { m.Body.Identification.Basis = "" },
		"body.identification.mismatch": func(m *Message) { m.Body.Identification.Reason = core.ReasonSerialConflict },
		"body.trust":                   func(m *Message) { m.Body.Trust = "trusted" },
		"body.source":                  func(m *Message) { m.Body.Source = "radio" },
	}
	for field, mutate := range cases {
		m := full(t)
		mutate(m)
		var fe *core.FieldError
		if err := m.Validate(); !errors.As(err, &fe) || fe.Field != field {
			t.Errorf("%s: got %v", field, err)
		}
	}
	m := full(t)
	ref := f3411.RIDHeightReference("Sea")
	m.Body.HeightRef = &ref
	if err := m.Validate(); err == nil {
		t.Error("an unknown height reference accepted")
	}
}

type recorder struct {
	subjects []string
	data     [][]byte
}

func (r *recorder) Publish(subject string, data []byte) error {
	r.subjects = append(r.subjects, subject)
	r.data = append(r.data, data)
	return nil
}

// Publish sends a valid message on trk.v1.<cell3>.<cell5>.<track_id>
// and sends nothing for an invalid one.
func TestPublishSubjectAndRefusal(t *testing.T) {
	r := &recorder{}
	m := full(t)
	if err := Publish(r, m); err != nil {
		t.Fatal(err)
	}
	want := "trk.v1.c3_131_224.c5_1317_2248." + m.Body.TrackID
	if len(r.subjects) != 1 || r.subjects[0] != want || m.Body.Cell != "c5:1317:2248" {
		t.Fatalf("published on %v (cell %s), want %s", r.subjects, m.Body.Cell, want)
	}
	m.Body.Trust = core.TrustSimulated
	if err := Publish(r, m); err == nil || len(r.subjects) != 1 {
		t.Fatalf("an invalid message was sent: %v", r.subjects)
	}
	if _, err := Subject("c3_131_224", "c5_1317_2248", "a.b"); err == nil {
		t.Fatal("a track id with a dot made a subject")
	}
	if _, err := New("authority/rid-ingest", core.Times{}, Body{Position: Position{Lat: 95}}); err == nil {
		t.Fatal("a position outside the grid got a cell")
	}
}

// ident.v1: a change of status, reason or mismatch is announced, the
// same block again is not; the change carries the block it replaces.
func TestIdentChange(t *testing.T) {
	a := core.Identification{Status: core.IdentUnknownOperator, Reason: core.ReasonRegistryUnavailable, Basis: core.BasisAsBroadcast}
	b := a
	b.Status, b.Reason = core.IdentRegistered, core.ReasonMatched
	c := b
	c.Mismatch = true
	if !IdentChanged(nil, a) || IdentChanged(&a, a) || !IdentChanged(&a, b) || !IdentChanged(&b, c) {
		t.Fatal("IdentChanged")
	}
	sn := "TESTREG0001"
	d := b
	d.Serial = &sn // a field ident.v1 does not announce
	if IdentChanged(&b, d) {
		t.Fatal("a serial alone announced a change")
	}
	m := full(t)
	ch := NewIdentChange(m, &a, time.Date(2026, 10, 2, 9, 15, 5, 0, time.UTC))
	r := &recorder{}
	if err := PublishIdent(r, ch); err != nil {
		t.Fatal(err)
	}
	if r.subjects[0] != "ident.v1."+m.Body.TrackID || ch.Body.Previous == &a || ch.Body.Previous.Reason != a.Reason ||
		ch.CapturedAt != m.CapturedAt || ch.Body.SourceInstance != "rx-1" {
		t.Fatalf("%v %+v", r.subjects, ch)
	}
	ch.Body.Identification.Basis = ""
	if err := PublishIdent(r, ch); err == nil || len(r.subjects) != 1 {
		t.Fatal("an invalid change was sent")
	}
	ch = NewIdentChange(m, nil, time.Now())
	bad := core.Identification{}
	ch.Body.Previous = &bad
	if err := ch.Validate(); err == nil {
		t.Fatal("an invalid previous block accepted")
	}
	ch.Schema = "x"
	if err := ch.Validate(); err == nil {
		t.Fatal("wrong schema accepted")
	}
	ch = NewIdentChange(m, nil, time.Now())
	ch.MsgID = ""
	if err := ch.Validate(); err == nil {
		t.Fatal("empty msg_id accepted")
	}
	ch = NewIdentChange(m, nil, time.Now())
	ch.Body.TrackID = ""
	if err := ch.Validate(); err == nil {
		t.Fatal("empty track_id accepted")
	}
}

// schemas/ident/change/v1.json names exactly IdentBody's members.
func TestIdentSchemaIsTheBody(t *testing.T) {
	s := readJSON(t, "../../schemas/ident/change/v1.json")
	body := s["properties"].(map[string]any)["body"].(map[string]any)
	raw, _ := json.Marshal(IdentBody{})
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if got, want := keys(m), keys(body["properties"].(map[string]any)); !slices.Equal(got, want) {
		t.Fatalf("IdentBody %v, schema %v", got, want)
	}
	if got, want := strs(body["required"]), keys(m); !slices.Equal(got, want) {
		t.Fatalf("required %v, members %v", got, want)
	}
}

// Row's JSON names are the tracks columns tsdb-writer maps one to one,
// and a row decodes onto the table.
func TestRowIsTheTracksTable(t *testing.T) {
	m := full(t)
	at := time.Date(2026, 10, 2, 9, 15, 4, 0, time.UTC)
	airborne := true
	r := RowOf(m, core.Times{TS: &at, RxTS: at, CapturedAt: at, Source: core.TimeBroadcast}, "direct_rid:abc", &airborne)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	want := ts.Tracks.ColumnNames()
	slices.Sort(want)
	if !slices.Equal(keys(got), want) {
		t.Fatalf("row %v, columns %v", keys(got), want)
	}
	if _, err := ts.Tracks.DecodeRow(raw); err != nil {
		t.Fatal(err)
	}
	if *r.HeightRef != "TakeoffLocation" || *r.Status != "Airborne" || *r.Cell5 != "c5:1317:2248" || r.IdentStatus != core.IdentRegistered ||
		*r.Serial != "TESTREG0001" || r.DedupeKey != "direct_rid:abc" || !r.TS.Equal(at) || !strings.HasPrefix(r.MsgID, "0") {
		t.Fatalf("%+v", r)
	}
	m.Body.HeightRef, m.Body.Status, m.Body.Cell = nil, nil, ""
	r = RowOf(m, core.Times{RxTS: at, CapturedAt: at, Source: core.TimeReceiver}, "k", nil)
	if r.HeightRef != nil || r.Status != nil || r.Cell5 != nil || r.TS != nil || r.Airborne != nil {
		t.Fatalf("%+v", r)
	}
}
