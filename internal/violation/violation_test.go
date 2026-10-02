package violation

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

func compile(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, path := range []string{"../track/testdata/envelope/v1.json", "../../schemas/violation/v1.json"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(doc.(map[string]any)["$id"].(string), doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile("https://schemas.uspace.ge/violation/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func example(state State) *Message {
	ts := "2026-10-01T12:00:00.000Z"
	serial := "TESTSER1"
	v := int64(3)
	b := Body{
		ViolationID: "01KAAAAAAAAAAAAAAAAAAAAAAA", Kind: KindZoneIncursion, State: state, Severity: core.SeverityCritical,
		AlertKey: "zone:GEO:Z1:A", TrackRef: "A", Serial: &serial, ZoneID: strp("GEO/Z1"), ZoneVersion: &v, ZoneType: strp("PROHIBITED"),
		CapturedAt: ts, OpenedAt: ts, PolicyVersion: 1, Detail: map[string]any{"identifier": "Z1", "restriction": "PROHIBITED"},
		EvidenceTrust: core.TrustBroadcast, Cell5: "c5:1317:2248",
		EvidenceRefs:    []EvidenceRef{{Type: RefTrack, ID: "A"}, {Type: RefZone, ID: "GEO/Z1", Version: &v}},
		EvidenceExcerpt: []Sample{{MsgID: "01KAAAAAAAAAAAAAAAAAAAAAAB", CapturedAt: ts, RxTS: ts, TimeSource: core.TimeBroadcast, Lat: 41.7, Lng: 44.8, AltSource: core.AltGeodetic, Source: "direct_rid", SourceInstance: "rx-1", Trust: core.TrustBroadcast, Identification: core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched}}},
	}
	if state == StateCleared {
		b.ClearReason, b.ClosedAt = strp("resolved"), strp(ts)
	}
	env := bus.SystemEnvelope(Schema, Producer, time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC), b)
	env.CapturedAt = ts
	return &env
}

func strp(s string) *string { return &s }

func validate(t *testing.T, s *jsonschema.Schema, m any) error {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst)
}

// schemas/violation/v1.json, which this repository owns, accepts what
// detect publishes in each state and refuses a kind this detector does
// not raise (E-01).
func TestMessagesValidateAgainstTheSchema(t *testing.T) {
	s := compile(t)
	for _, st := range []State{StateRaised, StateUpdated, StateCleared} {
		m := example(st)
		if err := Validate(m); err != nil {
			t.Fatal(err)
		}
		if err := validate(t, s, m); err != nil {
			t.Fatalf("%s: %v", st, err)
		}
	}
	bad := example(StateRaised)
	bad.Body.Kind = "no_authorisation"
	if validate(t, s, bad) == nil || Validate(bad) == nil {
		t.Fatal("a kind this detector does not raise validated")
	}
	if _, err := Subject(&bad.Body); err != nil {
		t.Fatal(err)
	}
	bad.Body.Cell5 = "nowhere"
	if _, err := Subject(&bad.Body); err == nil {
		t.Fatal("a subject from a bad cell")
	}
}

func jsonNames(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func schemaProps(t *testing.T, def string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../schemas/violation/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range s.Defs[def].Properties {
		out = append(out, k)
	}
	slices.Sort(out)
	req := slices.Clone(s.Defs[def].Required)
	slices.Sort(req)
	if !slices.Equal(req, out) {
		t.Errorf("%s: required %v, properties %v", def, req, out)
	}
	return out
}

// The schema names exactly the members of Body and Sample, every one
// required (null when it does not apply).
func TestSchemaNamesEveryMember(t *testing.T) {
	if got, want := jsonNames(reflect.TypeFor[Body]()), schemaProps(t, "body"); !slices.Equal(got, want) || len(want) < 20 {
		t.Errorf("body: struct %v, schema %v", got, want)
	}
	if got, want := jsonNames(reflect.TypeFor[Sample]()), schemaProps(t, "sample"); !slices.Equal(got, want) || len(want) < 10 {
		t.Errorf("sample: struct %v, schema %v", got, want)
	}
}
