package zonesvc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

// The vectors run through this repository's import -> store -> export
// path; every judgement is uspace-core's (CLAUDE.md, knowledge
// vectors). A document is read as an import reads it (readImport: the
// ED-318 or ED-269 parser, ed318.FromED269, then this service's
// authoring checks), each zone is stored as a version through the Tx
// the service writes with, and what is compared is what the store gives
// back. This proves the storage round trip changes nothing; the
// collection's own members (name, metadata) are not held by the store
// (a version is one feature), so features are compared.

// storeRoundTrip imports doc and returns the stored features in the
// document's order, or the import's problems.
func storeRoundTrip(t *testing.T, doc []byte, lang string) ([]json.RawMessage, []*core.FieldError) {
	t.Helper()
	im, errs, _ := readImport(doc, lang, "")
	if len(errs) > 0 {
		return nil, errs
	}
	st := newMemStore(testNow)
	ctx := context.Background()
	err := st.InTx(ctx, func(tx Tx) error {
		for i := range im.features {
			c := &im.features[i]
			d := &Draft{Dataset: c.dataset, Identifier: c.identifier, Feature: c.feature, Columns: c.columns, ValidFrom: t0, ValidTo: t1}
			_, fe, err := insertNext(ctx, tx, d, modeAny, inspector.ID)
			if err != nil {
				return err
			}
			if fe != nil {
				return fe
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]json.RawMessage, 0, len(im.features))
	for i := range im.features {
		v, err := st.Latest(ctx, im.features[i].identifier)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v.Feature)
	}
	return out, nil
}

type ed318VecInput struct {
	Kind          string                       `json:"kind"`
	Document      json.RawMessage              `json:"document"`
	ED269Document json.RawMessage              `json:"ed269_document"`
	Lang          string                       `json:"lang"`
	At            string                       `json:"at"`
	Where         *core.LatLon                 `json:"where"`
	Daylight      map[string]map[string]string `json:"daylight"`
}

type ed318VecExpected struct {
	Accepted    *bool           `json:"accepted"`
	Export      json.RawMessage `json:"export"`
	MustInclude *struct {
		FieldEndsWith  string `json:"field_endswith"`
		ReasonContains string `json:"reason_contains"`
	} `json:"must_include"`
	Mapped         *bool           `json:"mapped"`
	ED269          json.RawMessage `json:"ed269"`
	ED318          json.RawMessage `json:"ed318"`
	FieldEndsWith  string          `json:"field_endswith"`
	ReasonContains string          `json:"reason_contains"`
	Applies        *bool           `json:"applies"`
	NotEvaluated   *bool           `json:"not_evaluated"`
}

// sameFeatures compares stored features with a document's, by value.
func sameFeatures(t *testing.T, stored []json.RawMessage, doc json.RawMessage) {
	t.Helper()
	want, err := splitFeatures(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != len(stored) {
		t.Fatalf("%d features stored, %d expected", len(stored), len(want))
	}
	for i := range want {
		if !sameJSON(t, stored[i], want[i]) {
			t.Errorf("feature %d:\n stored %s\n   want %s", i, stored[i], want[i])
		}
	}
}

func storedCollection(t *testing.T, stored []json.RawMessage) *ed318.FeatureCollection {
	t.Helper()
	fc, err := collect(stored)
	if err != nil {
		t.Fatal(err)
	}
	return fc
}

func TestVectorsED318RoundtripThroughStorage(t *testing.T) {
	f := vectors.Load(t, "ed318_roundtrip.json")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in ed318VecInput
		var exp ed318VecExpected
		c.Decode(t, &in, &exp)
		switch in.Kind {
		case "parse":
			stored, errs := storeRoundTrip(t, in.Document, "")
			if !*exp.Accepted {
				m := exp.MustInclude
				for _, e := range errs {
					if strings.HasSuffix(e.Field, m.FieldEndsWith) && strings.Contains(e.Reason, m.ReasonContains) {
						return
					}
				}
				t.Fatalf("no problem ending %q containing %q in %v", m.FieldEndsWith, m.ReasonContains, errs)
			}
			if len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
			sameFeatures(t, stored, exp.Export)
		case "to_ed269":
			stored, errs := storeRoundTrip(t, in.Document, "")
			if len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
			doc, err := ed318.ToED269(storedCollection(t, stored), in.Lang)
			if !*exp.Mapped {
				var fe *core.FieldError
				if err == nil || !errors.As(err, &fe) || !strings.HasSuffix(fe.Field, exp.FieldEndsWith) || !strings.Contains(fe.Reason, exp.ReasonContains) {
					t.Fatalf("got %v, want a refusal of a field ending %q containing %q", err, exp.FieldEndsWith, exp.ReasonContains)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := ed269.Export(doc)
			if err != nil {
				t.Fatal(err)
			}
			if !sameJSON(t, out, exp.ED269) {
				t.Errorf("ED-269 differs:\n got %s\nwant %s", out, exp.ED269)
			}
		case "from_ed269":
			lang := in.Lang
			stored, errs := storeRoundTrip(t, in.ED269Document, lang)
			if len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
			sameFeatures(t, stored, exp.ED318)
		case "applies":
			stored, errs := storeRoundTrip(t, in.Document, "")
			if len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
			fc := storedCollection(t, stored)
			at, err := time.Parse(time.RFC3339, in.At)
			if err != nil {
				t.Fatal(err)
			}
			var dl ed318.Daylight
			if in.Daylight != nil {
				table := ed318.FixedDaylight{}
				for date, evs := range in.Daylight {
					table[date] = map[string]time.Time{}
					for ev, s := range evs {
						v, err := time.Parse(time.RFC3339, s)
						if err != nil {
							t.Fatal(err)
						}
						table[date][ev] = v
					}
				}
				dl = table
			}
			got, err := ed318.Applies(fc.Features[0].Properties.LimitedApplicability, at, *in.Where, dl)
			if got != *exp.Applies || (err != nil) != *exp.NotEvaluated {
				t.Fatalf("applies %v (error %v), want %v not evaluated %v", got, err, *exp.Applies, *exp.NotEvaluated)
			}
			if err != nil && !strings.Contains(err.Error(), exp.ReasonContains) {
				t.Errorf("reason %q does not contain %q", err, exp.ReasonContains)
			}
		default:
			t.Fatalf("unknown kind %q", in.Kind)
		}
	})
}

// zones_applicability: each ED-269 applicability list becomes a zone of
// an ED-269 file, imported (ed318.FromED269), stored and read back; the
// stored ED-318 limitedApplicability is what ed318.Applies judges.
func TestVectorsZonesApplicabilityThroughStorage(t *testing.T) {
	f := vectors.Load(t, "zones_applicability.json")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			Applicability json.RawMessage `json:"applicability"`
			At            string          `json:"at"`
		}
		var exp struct {
			Applies bool `json:"applies"`
		}
		c.Decode(t, &in, &exp)
		zone := strings.Replace(ed269Zone("TSA001", "PROHIBITED"), `"applicability":[{"permanent":"YES"}]`,
			`"applicability":`+string(in.Applicability), 1)
		stored, errs := storeRoundTrip(t, []byte(ed269Doc(zone)), DefaultLang)
		if len(errs) > 0 {
			t.Fatalf("refused: %v", errs)
		}
		at, err := time.Parse(time.RFC3339Nano, in.At)
		if err != nil {
			t.Fatal(err)
		}
		fc := storedCollection(t, stored)
		got, err := applicabilityOf(&fc.Features[0], at, NoDaylight{})
		if err != nil {
			t.Fatalf("not evaluated: %v", err)
		}
		if (got == Applies) != exp.Applies {
			t.Errorf("%s at %s: %s, want applies %v", in.Applicability, in.At, got, exp.Applies)
		}
	})
}
