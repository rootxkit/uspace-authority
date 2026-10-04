package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func policySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, path := range []string{"../track/testdata/envelope/v1.json", "../../schemas/policy/active/v1.json"} {
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
	s, err := c.Compile("https://schemas.uspace.ge/policy/active/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// INV-03, E-15: the active policy travels in its envelope, validates
// against schemas/policy/active/v1.json, and decodes back to the same
// thresholds; a value of another schema, version 0 or thresholds that do
// not validate are refused, naming the field (E-01: each refusal beside
// the accepted value).
func TestActivePolicyEncodesValidatesAndDecodes(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	p := Policy{Version: 4, Thresholds: Defaults(), ActivatedAt: &at}
	p.HeightLimitAGLM = 90
	raw, err := Encode(p, "authority/api", at)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := policySchema(t).Validate(inst); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil || got.Version != 4 || got.HeightLimitAGLM != 90 || !got.ActivatedAt.Equal(at) {
		t.Fatalf("%+v %v", got, err)
	}
	refuse := func(name, field string, mutate func(m map[string]any)) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mutate(m)
		b, _ := json.Marshal(m)
		if _, err := Decode(b); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refuse("schema", "schema", func(m map[string]any) { m["schema"] = "source/control/v1" })
	refuse("version", "body.version", func(m map[string]any) { m["body"].(map[string]any)["version"] = 0 })
	refuse("threshold", "clear_after_s", func(m map[string]any) { m["body"].(map[string]any)["clear_after_s"] = -1 })
	if _, err := Decode([]byte("[")); err == nil {
		t.Fatal("garbage decoded")
	}
}

// defaultedMembers are the members Decode fills when a value lacks them
// (written before migration 00024): the schema leaves them optional and
// names the same default.
var defaultedMembers = map[string]any{
	"no_authorisation_grace_s":  float64(DefaultNoAuthorisationGraceS),
	"no_authorisation_severity": string(DefaultNoAuthorisationSeverity),
}

// The schema names exactly the members of ActiveBody (the thresholds
// flattened), every one required but those Decode defaults, which carry
// Decode's default.
func TestActiveSchemaNamesEveryMember(t *testing.T) {
	var names []string
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for i := range rt.NumField() {
			f := rt.Field(i)
			if f.Anonymous {
				walk(f.Type)
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			names = append(names, name)
		}
	}
	walk(reflect.TypeFor[ActiveBody]())
	slices.Sort(names)
	raw, err := os.ReadFile("../../schemas/policy/active/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]struct {
			Properties map[string]map[string]any `json:"properties"`
			Required   []string                  `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	req := slices.Clone(s.Defs["body"].Required)
	for name := range defaultedMembers {
		req = append(req, name)
	}
	slices.Sort(req)
	if !slices.Equal(names, req) || len(s.Defs["body"].Properties) != len(names) {
		t.Fatalf("struct %v, schema %v", names, req)
	}
	for name, want := range defaultedMembers {
		if got := s.Defs["body"].Properties[name]["default"]; got != want {
			t.Errorf("%s: schema default %v, Decode's %v", name, got, want)
		}
	}
}

// The schema and Decode agree on a value written before migration 00024:
// the schema accepts it, as Decode does with its defaults; a value naming
// a zero grace is refused by both (E-01).
func TestActiveSchemaAndDecodeAgreeOnAnOlderValue(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	raw, err := Encode(Policy{Version: 3, Thresholds: Defaults(), ActivatedAt: &at}, "authority/api", at)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	body := doc["body"].(map[string]any)
	for name := range defaultedMembers {
		delete(body, name)
	}
	validate := func(doc map[string]any) error {
		b, _ := json.Marshal(doc)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); err != nil {
			return err
		}
		return policySchema(t).Validate(inst)
	}
	if err := validate(doc); err != nil {
		t.Fatalf("older value: %v", err)
	}
	body["no_authorisation_grace_s"] = 0
	b, _ := json.Marshal(doc)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(b); err == nil {
		t.Fatal("Decode took a zero grace")
	}
	if err := policySchema(t).Validate(inst); err == nil {
		t.Fatal("the schema took a zero grace")
	}
}

type recordPub struct {
	got []int64
	err error
}

func (r *recordPub) PublishPolicy(_ context.Context, p Policy) error {
	r.got = append(r.got, p.Version)
	return r.err
}

// Publishers announces to every publisher even when one fails, and says
// which failed.
func TestPublishersReachEveryOneAndJoinErrors(t *testing.T) {
	a, b := &recordPub{err: errors.New("bucket down")}, &recordPub{}
	err := Publishers{a, b}.PublishPolicy(context.Background(), Policy{Version: 2})
	if err == nil || !strings.Contains(err.Error(), "bucket down") || len(a.got) != 1 || len(b.got) != 1 {
		t.Fatalf("%v %v %v", err, a.got, b.got)
	}
	if err := (Publishers{b}).PublishPolicy(context.Background(), Policy{Version: 3}); err != nil {
		t.Fatal(err)
	}
}

// WP-26, E-01 pair: a value written before migration 00024 (no
// no_authorisation members) decodes with their defaults instead of being
// refused for a zero grace; a value that names them keeps its own; one
// that names a zero grace is refused, naming it.
func TestDecodeFillsTheNoAuthorisationDefaultsOfAnOlderValue(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	p := Policy{Version: 5, Thresholds: Defaults(), ActivatedAt: &at}
	p.NoAuthorisationGraceS, p.NoAuthorisationSeverity = 25, "critical"
	raw, err := Encode(p, "authority/api", at)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil || got.NoAuthorisationGraceS != 25 || got.NoAuthorisationSeverity != "critical" {
		t.Fatalf("own values: %+v %v", got.Thresholds, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	body := doc["body"].(map[string]any)
	delete(body, "no_authorisation_grace_s")
	delete(body, "no_authorisation_severity")
	old, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(old)
	if err != nil || got.NoAuthorisationGraceS != DefaultNoAuthorisationGraceS || got.NoAuthorisationSeverity != DefaultNoAuthorisationSeverity ||
		got.Version != 5 {
		t.Fatalf("older value: %+v %v", got, err)
	}
	body["no_authorisation_grace_s"] = 0
	zero, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(zero); err == nil || !strings.Contains(err.Error(), "no_authorisation_grace_s") {
		t.Fatalf("zero grace: %v", err)
	}
}
