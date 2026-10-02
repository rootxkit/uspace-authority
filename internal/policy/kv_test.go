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

// The schema names exactly the members of ActiveBody (the thresholds
// flattened), every one required.
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
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	req := slices.Clone(s.Defs["body"].Required)
	slices.Sort(req)
	if !slices.Equal(names, req) || len(s.Defs["body"].Properties) != len(names) {
		t.Fatalf("struct %v, schema %v", names, req)
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
