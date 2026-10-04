package occurrences

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaPath = "../../schemas/occurrence/v1.json"

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

func compileSchema(t *testing.T) (*jsonschema.Schema, map[string]any) {
	t.Helper()
	raw := readFile(t, schemaPath)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	m := doc.(map[string]any)
	if m["$id"] != "https://schemas.uspace.ge/occurrence/v1.json" {
		t.Fatalf("$id %v", m["$id"])
	}
	if err := c.AddResource(m["$id"].(string), doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(m["$id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

func validateJSON(t *testing.T, s *jsonschema.Schema, body string) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst)
}

// schemas/occurrence/v1.json (owned here, M14): every example validates
// and is received by the intake; the body the ANSP posts validates; a
// body that differs from an accepted one by one member is refused by the
// schema (E-01). Run by the contract job.
func TestOccurrenceSchemaExamples(t *testing.T) {
	s, m := compileSchema(t)
	examples, _ := m["examples"].([]any)
	if len(examples) < 3 {
		t.Fatalf("%d examples", len(examples))
	}
	for i, ex := range examples {
		b, err := json.Marshal(ex)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateJSON(t, s, string(b)); err != nil {
			t.Errorf("example %d: %v", i, err)
		}
		if _, err := Normalise(decode(t, string(b)), PublicPartOf(nil)); err != nil {
			t.Errorf("example %d is refused by the intake: %v", i, err)
		}
	}
	if err := validateJSON(t, s, anspBody); err != nil {
		t.Fatalf("the ANSP's body: %v", err)
	}
	future := mutate(t, anspBody, func(m map[string]any) { m["a_later_member"] = true })
	if err := validateJSON(t, s, future); err != nil {
		t.Fatalf("an unknown member is refused: %v", err)
	}
	for name, f := range map[string]func(m map[string]any){
		"no report_ref":       func(m map[string]any) { delete(m, "report_ref") },
		"another schema":      func(m map[string]any) { m["schema"] = "occurrence/v2" },
		"a channel":           func(m map[string]any) { m["channel"] = "gossip" },
		"a category":          func(m map[string]any) { m["category"] = "ufo" },
		"a time":              func(m map[string]any) { m["occurred_at"] = "yesterday" },
		"51 aircraft":         func(m map[string]any) { m["aircraft"] = make([]any, 51) },
		"an icao24":           func(m map[string]any) { m["manned"] = []any{map[string]any{"icao24": "4CA7B5"}} },
		"a negative distance": func(m map[string]any) { m["min_separation"] = map[string]any{"h_m": -1} },
		"a long person_ref":   func(m map[string]any) { m["reporter"] = map[string]any{"person_ref": strings.Repeat("p", 129)} },
		"21 evidence urls":    func(m map[string]any) { m["evidence_urls"] = slices.Repeat([]any{"https://e.example.test/x"}, 21) },
		"a non-http url":      func(m map[string]any) { m["evidence_urls"] = []any{"ftp://e.example.test/x"} },
	} {
		if err := validateJSON(t, s, mutate(t, anspBody, f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

var (
	propLine = regexp.MustCompile(`^        ([a-z0-9_]+):`)
	reqLine  = regexp.MustCompile(`^      required: \[([^\]]*)\]`)
)

// openAPISchema returns the property names and required list of
// components.schemas.<name> in api/openapi.yaml.
func openAPISchema(t *testing.T, spec, name string) (props, required []string) {
	t.Helper()
	start := strings.Index(spec, "\n    "+name+":\n")
	if start < 0 {
		t.Fatalf("no schema %s", name)
	}
	lines := strings.Split(spec[start+1:], "\n")
	inProps := false
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "     ") {
			break
		}
		switch {
		case l == "      properties:":
			inProps = true
		case strings.HasPrefix(l, "      ") && !strings.HasPrefix(l, "       "):
			inProps = false
			if m := reqLine.FindStringSubmatch(l); m != nil {
				for r := range strings.SplitSeq(m[1], ",") {
					required = append(required, strings.TrimSpace(r))
				}
			}
		case inProps:
			if m := propLine.FindStringSubmatch(l); m != nil {
				props = append(props, m[1])
			}
		}
	}
	slices.Sort(props)
	slices.Sort(required)
	return props, required
}

func jsonProps(t *testing.T, node map[string]any) []string {
	t.Helper()
	p, ok := node["properties"].(map[string]any)
	if !ok {
		t.Fatalf("no properties in %v", node)
	}
	return slices.Sorted(maps.Keys(p))
}

// The schema file and the contract's request body are one shape: the
// same members at every level and the same required list.
func TestOccurrenceSchemaMatchesTheContract(t *testing.T) {
	_, m := compileSchema(t)
	spec := string(readFile(t, "../../api/openapi.yaml"))
	top := m["properties"].(map[string]any)
	item := func(name string) map[string]any { return top[name].(map[string]any)["items"].(map[string]any) }
	for _, c := range []struct {
		openapi string
		node    map[string]any
	}{
		{"OccurrenceReport", m},
		{"OccurrenceReporterInput", top["reporter"].(map[string]any)},
		{"OccurrenceAircraftInput", item("aircraft")},
		{"OccurrenceManned", item("manned")},
		{"OccurrenceSeparation", top["min_separation"].(map[string]any)},
	} {
		props, required := openAPISchema(t, spec, c.openapi)
		if got := jsonProps(t, c.node); !slices.Equal(got, props) {
			t.Errorf("%s: schema file %v, contract %v", c.openapi, got, props)
		}
		var req []string
		if r, ok := c.node["required"].([]any); ok {
			for _, v := range r {
				req = append(req, v.(string))
			}
		}
		slices.Sort(req)
		if !slices.Equal(req, required) {
			t.Errorf("%s: required %v, contract %v", c.openapi, req, required)
		}
	}
	// E-01: the comparison sees a difference when there is one.
	if props, _ := openAPISchema(t, "\n    X:\n      properties:\n        a: {type: string}\n        b: {type: string}\n", "X"); !slices.Equal(props, []string{"a", "b"}) {
		t.Fatalf("parsed %v", props)
	}
}
