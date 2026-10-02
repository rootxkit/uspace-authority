package zonesvc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/ed318"
)

func testDesignation() *Designation {
	return &Designation{
		Name: "Tbilisi U-space (test)", ServicesRequired: []string{"NID", "GEO", "FA", "TI", "WX"},
		UASRequirements:       json.RawMessage(`{"remote_identification":"network and direct"}`),
		ServicePerformance:    json.RawMessage(`{"nid_update_hz":1,"ti_update_hz":1,"cis_latency_s":1,"fa_response_s":30}`),
		OperationalConditions: json.RawMessage(`{"night_operations":false}`),
		AirspaceConstraints:   json.RawMessage(`{"max_height_agl_m":120}`),
		AdjacentIDs:           []string{}, InControlledAirspace: true, DesignationRef: "TEST-DES-1",
	}
}

func uspaceIn(f string, d *Designation) DraftInput {
	return DraftInput{Feature: []byte(f), ValidFrom: ptr(t0), ValidTo: ptr(t1), Designation: d}
}

func uspaceFeature(id string) string {
	return feature(zoneOpts{identifier: id, typ: "USPACE", geometry: polygon(41.7, 44.8, 0.1, "AMSL")})
}

func TestDesignationRefusalsBesideTheAcceptance(t *testing.T) {
	if errs := checkDesignation(testDesignation(), "TSU001", "designation"); len(errs) != 0 {
		t.Fatalf("a complete designation: %v", errs)
	}
	cases := map[string]struct {
		edit   func(d *Designation)
		field  string
		reason string
	}{
		"missing FA":       {func(d *Designation) { d.ServicesRequired = []string{"NID", "GEO", "TI"} }, "services_required", "must include FA"},
		"unknown service":  {func(d *Designation) { d.ServicesRequired = append(d.ServicesRequired, "XX") }, "services_required[5]", "is not one of"},
		"repeated service": {func(d *Designation) { d.ServicesRequired = append(d.ServicesRequired, "NID") }, "services_required[5]", "twice"},
		"no nid rate": {func(d *Designation) { d.ServicePerformance = json.RawMessage(`{"ti_update_hz":1,"cis_latency_s":1}`) },
			"service_performance.nid_update_hz", "required"},
		"zero latency": {func(d *Designation) {
			d.ServicePerformance = json.RawMessage(`{"nid_update_hz":1,"ti_update_hz":1,"cis_latency_s":0}`)
		}, "service_performance.cis_latency_s", "above 0"},
		"ceiling zero":      {func(d *Designation) { d.AirspaceConstraints = json.RawMessage(`{"max_height_agl_m":0}`) }, "airspace_constraints.max_height_agl_m", "above 0"},
		"not an object":     {func(d *Designation) { d.UASRequirements = json.RawMessage(`[1]`) }, "uas_requirements", "JSON object"},
		"absent block":      {func(d *Designation) { d.OperationalConditions = nil }, "operational_conditions", "required"},
		"no name":           {func(d *Designation) { d.Name = "" }, "airspace_name", "required"},
		"adjacent self":     {func(d *Designation) { d.AdjacentIDs = []string{"TSU001"} }, "adjacent_ids[0]", "itself"},
		"adjacent too long": {func(d *Designation) { d.AdjacentIDs = []string{"TOOLONG1"} }, "adjacent_ids[0]", "1 to 7"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := testDesignation()
			c.edit(d)
			errs := checkDesignation(d, "TSU001", "designation")
			for _, e := range errs {
				if strings.HasSuffix(e.Field, c.field) && strings.Contains(e.Reason, c.reason) {
					return
				}
			}
			t.Fatalf("%v, want %s: %s", errs, c.field, c.reason)
		})
	}
}

func TestUSpaceDraftWritesTheRequirementsBlockFromTheDesignation(t *testing.T) {
	s, _, _, _ := newService(t)
	v, err := s.Draft(context.Background(), DatasetUSpace, uspaceIn(uspaceFeature("TSU001"), testDesignation()), true, admin)
	if err != nil {
		t.Fatal(err)
	}
	if v.Dataset != DatasetUSpace || v.Designation == nil || v.Type != "USPACE" {
		t.Fatalf("%+v", v)
	}
	block := requirementsOf(t, v.Feature)
	if errs := validateAgainst(t, cispSchema(t), "#", block); len(errs) > 0 {
		t.Fatalf("the block does not validate against the CISP's cis/uspace_requirements/v1: %v\n%s", errs, block)
	}
	// A feature that carries the block itself is refused: the block is
	// written from the designation only.
	withBlock := feature(zoneOpts{identifier: "TSU002", typ: "USPACE", extended: `{"uspace_requirements":{}}`})
	_, err = s.Draft(context.Background(), DatasetUSpace, uspaceIn(withBlock, testDesignation()), true, admin)
	mustProblem(t, err, http.StatusBadRequest, "extendedProperties.uspace_requirements", "written from designation")
	// Without a designation the draft is refused.
	_, err = s.Draft(context.Background(), DatasetUSpace, uspaceIn(uspaceFeature("TSU003"), nil), true, admin)
	mustProblem(t, err, http.StatusBadRequest, "designation", "required")
}

// requirementsOf is the stored feature's block.
func requirementsOf(t *testing.T, feature json.RawMessage) json.RawMessage {
	t.Helper()
	var w struct {
		Properties struct {
			ExtendedProperties map[string]json.RawMessage `json:"extendedProperties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(feature, &w); err != nil {
		t.Fatal(err)
	}
	b, ok := w.Properties.ExtendedProperties[RequirementsKey]
	if !ok {
		t.Fatalf("no %s in %s", RequirementsKey, feature)
	}
	return b
}

func TestUSpacePublicationRefusesAnAdjacentAirspaceNotInIt(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	d := testDesignation()
	d.AdjacentIDs = []string{"TSU002"}
	v, err := s.Draft(ctx, DatasetUSpace, uspaceIn(uspaceFeature("TSU001"), d), true, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetUSpace, "TSU001", v.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	_, err = s.Publish(ctx, DatasetUSpace, admin)
	mustProblem(t, err, http.StatusConflict, "TSU001.designation.adjacent_ids[0]", `"TSU002" is not a U-space airspace in force`)
	if len(st.publications()) != 0 {
		t.Fatal("a refused publication was queued")
	}
	// Designating the neighbour too makes the publication whole.
	d2 := testDesignation()
	d2.AdjacentIDs = []string{"TSU001"}
	if _, err := s.Draft(ctx, DatasetUSpace, uspaceIn(uspaceFeature("TSU002"), d2), true, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetUSpace, "TSU002", 1, admin); err != nil {
		t.Fatal(err)
	}
	p, err := s.Publish(ctx, DatasetUSpace, admin)
	if err != nil || p.Publication.FeatureCount != 2 || p.Dataset != DatasetUSpace {
		t.Fatalf("%v %+v", err, p)
	}
	fc, probs := ed318.Parse(st.payload(p.Publication.ID), ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	for _, f := range fc.Features {
		if errs := validateAgainst(t, cispSchema(t), "#", f.Properties.ExtendedProperties[RequirementsKey]); len(errs) > 0 {
			t.Fatalf("%s: %v", f.Properties.Identifier, errs)
		}
	}
}

// The CISP's cis/uspace_requirements/v1, pinned in testdata/cisp with
// its SOURCE (M7: the CISP owns the shape).
func cispSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/cisp/uspace_requirements.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// validateAgainst checks raw against the subset of JSON Schema the
// pinned schema uses (type, required, properties, additionalProperties
// false, items, enum, minItems, maxItems, uniqueItems, minLength,
// maxLength, exclusiveMinimum, local $ref). A keyword outside the
// subset fails the test, so a schema bump cannot be half-checked.
func validateAgainst(t *testing.T, root map[string]any, path string, raw json.RawMessage) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{path + ": not JSON"}
	}
	return check(t, root, root, path, v)
}

var knownKeywords = []string{"$defs", "$id", "$schema", "title", "description", "format", "type", "required", "properties",
	"additionalProperties", "items", "enum", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "exclusiveMinimum", "$ref"}

func check(t *testing.T, root, s map[string]any, path string, v any) []string {
	t.Helper()
	for k := range s {
		if !slices.Contains(knownKeywords, k) {
			t.Fatalf("schema keyword %q at %s is not checked by this test", k, path)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		return check(t, root, root["$defs"].(map[string]any)[name].(map[string]any), path, v)
	}
	var errs []string
	switch s["type"] {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return []string{path + ": not an object"}
		}
		for _, r := range asList(s["required"]) {
			if _, ok := m[r.(string)]; !ok {
				errs = append(errs, fmt.Sprintf("%s.%s: required", path, r))
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, x := range m {
			ps, ok := props[k].(map[string]any)
			if !ok {
				if s["additionalProperties"] == false {
					errs = append(errs, fmt.Sprintf("%s.%s: not allowed", path, k))
				}
				continue
			}
			errs = append(errs, check(t, root, ps, path+"."+k, x)...)
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return []string{path + ": not an array"}
		}
		if n, ok := s["minItems"].(float64); ok && float64(len(a)) < n {
			errs = append(errs, path+": too few items")
		}
		if n, ok := s["maxItems"].(float64); ok && float64(len(a)) > n {
			errs = append(errs, path+": too many items")
		}
		seen := map[string]bool{}
		for i, x := range a {
			b, _ := json.Marshal(x)
			if s["uniqueItems"] == true && seen[string(b)] {
				errs = append(errs, fmt.Sprintf("%s[%d]: repeated", path, i))
			}
			seen[string(b)] = true
			if is, ok := s["items"].(map[string]any); ok {
				errs = append(errs, check(t, root, is, fmt.Sprintf("%s[%d]", path, i), x)...)
			}
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			return []string{path + ": not a string"}
		}
		n := float64(utf8.RuneCountInString(str))
		if m, ok := s["minLength"].(float64); ok && n < m {
			errs = append(errs, path+": too short")
		}
		if m, ok := s["maxLength"].(float64); ok && n > m {
			errs = append(errs, path+": too long")
		}
		if e := asList(s["enum"]); e != nil && !slices.Contains(e, any(str)) {
			errs = append(errs, path+": not in the enumeration")
		}
	case "number":
		f, ok := v.(float64)
		if !ok {
			return []string{path + ": not a number"}
		}
		if m, ok := s["exclusiveMinimum"].(float64); ok && f <= m {
			errs = append(errs, path+": not above the minimum")
		}
	}
	return errs
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// The schema check finds what it should (E-01): a block missing a
// required member, with an unknown member and a service outside the
// enumeration is refused, naming each.
func TestSchemaCheckFindsPlantedErrors(t *testing.T) {
	bad := json.RawMessage(`{"uas_requirements":{},"service_performance":{"nid_update_hz":0,"ti_update_hz":1,"cis_latency_s":1},
		"operational_conditions":{},"services_required":["NID","GEO","FA","XX"],"adjacent":[],"colour":"red"}`)
	errs := validateAgainst(t, cispSchema(t), "#", bad)
	for _, want := range []string{"#.airspace_constraints: required", "#.colour: not allowed", "#.services_required[3]: not in the enumeration",
		"#.service_performance.nid_update_hz: not above the minimum"} {
		if !slices.Contains(errs, want) {
			t.Errorf("missing %q in %v", want, errs)
		}
	}
}
