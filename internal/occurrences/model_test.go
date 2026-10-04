package occurrences

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-authority/api/gen"
)

// The ANSP's body is received as it marshals it: every member read, the
// times in UTC, the registration cut to its public part.
func TestNormaliseTheANSPBody(t *testing.T) {
	in := input(t, anspBody)
	if in.ReportRef != "ANSP-OCC-2026-0001" || in.Channel != ChannelMandatory || in.Category != "airprox" || in.ReporterOrg != "ansp-01" ||
		in.PersonRef != "staff-0042" || !in.OccurredAt.Equal(time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)) ||
		!in.BecameAwareAt.Equal(aware) || in.ReportedAt == nil || len(in.Aircraft) != 1 || in.Aircraft[0].Serial != "TEST1581F5FHD2344" ||
		in.Aircraft[0].OperatorReg != "FIN87astrdge12k8" || in.Manned[0].ICAO24 != "4ca7b5" || in.Manned[0].Callsign != "TST123" ||
		in.IntentRefs[0] != "2f8343be-6482-4d1b-a474-16847e01af1e" || *in.MinSeparation.HM != 180 || *in.MinSeparation.VM != 40 ||
		in.MinSeparation.At == nil || in.Narrative == "" || in.EvidenceURLs == nil {
		t.Fatalf("%+v", in)
	}
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "staff-0042") || strings.Contains(string(raw), "-xyz") {
		t.Fatalf("the input encodes the reference or the secret part: %s", raw)
	}
	// The minimum body: the required members only; lists are empty, not nil.
	minimal := `{"schema":"occurrence/v1","report_ref":"R-1","channel":"voluntary","occurred_at":"2026-10-03T10:00:00Z",` +
		`"became_aware_at":"2026-10-03T10:00:00Z","category":"other","future_member":{"x":1}}`
	m := input(t, minimal)
	if m.Aircraft == nil || m.Manned == nil || m.IntentRefs == nil || m.EvidenceURLs == nil || m.MinSeparation != nil || m.PersonRef != "" {
		t.Fatalf("%+v", m)
	}
}

// Every refusal names its member, beside the body it differs from by one
// thing (E-01: the base body above is accepted).
func TestNormaliseRefusesByName(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	items := func(n int, v any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	cases := map[string]func(m map[string]any){
		"schema":                func(m map[string]any) { m["schema"] = "occurrence/v2" },
		"report_ref":            func(m map[string]any) { m["report_ref"] = "  " },
		"channel":               func(m map[string]any) { m["channel"] = "gossip" },
		"category":              func(m map[string]any) { m["category"] = "ufo" },
		"occurred_at":           func(m map[string]any) { delete(m, "occurred_at") },
		"became_aware_at":       func(m map[string]any) { m["became_aware_at"] = "2026-10-03T09:00:00Z" },
		"reporter.person_ref":   func(m map[string]any) { m["reporter"] = map[string]any{"person_ref": long(MaxPersonRefBytes + 1)} },
		"reporter.org":          func(m map[string]any) { m["reporter"] = map[string]any{"org": long(MaxOrgBytes + 1)} },
		"aircraft":              func(m map[string]any) { m["aircraft"] = items(MaxItems+1, map[string]any{"serial": "TESTS"}) },
		"aircraft[0].serial":    func(m map[string]any) { m["aircraft"] = []any{map[string]any{"serial": long(MaxTextBytes + 1)}} },
		"aircraft[0].flight_id": func(m map[string]any) { m["aircraft"] = []any{map[string]any{"flight_id": "a\x00b"}} },
		"manned":                func(m map[string]any) { m["manned"] = items(MaxItems+1, map[string]any{}) },
		"manned[0].icao24":      func(m map[string]any) { m["manned"] = []any{map[string]any{"icao24": "4CA7B5"}} },
		"manned[0].callsign":    func(m map[string]any) { m["manned"] = []any{map[string]any{"callsign": long(MaxTextBytes + 1)}} },
		"intent_refs":           func(m map[string]any) { m["intent_refs"] = items(MaxItems+1, "r") },
		"intent_refs[0]":        func(m map[string]any) { m["intent_refs"] = []any{" "} },
		"min_separation.h_m":    func(m map[string]any) { m["min_separation"] = map[string]any{"h_m": -1} },
		"narrative":             func(m map[string]any) { m["narrative"] = long(MaxNarrativeBytes + 1) },
		"evidence_urls":         func(m map[string]any) { m["evidence_urls"] = items(MaxEvidenceURLs+1, "https://e.example.test/x") },
		"evidence_urls[0]":      func(m map[string]any) { m["evidence_urls"] = []any{"ftp://e.example.test/x"} },
	}
	for field, f := range cases {
		_, err := Normalise(decode(t, mutate(t, anspBody, f)), PublicPartOf(nil))
		if err == nil {
			t.Errorf("%s: accepted", field)
			continue
		}
		wantField(t, err, field)
		if strings.Contains(err.Error(), "staff-0042") {
			t.Errorf("%s: the reason echoes the reference: %v", field, err)
		}
	}
	if _, err := Normalise(nil, nil); err == nil {
		t.Fatal("no body accepted")
	}
}

// E-10: each bound is accepted at its value and refused one past it.
func TestNormaliseBoundsAtTheirValue(t *testing.T) {
	items := func(n int, v any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	at := map[string]func(m map[string]any){
		"aircraft":      func(m map[string]any) { m["aircraft"] = items(MaxItems, map[string]any{"serial": "TESTS"}) },
		"manned":        func(m map[string]any) { m["manned"] = items(MaxItems, map[string]any{"icao24": "4ca7b5"}) },
		"intent_refs":   func(m map[string]any) { m["intent_refs"] = items(MaxItems, strings.Repeat("r", MaxIntentRefBytes)) },
		"evidence_urls": func(m map[string]any) { m["evidence_urls"] = items(MaxEvidenceURLs, "https://e.example.test/x") },
		"narrative": func(m map[string]any) {
			m["narrative"] = strings.Repeat("ა", MaxNarrativeBytes/len("ა")) + "\nline two\ttab"[:0]
		},
		"person_ref": func(m map[string]any) {
			m["reporter"] = map[string]any{"person_ref": strings.Repeat("p", MaxPersonRefBytes)}
		},
	}
	for name, f := range at {
		if _, err := Normalise(decode(t, mutate(t, anspBody, f)), PublicPartOf(nil)); err != nil {
			t.Errorf("%s at its bound: %v", name, err)
		}
	}
	multi := mutate(t, anspBody, func(m map[string]any) { m["narrative"] = "line one\nline two\r\n\tindented" })
	if _, err := Normalise(decode(t, multi), nil); err != nil {
		t.Fatalf("a narrative with line breaks: %v", err)
	}
	ctrl := mutate(t, anspBody, func(m map[string]any) { m["narrative"] = "bell\x07" })
	if _, err := Normalise(decode(t, ctrl), nil); err == nil {
		t.Fatal("a control character in the narrative")
	}
}

// The content hash is the replay check: the same report hashes the same,
// any member changed changes it, and the person reference is never an
// input (only whether one was sent).
func TestContentHash(t *testing.T) {
	a, b := input(t, anspBody), input(t, anspBody)
	if ContentHash(&a) != ContentHash(&b) || !strings.HasPrefix(ContentHash(&a), "sha256:") {
		t.Fatal("the same report hashes differently")
	}
	b.PersonRef = "staff-0043"
	if ContentHash(&a) != ContentHash(&b) {
		t.Fatal("the person reference is hashed")
	}
	b.PersonRef = ""
	if ContentHash(&a) == ContentHash(&b) {
		t.Fatal("whether a person was sent is not hashed")
	}
	for name, f := range map[string]func(in *Input){
		"narrative":   func(in *Input) { in.Narrative += "." },
		"category":    func(in *Input) { in.Category = "other" },
		"aircraft":    func(in *Input) { in.Aircraft[0].Serial = "TESTOTHER" },
		"occurred_at": func(in *Input) { in.OccurredAt = in.OccurredAt.Add(time.Millisecond) },
		"separation":  func(in *Input) { in.MinSeparation = nil },
		"evidence":    func(in *Input) { in.EvidenceURLs = append(in.EvidenceURLs, "https://e.example.test/1") },
	} {
		c := input(t, anspBody)
		f(&c)
		if ContentHash(&a) == ContentHash(&c) {
			t.Errorf("%s changed, the hash did not", name)
		}
	}
}

// Fuzz the intake parser (LESSONS: fuzz parsers): whatever JSON arrives,
// Normalise either names a problem or returns an input that holds every
// bound, carries no NUL into PostgreSQL, hashes deterministically and
// exports as valid JSON.
func FuzzNormalise(f *testing.F) {
	f.Add([]byte(anspBody))
	f.Add([]byte(`{"schema":"occurrence/v1","report_ref":"R","channel":"voluntary","occurred_at":"2026-10-03T10:00:00Z","became_aware_at":"2026-10-03T10:00:00Z","category":"other"}`))
	f.Add([]byte(`{"schema":"occurrence/v1","report_ref":"\u0000","aircraft":[{"operator_reg":"GEO-TEST-1-abc"}],"min_separation":{"h_m":1e308}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep := decodeLoose(data)
		if rep == nil {
			return
		}
		in, err := Normalise(rep, PublicPartOf(nil))
		if err != nil {
			return
		}
		check := func(field, v string, maxBytes int) {
			if len(v) > maxBytes || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
				t.Fatalf("%s %q passed", field, v)
			}
		}
		check("report_ref", in.ReportRef, MaxReportRefBytes)
		check("narrative", in.Narrative, MaxNarrativeBytes)
		check("person_ref", in.PersonRef, MaxPersonRefBytes)
		if in.ReportRef == "" || len(in.Aircraft) > MaxItems || len(in.Manned) > MaxItems || len(in.IntentRefs) > MaxItems ||
			len(in.EvidenceURLs) > MaxEvidenceURLs || in.BecameAwareAt.Before(in.OccurredAt) {
			t.Fatalf("bounds: %+v", in)
		}
		for _, a := range in.Aircraft {
			for _, v := range []string{a.Serial, a.OperatorReg, a.FlightID, a.AuthorisationNumber} {
				check("aircraft", v, MaxTextBytes)
			}
		}
		for _, r := range in.IntentRefs {
			check("intent_ref", r, MaxIntentRefBytes)
		}
		again := in
		if ContentHash(&in) != ContentHash(&again) {
			t.Fatal("the hash is not deterministic")
		}
		out, err := ECCAIRSDraft{}.Export(ExportMeta{ExportID: ulidOf(1)}, []Report{{ID: ulidOf(1), Channel: in.Channel,
			Category: in.Category, Aircraft: in.Aircraft, Manned: in.Manned, MinSeparation: in.MinSeparation, Narrative: in.Narrative}})
		if err != nil || !json.Valid(out) {
			t.Fatalf("export: %v", err)
		}
	})
}

// decodeLoose decodes data as the strict server does, or nil.
func decodeLoose(data []byte) *gen.OccurrenceReport {
	var b gen.OccurrenceReport
	if json.Unmarshal(data, &b) != nil {
		return nil
	}
	return &b
}
