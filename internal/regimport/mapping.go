package regimport

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/registry"
)

// mapper maps the records of one kind under the rules, collecting every
// problem by record and field.
type mapper struct {
	r        *Rules
	e        *EntityRules
	kind     string
	problems []*core.FieldError
	rec      *Record
	bad      bool
}

func (m *mapper) fail(field, format string, args ...any) {
	reason := fmt.Sprintf(format, args...)
	if col, ok := m.e.Columns[field]; ok {
		reason = fmt.Sprintf("column %q: %s", col, reason)
	}
	m.problems = append(m.problems, &core.FieldError{Field: fmt.Sprintf("records[%d].%s", m.rec.N, field), Reason: reason})
	m.bad = true
}

// raw is the field's value: the column's text, else the default; ok is
// false when neither gives one. fromColumn says which.
func (m *mapper) raw(field string) (v string, fromColumn, ok bool) {
	if col, mapped := m.e.Columns[field]; mapped {
		if v, present := m.rec.Values[col]; present && v != "" {
			return v, true, true
		}
	}
	if d, has := m.e.Defaults[field]; has {
		return d, false, true
	}
	return "", false, false
}

// text is the field's value with its values map applied to a column's
// text. A text the map does not name is a problem: nothing is guessed.
func (m *mapper) text(field string) string {
	v, fromColumn, ok := m.raw(field)
	if !ok {
		return ""
	}
	if vm, has := m.r.folded[m.kind][field]; has && fromColumn {
		to, found := vm[foldKey(v)]
		if !found {
			m.fail(field, "value %q has no mapping in the rules file (values.%s)", v, field)
			return ""
		}
		return to
	}
	return v
}

func (m *mapper) required(field string) string {
	v := m.text(field)
	if v == "" && !m.failedOn(field) {
		m.fail(field, "required")
	}
	return v
}

func (m *mapper) failedOn(field string) bool {
	want := fmt.Sprintf("records[%d].%s", m.rec.N, field)
	for _, p := range m.problems {
		if p.Field == want {
			return true
		}
	}
	return false
}

// date parses a date or time under the rules' formats. A date without a
// time is the start of that day at the rules' offset, or with endOfDay
// the start of the next (a registration valid until a day is valid
// through it).
func (m *mapper) date(field string, endOfDay bool) (time.Time, bool) {
	v := m.text(field)
	if v == "" {
		return time.Time{}, false
	}
	for _, l := range m.r.layouts {
		var t time.Time
		var err error
		if l.hasZone {
			t, err = time.Parse(l.goLayout, v)
		} else {
			t, err = time.ParseInLocation(l.goLayout, v, m.r.offset)
		}
		if err != nil {
			continue
		}
		if !l.hasTime && endOfDay {
			t = t.AddDate(0, 0, 1)
		}
		return t.UTC(), true
	}
	m.fail(field, "%q matches none of the rules' date_formats", v)
	return time.Time{}, false
}

// dateOnly is a date as the registry stores a date of birth.
func (m *mapper) dateOnly(field string) string {
	v := m.text(field)
	if v == "" {
		return ""
	}
	for _, l := range m.r.layouts {
		if l.hasTime {
			continue
		}
		if t, err := time.Parse(l.goLayout, v); err == nil {
			return t.Format(time.DateOnly)
		}
	}
	m.fail(field, "%q matches none of the rules' date-only formats", v)
	return ""
}

func (m *mapper) boolean(field string) bool {
	v := m.text(field)
	switch v {
	case "", "false":
		return false
	case "true":
		return true
	}
	m.fail(field, "%q is not true or false (map it under values.%s)", v, field)
	return false
}

// number reads the registration number, checks it against the export's
// pattern and splits an EU secret suffix when the rules say so.
func (m *mapper) number(field string) (public, secret string) {
	v := m.required(field)
	if v == "" {
		return "", ""
	}
	if m.r.SecretSuffix {
		if head, tail, ok := cutSecret(v); ok {
			v, secret = head, tail
		}
	}
	if m.r.pattern != nil && !m.r.pattern.MatchString(v) {
		m.fail(field, "%q does not follow the export's registration_number_pattern", v)
	}
	return v, secret
}

// cutSecret splits "<public>-<three ASCII letters or digits>".
func cutSecret(v string) (head, tail string, ok bool) {
	i := strings.LastIndexByte(v, '-')
	if i <= 0 || len(v)-i-1 != 3 {
		return "", "", false
	}
	for _, c := range []byte(v[i+1:]) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return "", "", false
		}
	}
	return v[:i], v[i+1:], true
}

// MapOperators maps CSV or JSON records onto registry operators. The
// records with a problem are left out of rows; every problem is in
// problems.
func MapOperators(r *Rules, recs []Record) (rows []registry.ImportedOperator, problems []*core.FieldError) {
	m := &mapper{r: r, e: &r.Operators, kind: "operators"}
	for i := range recs {
		m.rec, m.bad = &recs[i], false
		ref := m.required("source_id")
		number, secret := m.number("registration_number")
		if s := m.text("secret_part"); s != "" {
			secret = s
		}
		op := registry.NewOperator{
			OperatorType: m.required("operator_type"), RegistrationNumber: number, SecretPart: secret,
			PII: registry.OperatorPII{
				FullName: m.text("full_name"), LegalName: m.text("legal_name"), DateOfBirth: m.dateOnly("date_of_birth"),
				LegalIdentificationNumber: m.text("legal_identification_number"), PostalAddress: m.text("postal_address"),
				ContactEmail: m.text("contact_email"), ContactPhone: m.text("contact_phone"),
				InsurancePolicyNumber: m.text("insurance_policy_number"),
			},
			CompetencyConfirmation: m.boolean("competency_confirmation"),
			Authorisations:         json.RawMessage("[]"),
		}
		if t, ok := m.date("valid_from", false); ok {
			op.ValidFrom = t
		}
		if t, ok := m.date("valid_until", true); ok {
			op.ValidUntil = t
		} else if !m.failedOn("valid_until") {
			m.fail("valid_until", "required")
		}
		st := m.required("status")
		if m.bad {
			continue
		}
		rows = append(rows, registry.ImportedOperator{Record: m.rec.N, SourceRef: ref, Operator: op, Status: registry.Status(st)})
	}
	return rows, m.problems
}

// mtomG reads the mass in the rules' unit as whole grams.
func (m *mapper) mtomG(field string) *int {
	v := m.text(field)
	if v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		m.fail(field, "%q is not a positive number", v)
		return nil
	}
	if m.r.MTOMUnit == "kg" {
		f *= 1000
	}
	g := math.Round(f)
	if math.Abs(f-g) > 1e-6 || g > math.MaxInt32 {
		m.fail(field, "%q is not a whole number of grams", v)
		return nil
	}
	n := int(g)
	return &n
}

// MapUAS maps records onto registry aircraft, as MapOperators does.
func MapUAS(r *Rules, recs []Record) (rows []registry.ImportedUAS, problems []*core.FieldError) {
	m := &mapper{r: r, e: &r.UAS, kind: "uas"}
	for i := range recs {
		m.rec, m.bad = &recs[i], false
		ref := m.required("source_id")
		u := registry.NewUAS{
			Serial: m.required("serial"), RegistrationMark: m.text("registration_mark"), Manufacturer: m.text("manufacturer"),
			Model: m.text("model"), OwnerRef: m.text("owner_ref"), ClassLabel: m.text("class_label"), MTOMG: m.mtomG("mtom"),
			RIDCapability: m.required("rid_capability"),
		}
		owner, _ := m.number("operator_registration_number")
		st := m.required("status")
		if m.bad {
			continue
		}
		rows = append(rows, registry.ImportedUAS{Record: m.rec.N, SourceRef: ref, OperatorNumber: owner, UAS: u, Status: registry.Status(st)})
	}
	return rows, m.problems
}
