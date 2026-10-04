package regimport

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/registry"
)

func records(t *testing.T, name string) []Record {
	t.Helper()
	recs, _, err := ReadRecords(readFile(t, name), FormatCSV, ';', 100)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func fields(ps []*core.FieldError) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Field)
	}
	return out
}

func TestMapOperatorsUnderTheRules(t *testing.T) {
	rows, problems := MapOperators(testRules(t), records(t, "operators.csv"))
	if len(problems) != 0 || len(rows) != 2 {
		t.Fatalf("%v %d", problems, len(rows))
	}
	a, b := rows[0], rows[1]
	tbilisi := time.FixedZone("+04:00", 4*3600)
	// The secret suffix is split off; a date-only valid_until is valid
	// through that day at the rules' offset.
	if a.SourceRef != "TEST-OP-1" || a.Operator.RegistrationNumber != "GEOTEST00000001" || a.Operator.SecretPart != "x9z" {
		t.Fatalf("%+v", a)
	}
	if !a.Operator.ValidUntil.Equal(time.Date(2031, 1, 1, 0, 0, 0, 0, tbilisi)) ||
		!a.Operator.ValidFrom.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, tbilisi)) {
		t.Fatalf("validity %v %v", a.Operator.ValidFrom, a.Operator.ValidUntil)
	}
	if a.Operator.OperatorType != registry.OperatorNatural || a.Operator.PII.DateOfBirth != "1980-01-02" || a.Status != registry.StatusActive {
		t.Fatalf("%+v", a.Operator)
	}
	if b.Operator.OperatorType != registry.OperatorLegal || !b.Operator.CompetencyConfirmation || b.Status != registry.StatusSuspended ||
		b.Operator.SecretPart != "" {
		t.Fatalf("%+v", b)
	}
}

// Every mapping problem beside a record that maps: the record with the
// problem is left out, the others are kept.
func TestMapOperatorsNamesEveryProblem(t *testing.T) {
	r := testRules(t)
	base := records(t, "operators.csv")[0].Values
	with := func(col, v string) Record {
		vals := map[string]string{}
		for k, x := range base {
			vals[k] = x
		}
		if v == "<absent>" {
			delete(vals, col)
		} else {
			vals[col] = v
		}
		return Record{N: 2, Values: vals}
	}
	cases := []struct {
		col, value, field, reason string
	}{
		{"Type", "Robot", "records[2].operator_type", `no mapping`},
		{"Status", "Lost", "records[2].status", `no mapping`},
		{"Expires", "2030/12/31", "records[2].valid_until", "date_formats"},
		{"Expires", "<absent>", "records[2].valid_until", "required"},
		{"Born", "02-01-1980 10:00", "records[2].date_of_birth", "date-only"},
		{"Reg No", "GEO-1", "records[2].registration_number", "registration_number_pattern"},
		{"Record ID", "", "records[2].source_id", "required"},
		{"Competency", "maybe", "records[2].competency_confirmation", "no mapping"},
	}
	for _, c := range cases {
		t.Run(c.field+"/"+c.value, func(t *testing.T) {
			rows, problems := MapOperators(r, []Record{{N: 1, Values: base}, with(c.col, c.value)})
			if len(rows) != 1 || rows[0].Record != 1 {
				t.Fatalf("rows %+v", rows)
			}
			if len(problems) == 0 || problems[0].Field != c.field || !strings.Contains(problems[0].Reason, c.reason) {
				t.Fatalf("problems %+v", problems)
			}
			if col := r.Operators.Columns[strings.TrimPrefix(c.field, "records[2].")]; !strings.Contains(problems[0].Reason, `column "`+col+`"`) {
				t.Fatalf("the column is not named: %+v", problems[0])
			}
		})
	}
	// The status default applies when the column is empty.
	rows, problems := MapOperators(r, []Record{with("Status", "")})
	if len(problems) != 0 || rows[0].Status != registry.StatusActive {
		t.Fatalf("default: %+v %v", rows, problems)
	}
}

func TestMapUASUnderTheRules(t *testing.T) {
	rows, problems := MapUAS(testRules(t), records(t, "uas.csv"))
	if len(problems) != 0 || len(rows) != 2 {
		t.Fatalf("%v %d", problems, len(rows))
	}
	a, b := rows[0], rows[1]
	if a.OperatorNumber != "GEOTEST00000001" || a.UAS.ClassLabel != "C1" || *a.UAS.MTOMG != 800 || a.UAS.RIDCapability != "direct" {
		t.Fatalf("%+v", a)
	}
	// An empty Remote ID cell takes the default; "none" maps to no label.
	if b.UAS.ClassLabel != "" || *b.UAS.MTOMG != 2500 || b.UAS.RIDCapability != "none" {
		t.Fatalf("%+v", b.UAS)
	}
	bad := records(t, "uas.csv")
	bad[0].Values["Mass kg"] = "0.0005"
	bad[1].Values["Mass kg"] = "-1"
	rows, problems = MapUAS(testRules(t), bad)
	if len(rows) != 0 || !slices.Equal(fields(problems), []string{"records[1].mtom", "records[2].mtom"}) {
		t.Fatalf("%+v %v", rows, fields(problems))
	}
}

func TestCutSecret(t *testing.T) {
	for in, want := range map[string][2]string{
		"GEOTEST00000001-x9z": {"GEOTEST00000001", "x9z"},
		"GEOTEST00000001-x9":  {"", ""},
		"GEOTEST00000001-x-z": {"", ""},
		"-abc":                {"", ""},
	} {
		h, s, _ := cutSecret(in)
		if h != want[0] || s != want[1] {
			t.Errorf("%q: %q %q", in, h, s)
		}
	}
}
