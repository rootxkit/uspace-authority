package regimport

import (
	"os"
	"strings"
	"testing"
)

// The parsers never panic and never hand on what they refuse (go test
// -fuzz; the seeds run on every go test).

func FuzzParseRules(f *testing.F) {
	if b, err := os.ReadFile("testdata/rules.json"); err == nil {
		f.Add(b)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"rules_version":"x","format":"csv","date_formats":["YYYY"],"utc_offset":"+99:99"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRules(b)
		if err == nil && (r.offset == nil || len(r.layouts) == 0 || r.folded == nil) {
			t.Fatalf("accepted rules without their parsed parts: %+v", r)
		}
	})
}

func FuzzReadRecords(f *testing.F) {
	if b, err := os.ReadFile("testdata/operators.csv"); err == nil {
		f.Add(b, true)
	}
	f.Add([]byte(`[{"a":"1","b":2,"c":null}]`), false)
	f.Add([]byte("a;b\n\"x\n"), true)
	f.Add([]byte(`[{"a":{"b":1}}, 3]`), false)
	f.Fuzz(func(t *testing.T, b []byte, csv bool) {
		format := FormatJSON
		if csv {
			format = FormatCSV
		}
		recs, problems, err := ReadRecords(b, format, ';', 50)
		if err != nil {
			if recs != nil || problems != nil {
				t.Fatal("an unreadable file handed records on")
			}
			return
		}
		if len(recs) > 50 {
			t.Fatalf("%d records past the bound", len(recs))
		}
		for i, r := range recs {
			if r.N != i+1 {
				t.Fatalf("record %d numbered %d", i, r.N)
			}
			for k, v := range r.Values {
				if len(v) > MaxCellBytes || strings.TrimSpace(v) != v || k == "" && csv {
					t.Fatalf("value %q=%q", k, v)
				}
			}
		}
	})
}

func FuzzMap(f *testing.F) {
	rules, err := ParseRules(mustRead(f, "testdata/rules.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add("TEST-1", "GEOTEST00000001-x9z", "Physical person", "02.01.1980", "31.12.2030", "Active", "0.8")
	f.Add("", "GEO-", "x", "99.99.9999", "2030-02-30", "", "-1e309")
	f.Fuzz(func(t *testing.T, id, number, typ, born, until, st, mass string) {
		rec := Record{N: 1, Values: map[string]string{
			"Record ID": id, "Reg No": number, "Type": typ, "Born": born, "Expires": until, "Status": st,
			"Name": "Test Person", "Address": "1 Test Street", "E-mail": "a@example.test", "Phone": "+995 555 000 001",
		}}
		rows, problems := MapOperators(rules, []Record{rec})
		if len(rows)+min(1, len(problems)) != 1 {
			t.Fatalf("rows %d problems %d", len(rows), len(problems))
		}
		u := Record{N: 1, Values: map[string]string{"Record ID": id, "Serial": number, "Operator": number, "Mass kg": mass, "Status": st}}
		urows, uproblems := MapUAS(rules, []Record{u})
		if len(urows)+min(1, len(uproblems)) != 1 {
			t.Fatalf("uas rows %d problems %d", len(urows), len(uproblems))
		}
		for i := range urows {
			if m := urows[i].UAS.MTOMG; m != nil && *m <= 0 {
				t.Fatalf("mass %d", *m)
			}
		}
	})
}

func mustRead(f *testing.F, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	return b
}
