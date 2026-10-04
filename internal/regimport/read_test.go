package regimport

import (
	"fmt"
	"strings"
	"testing"
)

func TestReadCSV(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, readFile(t, "operators.csv")...)
	recs, problems, err := ReadRecords(body, FormatCSV, ';', 10)
	if err != nil || len(problems) != 0 || len(recs) != 2 {
		t.Fatalf("%v %v %d", err, problems, len(recs))
	}
	if recs[0].N != 1 || recs[0].Values["Record ID"] != "TEST-OP-1" || recs[1].Values["Company"] != "Test Aerial LLC" {
		t.Fatalf("%+v", recs)
	}
}

func TestReadCSVRefusesWhatItCannotRead(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"empty header":     "a;;b\n1;2;3\n",
		"duplicate header": "a;a\n1;2\n",
		"ragged":           "a;b\n1;2\n3\n",
		"quote":            "a;b\n\"1;2\n",
		"long cell":        "a\n" + strings.Repeat("x", MaxCellBytes+1) + "\n",
		"not utf-8":        "a\n\xff\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ReadRecords([]byte(body), FormatCSV, ';', 10); err == nil {
				t.Fatal("read")
			}
		})
	}
}

// E-10: the record bound is exceeded by one and met exactly.
func TestReadBoundsTheRecords(t *testing.T) {
	var b strings.Builder
	b.WriteString("a\n")
	for i := range 3 {
		fmt.Fprintf(&b, "%d\n", i)
	}
	if _, _, err := ReadRecords([]byte(b.String()), FormatCSV, ',', 2); err == nil || !strings.Contains(err.Error(), "more than 2") {
		t.Fatalf("past the bound: %v", err)
	}
	if recs, _, err := ReadRecords([]byte(b.String()), FormatCSV, ',', 3); err != nil || len(recs) != 3 {
		t.Fatalf("at the bound: %v", err)
	}
	js := `[{"a":1},{"a":2},{"a":3}]`
	if _, _, err := ReadRecords([]byte(js), FormatJSON, 0, 2); err == nil {
		t.Fatal("JSON past the bound")
	}
	if recs, _, err := ReadRecords([]byte(js), FormatJSON, 0, 3); err != nil || len(recs) != 3 {
		t.Fatalf("JSON at the bound: %v", err)
	}
}

func TestReadJSON(t *testing.T) {
	body := `[{"id": "TEST-1", "mass": 12345678901234567890, "ok": true, "gone": null, "name": " Test "}, {"id": "TEST-2", "nested": {"a": 1}}]`
	recs, problems, err := ReadRecords([]byte(body), FormatJSON, 0, 10)
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %d", err, len(recs))
	}
	v := recs[0].Values
	// A number is kept as written, never through a float.
	if v["mass"] != "12345678901234567890" || v["ok"] != "true" || v["name"] != "Test" {
		t.Fatalf("%+v", v)
	}
	if _, present := v["gone"]; present {
		t.Fatal("null is present")
	}
	if len(problems) != 1 || problems[0].Field != "records[2]" || !strings.Contains(problems[0].Reason, "nested") {
		t.Fatalf("problems %+v", problems)
	}
	for name, bad := range map[string]string{"object": `{"a":1}`, "trailing": `[] []`, "unclosed": `[{"a":1}`, "not json": `x`, "array member": `[1]`} {
		if _, _, err := ReadRecords([]byte(bad), FormatJSON, 0, 10); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, _, err := ReadRecords([]byte("[]"), "xml", 0, 10); err == nil {
		t.Fatal("an unknown format was read")
	}
}
