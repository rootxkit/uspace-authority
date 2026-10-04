package regimport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
)

// MaxCellBytes bounds one value of an export (E-10).
const MaxCellBytes = 4096

// MaxColumns bounds the columns of an export.
const MaxColumns = 256

// Record is one record of an export: its 1-based number (the first
// after a CSV header is 1) and its values by column, trimmed. A column
// absent from a JSON object is absent from Values.
type Record struct {
	N      int
	Values map[string]string
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadRecords reads an export of format (csv or json) holding at most
// maxRecords records. A file that cannot be read as that format is an
// error naming where (body, line or record); a record whose value
// cannot be read is a problem of that record, so the rest are still
// checked.
func ReadRecords(body []byte, format string, delimiter rune, maxRecords int) ([]Record, []*core.FieldError, error) {
	if !utf8.Valid(body) {
		return nil, nil, core.Fieldf("body", "not UTF-8")
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	switch format {
	case FormatCSV:
		recs, err := readCSV(body, delimiter, maxRecords)
		return recs, nil, err
	case FormatJSON:
		return readJSON(body, maxRecords)
	}
	return nil, nil, core.Fieldf("format", "must be csv or json")
}

func readCSV(body []byte, delimiter rune, maxRecords int) ([]Record, error) {
	r := csv.NewReader(bytes.NewReader(body))
	if delimiter != 0 {
		r.Comma = delimiter
	}
	r.FieldsPerRecord = 0
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, core.Fieldf("body", "empty: a header row is required")
	}
	if err != nil {
		return nil, csvError(err)
	}
	if len(header) > MaxColumns {
		return nil, core.Fieldf("body", "%d columns, at most %d", len(header), MaxColumns)
	}
	seen := map[string]bool{}
	for i, h := range header {
		h = strings.TrimSpace(h)
		header[i] = h
		switch {
		case h == "":
			return nil, core.Fieldf("body", "header column %d is empty", i+1)
		case seen[h]:
			return nil, core.Fieldf("body", "header column %q is given twice", h)
		}
		seen[h] = true
	}
	var out []Record
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, csvError(err)
		}
		if len(out) == maxRecords {
			return nil, core.Fieldf("body", "more than %d records (REGISTRY_IMPORT_MAX_ROWS)", maxRecords)
		}
		rec := Record{N: len(out) + 1, Values: make(map[string]string, len(header))}
		for i, v := range row {
			if len(v) > MaxCellBytes {
				line, _ := r.FieldPos(i)
				return nil, core.Fieldf("body", "line %d: a value longer than %d bytes", line, MaxCellBytes)
			}
			rec.Values[header[i]] = strings.TrimSpace(v)
		}
		out = append(out, rec)
	}
}

func csvError(err error) error {
	var pe *csv.ParseError
	if errors.As(err, &pe) {
		return core.Fieldf("body", "line %d: %v", pe.Line, pe.Err)
	}
	return core.Fieldf("body", "not CSV: %v", err)
}

// readJSON reads an array of flat objects: each value a string, a
// number (kept as written), a boolean or null (absent).
func readJSON(body []byte, maxRecords int) ([]Record, []*core.FieldError, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, core.Fieldf("body", "not JSON: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, nil, core.Fieldf("body", "must be a JSON array of objects")
	}
	var out []Record
	var problems []*core.FieldError
	for dec.More() {
		if len(out) == maxRecords {
			return nil, nil, core.Fieldf("body", "more than %d records (REGISTRY_IMPORT_MAX_ROWS)", maxRecords)
		}
		n := len(out) + 1
		var obj map[string]json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			return nil, nil, core.Fieldf(fmt.Sprintf("records[%d]", n), "not a JSON object: %v", err)
		}
		if len(obj) > MaxColumns {
			return nil, nil, core.Fieldf(fmt.Sprintf("records[%d]", n), "%d members, at most %d", len(obj), MaxColumns)
		}
		rec := Record{N: n, Values: make(map[string]string, len(obj))}
		for k, raw := range obj {
			v, present, err := scalar(raw)
			if err != nil {
				problems = append(problems, core.Fieldf(fmt.Sprintf("records[%d]", n), "member %q: %v", k, err))
				continue
			}
			if len(v) > MaxCellBytes {
				problems = append(problems, core.Fieldf(fmt.Sprintf("records[%d]", n), "member %q: longer than %d bytes", k, MaxCellBytes))
				continue
			}
			if present {
				rec.Values[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		out = append(out, rec)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, core.Fieldf("body", "the array is not closed: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, core.Fieldf("body", "anything after the array is refused")
	}
	return out, problems, nil
}

// scalar is a JSON value as text: a string as is, a number as written,
// true or false; null is absent; an array or object is refused.
func scalar(raw json.RawMessage) (string, bool, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false, errors.New("empty")
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false, err
		}
		return s, true, nil
	case 'n':
		return "", false, nil
	case 't', 'f':
		return string(raw), true, nil
	case '[', '{':
		return "", false, errors.New("a nested value; the export must be flat")
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", false, err
	}
	return n.String(), true, nil
}
