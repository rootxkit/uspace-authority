package ts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

var kinds = Table{Name: "kinds", Columns: []Column{
	{Name: "s", Kind: KindText}, {Name: "t", Kind: KindTime}, {Name: "b", Kind: KindBytes},
	{Name: "i", Kind: KindInt}, {Name: "f", Kind: KindFloat}, {Name: "ok", Kind: KindBool},
	{Name: "opt", Kind: KindText, Nullable: true},
}}

func TestDecodeRowMapsEveryKind(t *testing.T) {
	row, err := kinds.DecodeRow(json.RawMessage(`{"s":"x","t":"2026-10-02T12:00:00.5+02:00","b":"AQI=","i":9007199254740993,"f":-1.5,"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"x", time.Date(2026, 10, 2, 10, 0, 0, 500e6, time.UTC), []byte{1, 2}, int64(9007199254740993), -1.5, true, nil}
	for i := range want {
		if b, ok := want[i].([]byte); ok {
			if !bytes.Equal(row[i].([]byte), b) {
				t.Errorf("%d: %v", i, row[i])
			}
			continue
		}
		if row[i] != want[i] {
			t.Errorf("column %s: got %#v want %#v", kinds.Columns[i].Name, row[i], want[i])
		}
	}
	// An explicit null of a nullable column is accepted too.
	if _, err := kinds.DecodeRow(json.RawMessage(`{"s":"x","t":"2026-10-02T12:00:00Z","b":"","i":1,"f":1,"ok":false,"opt":null}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRowRefusesNamingTheMember(t *testing.T) {
	base := map[string]any{"s": "x", "t": "2026-10-02T12:00:00Z", "b": "AQI=", "i": 1, "f": 1.0, "ok": true}
	cases := map[string]struct {
		set   map[string]any
		field string
	}{
		"missing required": {map[string]any{"s": nil}, "s"},
		"text not string":  {map[string]any{"s": 1}, "s"},
		"time not RFC3339": {map[string]any{"t": "yesterday"}, "t"},
		"time not string":  {map[string]any{"t": 5}, "t"},
		"bytes not base64": {map[string]any{"b": "!!"}, "b"},
		"bytes not string": {map[string]any{"b": 5}, "b"},
		"int fraction":     {map[string]any{"i": 1.5}, "i"},
		"int string":       {map[string]any{"i": "1"}, "i"},
		"float string":     {map[string]any{"f": "1"}, "f"},
		"bool string":      {map[string]any{"ok": "true"}, "ok"},
		"unknown member":   {map[string]any{"extra": 1}, "extra"},
	}
	for name, c := range cases {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range c.set {
			if v == nil {
				delete(m, k)
				continue
			}
			m[k] = v
		}
		raw, _ := json.Marshal(m)
		_, err := kinds.DecodeRow(raw)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := kinds.DecodeRow(json.RawMessage(`[1]`)); err == nil {
		t.Fatal("array accepted")
	}
	if _, err := kinds.DecodeRow(json.RawMessage(`null`)); err == nil {
		t.Fatal("null accepted")
	}
	if _, err := (Table{Name: "x", Columns: []Column{{Name: "k", Kind: Kind(99)}}}).DecodeRow(json.RawMessage(`{"k":1}`)); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

// ridpipe.Row's JSON (WP-7) decodes onto rid_observations.
func TestRIDObservationRowDecodes(t *testing.T) {
	raw := `{"ingest_ts":"2026-10-02T10:00:00Z","frame_id":"0123456789abcdef0123456789abcdef","receiver_id":"rx-1",
	"transmitter":"TEST1","receiver_ts":null,"msg_type":2,"payload":"AQI=","payload_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	"rssi_dbm":-70.5,"backlog":false,"receiver_lat_deg":41.7,"receiver_lon_deg":44.8,"receiver_alt_hae_m":null,"sent_at_ms":1,"nonce":"n"}`
	row, err := RIDObservations.DecodeRow(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != len(RIDObservations.Columns) || row[4] != nil || row[5] != int64(2) {
		t.Fatalf("%v", row)
	}
}

func TestGapValidateAndRow(t *testing.T) {
	g := Gap{DedupeKey: "k", Table: "t", Stream: "TSW", FromSeq: 1, ToSeq: 2, Cause: "c", Count: 3, CountUnit: UnitRows,
		At: time.Date(2026, 10, 2, 12, 0, 0, 0, time.FixedZone("x", 7200))}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	row := g.Row()
	if len(row) != len(WriterGaps.Columns) || row[8] != time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC) || row[9] != nil || row[10] != nil {
		t.Fatalf("%v", row)
	}
	if !strings.Contains(g.String(), "t c TSW:1-2 3 rows") {
		t.Fatal(g.String())
	}
	for name, mut := range map[string]func(*Gap){
		"key": func(g *Gap) { g.DedupeKey = "" }, "table": func(g *Gap) { g.Table = "" }, "cause": func(g *Gap) { g.Cause = "" },
		"seq": func(g *Gap) { g.ToSeq = 0 }, "count": func(g *Gap) { g.Count = -1 }, "unit": func(g *Gap) { g.CountUnit = "" },
		"at": func(g *Gap) { g.At = time.Time{} },
	} {
		c := g
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBusWriterRefusesBeforePublishing(t *testing.T) {
	w := BusWriter{}
	ctx := context.Background()
	if err := w.Enqueue(ctx, "no_such_table", []map[string]any{}, ""); !errors.Is(err, ErrUnknownTable) {
		t.Fatalf("unknown table: %v", err)
	}
	if err := w.Enqueue(ctx, RIDObservations.Name, func() {}, ""); err == nil {
		t.Fatal("unmarshalable rows accepted")
	}
	if err := w.Enqueue(ctx, RIDObservations.Name, "not rows", ""); err == nil {
		t.Fatal("a string accepted as rows")
	}
	big := []map[string]string{{"nonce": strings.Repeat("x", 1<<20)}}
	if err := w.Enqueue(ctx, RIDObservations.Name, big, ""); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if err := w.EnqueueGap(ctx, GapMessage{Detail: strings.Repeat("x", 1<<20)}, ""); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("gap too large: %v", err)
	}
}

func TestIsDataError(t *testing.T) {
	if IsDataError(errors.New("connection refused")) {
		t.Fatal("a connection error is not a data error")
	}
}

func readSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func keys(m any) []string {
	var out []string
	for k := range m.(map[string]any) {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// schemas/tsw/* hold to the registrations: every registered table is in
// the rows schema's enum with its columns, and the gap schema's members
// are GapMessage's JSON names.
func TestTSWSchemasMatchTheRegistrations(t *testing.T) {
	rows := readSchema(t, "../../../schemas/tsw/rows/v1.json")
	enum := rows["properties"].(map[string]any)["table"].(map[string]any)["enum"].([]any)
	defs := rows["$defs"].(map[string]any)
	if len(enum) != len(Tables) {
		t.Fatalf("enum %v, tables %d", enum, len(Tables))
	}
	for _, name := range enum {
		tb, ok := Tables[name.(string)]
		if !ok {
			t.Fatalf("%v is not registered", name)
		}
		def := defs[tb.Name].(map[string]any)
		want := tb.ColumnNames()
		slices.Sort(want)
		if got := keys(def["properties"]); !slices.Equal(got, want) {
			t.Errorf("%s: schema %v, columns %v", tb.Name, got, want)
		}
		var required []string
		for _, r := range def["required"].([]any) {
			required = append(required, r.(string))
		}
		slices.Sort(required)
		var notNull []string
		for _, c := range tb.Columns {
			if !c.Nullable {
				notNull = append(notNull, c.Name)
			}
		}
		slices.Sort(notNull)
		if !slices.Equal(required, notNull) {
			t.Errorf("%s: required %v, NOT NULL %v", tb.Name, required, notNull)
		}
	}
	gap := readSchema(t, "../../../schemas/tsw/gap/v1.json")
	b, _ := json.Marshal(GapMessage{ReceiverID: "x", Stream: "x", CountUnit: "x", Detail: "x"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if got, want := keys(gap["properties"]), keys(m); !slices.Equal(got, want) {
		t.Fatalf("gap schema %v, GapMessage %v", got, want)
	}
}
