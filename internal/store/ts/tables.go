package ts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Kind is the JSON form of one column on a tsw.v1.<table> message and
// the Go value handed to COPY.
type Kind int

// Column kinds.
const (
	// KindText is a JSON string.
	KindText Kind = iota
	// KindTime is an RFC 3339 string, stored as timestamptz in UTC.
	KindTime
	// KindBytes is base64 (encoding/json's []byte), stored as bytea.
	KindBytes
	// KindInt is a JSON integer (smallint, integer, bigint).
	KindInt
	// KindFloat is a JSON number (real, double precision).
	KindFloat
	// KindBool is a JSON boolean.
	KindBool
)

// Column is one column of a hypertable as it travels on the bus: the
// JSON member has the column's name.
type Column struct {
	Name     string
	Kind     Kind
	Nullable bool
}

// Table is a hypertable tsdb-writer writes: its name (the token of
// tsw.v1.<table>) and its columns in COPY order. A WP that defines a
// hypertable registers it in Tables; the integration test holds each
// registration to the migrated table's columns.
type Table struct {
	Name    string
	Columns []Column
}

// ColumnNames lists the columns in COPY order.
func (t Table) ColumnNames() []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name
	}
	return out
}

// DecodeRow maps one JSON object onto the table's columns. A missing or
// null member of a NOT NULL column, a value of the wrong kind and a
// member the table does not have are refused, naming the member: the
// writer records a refused message as a gap rather than drop a column
// it does not know (B-12).
func (t Table) DecodeRow(raw json.RawMessage) ([]any, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, &core.FieldError{Field: "row", Reason: "not a JSON object"}
	}
	row := make([]any, len(t.Columns))
	known := 0
	for i, c := range t.Columns {
		v, ok := obj[c.Name]
		if ok {
			known++
		}
		if !ok || string(v) == "null" {
			if !c.Nullable {
				return nil, &core.FieldError{Field: c.Name, Reason: "required"}
			}
			continue
		}
		val, err := decodeValue(c, v)
		if err != nil {
			return nil, err
		}
		row[i] = val
	}
	if known != len(obj) {
		for name := range obj {
			if !slices.ContainsFunc(t.Columns, func(c Column) bool { return c.Name == name }) {
				return nil, core.Fieldf(name, "not a column of %s", t.Name)
			}
		}
	}
	return row, nil
}

func decodeValue(c Column, v json.RawMessage) (any, error) {
	switch c.Kind {
	case KindText:
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not a string"}
		}
		return s, nil
	case KindTime:
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not an RFC 3339 time"}
		}
		at, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not an RFC 3339 time"}
		}
		return at.UTC(), nil
	case KindBytes:
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not base64"}
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not base64"}
		}
		return b, nil
	case KindInt:
		var n json.Number
		if err := json.Unmarshal(v, &n); err != nil || v[0] == '"' {
			return nil, &core.FieldError{Field: c.Name, Reason: "not an integer"}
		}
		i, err := n.Int64()
		if err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not an integer"}
		}
		return i, nil
	case KindFloat:
		var n json.Number
		if err := json.Unmarshal(v, &n); err != nil || v[0] == '"' {
			return nil, &core.FieldError{Field: c.Name, Reason: "not a number"}
		}
		f, err := n.Float64()
		if err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not a number"}
		}
		return f, nil
	case KindBool:
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return nil, &core.FieldError{Field: c.Name, Reason: "not a boolean"}
		}
		return b, nil
	}
	return nil, core.Fieldf(c.Name, "unknown column kind %d", c.Kind)
}

// RIDObservations is rid_observations (timeseries 00004, WP-7, and
// 00006, WP-8): the raw side rid-ingest fills and the columns its
// pipeline decodes, ridpipe.Row's JSON.
var RIDObservations = Table{Name: "rid_observations", Columns: []Column{
	{Name: "ingest_ts", Kind: KindTime},
	{Name: "frame_id", Kind: KindText},
	{Name: "receiver_id", Kind: KindText},
	{Name: "transmitter", Kind: KindText},
	{Name: "receiver_ts", Kind: KindTime, Nullable: true},
	{Name: "msg_type", Kind: KindInt, Nullable: true},
	{Name: "payload", Kind: KindBytes},
	{Name: "payload_sha256", Kind: KindBytes},
	{Name: "rssi_dbm", Kind: KindFloat, Nullable: true},
	{Name: "backlog", Kind: KindBool},
	{Name: "receiver_lat_deg", Kind: KindFloat, Nullable: true},
	{Name: "receiver_lon_deg", Kind: KindFloat, Nullable: true},
	{Name: "receiver_alt_hae_m", Kind: KindFloat, Nullable: true},
	{Name: "sent_at_ms", Kind: KindInt},
	{Name: "nonce", Kind: KindText},
	{Name: "serial", Kind: KindText, Nullable: true},
	{Name: "operator_reg", Kind: KindText, Nullable: true},
	{Name: "id_type", Kind: KindInt, Nullable: true},
	{Name: "lat_deg", Kind: KindFloat, Nullable: true},
	{Name: "lon_deg", Kind: KindFloat, Nullable: true},
	{Name: "alt_wgs84_m", Kind: KindFloat, Nullable: true},
	{Name: "alt_pressure_m", Kind: KindFloat, Nullable: true},
	{Name: "height_m", Kind: KindFloat, Nullable: true},
	{Name: "height_ref", Kind: KindText, Nullable: true},
	{Name: "speed_ms", Kind: KindFloat, Nullable: true},
	{Name: "track_deg", Kind: KindFloat, Nullable: true},
	{Name: "vspeed_ms", Kind: KindFloat, Nullable: true},
	{Name: "status", Kind: KindText, Nullable: true},
	{Name: "ts_broadcast", Kind: KindTime, Nullable: true},
	{Name: "captured_at", Kind: KindTime, Nullable: true},
	{Name: "time_source", Kind: KindText, Nullable: true},
	{Name: "decode_error", Kind: KindText, Nullable: true},
}}

// Tracks is tracks (timeseries 00006, WP-8): the published picture,
// internal/track.Row's JSON.
var Tracks = Table{Name: "tracks", Columns: []Column{
	{Name: "captured_at", Kind: KindTime},
	{Name: "track_id", Kind: KindText},
	{Name: "dedupe_key", Kind: KindText},
	{Name: "msg_id", Kind: KindText},
	{Name: "ts", Kind: KindTime, Nullable: true},
	{Name: "rx_ts", Kind: KindTime},
	{Name: "time_source", Kind: KindText},
	{Name: "backlog", Kind: KindBool},
	{Name: "source", Kind: KindText},
	{Name: "source_instance", Kind: KindText},
	{Name: "trust", Kind: KindText},
	{Name: "lat_deg", Kind: KindFloat},
	{Name: "lon_deg", Kind: KindFloat},
	{Name: "alt_wgs84_m", Kind: KindFloat, Nullable: true},
	{Name: "alt_amsl_m", Kind: KindFloat, Nullable: true},
	{Name: "alt_source", Kind: KindText},
	{Name: "alt_pressure_m", Kind: KindFloat, Nullable: true},
	{Name: "height_m", Kind: KindFloat, Nullable: true},
	{Name: "height_ref", Kind: KindText, Nullable: true},
	{Name: "speed_ms", Kind: KindFloat, Nullable: true},
	{Name: "track_deg", Kind: KindFloat, Nullable: true},
	{Name: "vspeed_ms", Kind: KindFloat, Nullable: true},
	{Name: "accuracy_h_m", Kind: KindFloat, Nullable: true},
	{Name: "accuracy_v_m", Kind: KindFloat, Nullable: true},
	{Name: "status", Kind: KindText, Nullable: true},
	{Name: "emergency", Kind: KindBool},
	{Name: "airborne", Kind: KindBool, Nullable: true},
	{Name: "ident_status", Kind: KindText},
	{Name: "ident_reason", Kind: KindText},
	{Name: "ident_mismatch", Kind: KindBool},
	{Name: "ident_basis", Kind: KindText},
	{Name: "serial", Kind: KindText, Nullable: true},
	{Name: "operator_reg", Kind: KindText, Nullable: true},
	{Name: "registered_operator_reg", Kind: KindText, Nullable: true},
	{Name: "registry_uas_id", Kind: KindText, Nullable: true},
	{Name: "flight_id", Kind: KindText, Nullable: true},
	{Name: "ussp_id", Kind: KindText, Nullable: true},
	{Name: "cell5", Kind: KindText, Nullable: true},
}}

// WriterGaps is writer_gaps (timeseries 00005): every hole, with its
// cause (B-13). recorded_at is the database's default.
var WriterGaps = Table{Name: "writer_gaps", Columns: []Column{
	{Name: "dedupe_key", Kind: KindText},
	{Name: "table_name", Kind: KindText},
	{Name: "stream", Kind: KindText},
	{Name: "from_seq", Kind: KindInt},
	{Name: "to_seq", Kind: KindInt},
	{Name: "cause", Kind: KindText},
	{Name: "count", Kind: KindInt},
	{Name: "count_unit", Kind: KindText},
	{Name: "at", Kind: KindTime},
	{Name: "receiver_id", Kind: KindText, Nullable: true},
	{Name: "detail", Kind: KindText, Nullable: true},
}}

// Tables are the hypertables tsdb-writer consumes tsw.v1.<table> for,
// by name. ussp_flights (WP-14) and manned_tracks (WP-15) are added by
// their WPs with their migrations.
var Tables = map[string]Table{
	RIDObservations.Name: RIDObservations,
	Tracks.Name:          Tracks,
}

// Gap is one writer_gaps row.
type Gap struct {
	DedupeKey  string
	Table      string
	Stream     string
	FromSeq    uint64
	ToSeq      uint64
	Cause      string
	Count      int64
	CountUnit  string
	At         time.Time
	ReceiverID string
	Detail     string
}

// Count units of a Gap.
const (
	UnitRows     = "rows"
	UnitMessages = "messages"
)

// Row is g as a WriterGaps row.
func (g Gap) Row() []any {
	opt := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	return []any{g.DedupeKey, g.Table, g.Stream, int64(g.FromSeq), int64(g.ToSeq), g.Cause, g.Count, g.CountUnit,
		g.At.UTC(), opt(g.ReceiverID), opt(g.Detail)}
}

// Validate refuses a gap the table would refuse.
func (g Gap) Validate() error {
	switch {
	case g.DedupeKey == "":
		return &core.FieldError{Field: "dedupe_key", Reason: "required"}
	case g.Table == "":
		return &core.FieldError{Field: "table", Reason: "required"}
	case g.Cause == "":
		return &core.FieldError{Field: "cause", Reason: "required"}
	case g.ToSeq < g.FromSeq:
		return &core.FieldError{Field: "to_seq", Reason: "before from_seq"}
	case g.Count < 0:
		return &core.FieldError{Field: "count", Reason: "negative"}
	case g.CountUnit != UnitRows && g.CountUnit != UnitMessages:
		return core.Fieldf("count_unit", "must be %s or %s", UnitRows, UnitMessages)
	case g.At.IsZero():
		return &core.FieldError{Field: "at", Reason: "required"}
	}
	return nil
}

// String names the gap in a log line.
func (g Gap) String() string {
	return fmt.Sprintf("%s %s %s:%d-%d %d %s", g.Table, g.Cause, g.Stream, g.FromSeq, g.ToSeq, g.Count, g.CountUnit)
}
