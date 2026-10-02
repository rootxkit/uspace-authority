package track

import (
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Row is one tracks row (timeseries 00006): a published track message
// flattened for tsdb-writer, its JSON names the column names. AGL is
// never stored (D-02); a pressure altitude is in alt_pressure_m only
// (R-08).
type Row struct {
	CapturedAt time.Time `json:"captured_at"`
	TrackID    string    `json:"track_id"`
	// DedupeKey makes a redelivered batch write each track once (B-05):
	// for direct Remote ID "direct_rid:<frame_id>" of the frame that
	// carried the Location.
	DedupeKey             string           `json:"dedupe_key"`
	MsgID                 string           `json:"msg_id"`
	TS                    *time.Time       `json:"ts"`
	RxTS                  time.Time        `json:"rx_ts"`
	TimeSource            core.TimeSource  `json:"time_source"`
	Backlog               bool             `json:"backlog"`
	Source                Source           `json:"source"`
	SourceInstance        string           `json:"source_instance"`
	Trust                 core.Trust       `json:"trust"`
	LatDeg                float64          `json:"lat_deg"`
	LonDeg                float64          `json:"lon_deg"`
	AltWGS84M             *float64         `json:"alt_wgs84_m"`
	AltAMSLM              *float64         `json:"alt_amsl_m"`
	AltSource             core.AltSource   `json:"alt_source"`
	AltPressureM          *float64         `json:"alt_pressure_m"`
	HeightM               *float64         `json:"height_m"`
	HeightRef             *string          `json:"height_ref"`
	SpeedMS               *float64         `json:"speed_ms"`
	TrackDeg              *float64         `json:"track_deg"`
	VSpeedMS              *float64         `json:"vspeed_ms"`
	AccuracyHM            *float64         `json:"accuracy_h_m"`
	AccuracyVM            *float64         `json:"accuracy_v_m"`
	Status                *string          `json:"status"`
	Emergency             bool             `json:"emergency"`
	Airborne              *bool            `json:"airborne"`
	IdentStatus           core.IdentStatus `json:"ident_status"`
	IdentReason           core.IdentReason `json:"ident_reason"`
	IdentMismatch         bool             `json:"ident_mismatch"`
	IdentBasis            core.IdentBasis  `json:"ident_basis"`
	Serial                *string          `json:"serial"`
	OperatorReg           *string          `json:"operator_reg"`
	RegisteredOperatorReg *string          `json:"registered_operator_reg"`
	RegistryUASID         *string          `json:"registry_uas_id"`
	FlightID              *string          `json:"flight_id"`
	USSPID                *string          `json:"ussp_id"`
	Cell5                 *string          `json:"cell5"`
}

// RowOf flattens m. dedupeKey identifies the observation across
// redeliveries; airborne is the adapter's verdict (R-11), nil when the
// source says nothing about it.
func RowOf(m *Message, t core.Times, dedupeKey string, airborne *bool) Row {
	b := &m.Body
	id := &b.Identification
	r := Row{
		CapturedAt: t.CapturedAt.UTC(), TrackID: b.TrackID, DedupeKey: dedupeKey, MsgID: m.MsgID, RxTS: t.RxTS.UTC(),
		TimeSource: t.Source, Backlog: t.Backlog, Source: b.Source, SourceInstance: b.SourceInstance, Trust: b.Trust,
		LatDeg: b.Position.Lat, LonDeg: b.Position.Lng, AltWGS84M: b.AltWGS84M, AltAMSLM: b.AltAMSLM,
		AltSource: b.AltSource, AltPressureM: b.AltPressureM, HeightM: b.HeightM, SpeedMS: b.SpeedMS,
		TrackDeg: b.TrackDeg, VSpeedMS: b.VSpeedMS, AccuracyHM: b.AccuracyHM, AccuracyVM: b.AccuracyVM,
		Emergency: b.Emergency, Airborne: airborne, IdentStatus: id.Status, IdentReason: id.Reason,
		IdentMismatch: id.Mismatch, IdentBasis: id.Basis, Serial: id.Serial, OperatorReg: id.OperatorReg,
		RegisteredOperatorReg: id.RegisteredOperatorReg, RegistryUASID: id.RegistryUASID, FlightID: b.FlightID,
	}
	if t.TS != nil {
		ts := t.TS.UTC()
		r.TS = &ts
	}
	if b.HeightRef != nil {
		s := string(*b.HeightRef)
		r.HeightRef = &s
	}
	if b.Status != nil {
		s := string(*b.Status)
		r.Status = &s
	}
	if b.Cell != "" {
		c := b.Cell
		r.Cell5 = &c
	}
	return r
}
