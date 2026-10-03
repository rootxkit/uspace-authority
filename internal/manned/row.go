package manned

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
)

// Table is the hypertable of the rows (timeseries 00012).
const Table = "manned_tracks"

// Row is one manned_tracks row (internal/store/ts.MannedTracks): a
// published track/manned/v1 message, the ANSP's members flattened.
type Row struct {
	SourceCapturedAt time.Time       `json:"source_captured_at"`
	CapturedAt       time.Time       `json:"captured_at"`
	DedupeKey        string          `json:"dedupe_key"`
	MsgID            string          `json:"msg_id"`
	SourceMsgID      *string         `json:"source_msg_id"`
	TS               *time.Time      `json:"ts"`
	RxTS             time.Time       `json:"rx_ts"`
	TimeSource       string          `json:"time_source"`
	Backlog          bool            `json:"backlog"`
	ICAO24           string          `json:"icao24"`
	Callsign         *string         `json:"callsign"`
	LatDeg           float64         `json:"lat_deg"`
	LonDeg           float64         `json:"lon_deg"`
	AltPressureM     *float64        `json:"alt_pressure_m"`
	AltWGS84M        *float64        `json:"alt_wgs84_m"`
	GSMS             *float64        `json:"gs_ms"`
	TrackDeg         *float64        `json:"track_deg"`
	VRateMS          *float64        `json:"vrate_ms"`
	Emergency        *bool           `json:"emergency"`
	SPI              *bool           `json:"spi"`
	Squawk           *string         `json:"squawk"`
	SourceClass      string          `json:"source_class"`
	Quality          json.RawMessage `json:"quality"`
	Trust            string          `json:"trust"`
	Source           string          `json:"source"`
	SourceInstance   string          `json:"source_instance"`
	State            string          `json:"state"`
	Relevant         *bool           `json:"relevant"`
	PolicyVersion    *string         `json:"policy_version"`
	Cell5            *string         `json:"cell5"`
}

// DedupeKey names one state of one sample: the adapter, the aircraft,
// the sample's time on the ANSP's clock and the state.
func DedupeKey(instance, icao24 string, sourceAt time.Time, state string) string {
	return SourceType + ":" + instance + ":" + icao24 + ":" + sourceAt.UTC().Format(time.RFC3339Nano) + ":" + state
}

// held is the last published state of one aircraft.
type held struct {
	msg      Message
	sourceAt time.Time
	orderAt  time.Time
	srcMsgID string
	ts       *time.Time
	capAt    time.Time
	rx       time.Time
	cell3    string
	cell5    string
}

// Published is one message this process publishes with its subject and
// its row.
type Published struct {
	Subject string
	Message Message
	Row     Row
}

func secondsSince(now, at time.Time) float64 {
	return math.Round(math.Max(0, now.Sub(at).Seconds())*1000) / 1000
}

// newHeld maps a placed sample onto the message this process publishes.
func newHeld(p placed) (*held, error) {
	pos := core.LatLon{LatDeg: p.body.Position.Lat, LonDeg: p.body.Position.Lng}
	c3, c5, err := cell.Tokens(pos)
	if err != nil {
		return nil, err
	}
	body := p.body
	age := secondsSince(p.rx, p.capturedAt)
	body.AgeS = &age
	m := Message{
		Schema: SchemaTrack, MsgID: bus.NewULID(p.rx), Producer: Producer, RxTS: bus.Stamp(p.rx),
		CapturedAt: bus.Stamp(p.capturedAt), TimeSource: string(p.timeSource), Backlog: p.env.Backlog, Body: body,
	}
	if p.ts != nil {
		s := bus.Stamp(*p.ts)
		m.TS = &s
	}
	return &held{msg: m, sourceAt: p.sourceAt, orderAt: p.orderAt, srcMsgID: p.env.MsgID, ts: p.ts, capAt: p.capturedAt, rx: p.rx, cell3: c3, cell5: c5}, nil
}

// published is h as a message, its subject and its row.
func (h *held) published() (Published, error) {
	subject, err := bus.Subjects.Man(h.cell3, h.cell5, h.msg.Body.ICAO24)
	if err != nil {
		return Published{}, err
	}
	b := h.msg.Body
	r := Row{
		SourceCapturedAt: h.sourceAt.UTC(), CapturedAt: h.capAt.UTC(), DedupeKey: DedupeKey(b.SourceInstance, b.ICAO24, h.sourceAt, b.State),
		MsgID: h.msg.MsgID, TS: h.ts, RxTS: h.rx.UTC(), TimeSource: h.msg.TimeSource, Backlog: h.msg.Backlog, ICAO24: b.ICAO24,
		Callsign: b.Callsign, LatDeg: b.Position.Lat, LonDeg: b.Position.Lng, AltPressureM: b.AltPressureM, AltWGS84M: b.AltWGS84M,
		GSMS: b.GSMS, TrackDeg: b.TrackDeg, VRateMS: b.VRateMS, Emergency: b.Emergency, SPI: b.SPI, Squawk: b.Squawk,
		SourceClass: b.SourceClass, Trust: b.Trust, Source: b.Source, SourceInstance: b.SourceInstance, State: b.State,
		Relevant: b.Relevant, PolicyVersion: b.PolicyVersion,
	}
	if len(b.Quality) > 0 && b.Quality[0] == '{' {
		r.Quality = b.Quality
	}
	if h.srcMsgID != "" {
		id := h.srcMsgID
		r.SourceMsgID = &id
	}
	// The column holds the cell's own form (c5:<row>:<col>), the subject
	// its token form.
	c5 := strings.ReplaceAll(h.cell5, "_", ":")
	r.Cell5 = &c5
	return Published{Subject: subject, Message: h.msg, Row: r}, nil
}
