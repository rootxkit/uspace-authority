package ridpipe

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/track"
)

// Row is one rid_observations row as rid-ingest fills it: the raw frame
// and who heard it when (LESSONS R-15), then the columns the Pipeline
// decodes from it (WP-8). The JSON names are the column names of
// migrations/timeseries (00004 and 00006); bytea columns travel as base64
// (encoding/json's []byte). A decoded column is null when the frame did
// not carry the value (R-01) or could not be decoded (DecodeError says
// why).
//
// The times are LESSONS T-01's three: ReceiverTS is the source's own
// clock (`ts`; the receiver's, sent as rx_ts on the F9 wire), IngestTS is
// when this system received it (`rx_ts`), and CapturedAt is where the
// row is placed on this system's clock. The Pipeline places the
// receiver's reception of each row on this system's clock by T-02:
// within one batch, rx = IngestTS - (newest ReceiverTS in the batch -
// ReceiverTS), so the receiver's clock error cancels and the rows keep
// their true spacing (T-11), and a row without ReceiverTS is received at
// IngestTS, its arrival (T-12). A row carrying a Location is then placed
// at its broadcast time when that time is within the tolerance of rx
// (timeplace.PlaceBroadcast, T-07, T-08), else at rx; every other row at
// rx.
type Row struct {
	IngestTS        time.Time  `json:"ingest_ts"`
	FrameID         string     `json:"frame_id"`
	ReceiverID      string     `json:"receiver_id"`
	Transmitter     string     `json:"transmitter"`
	ReceiverTS      *time.Time `json:"receiver_ts"`
	MsgType         *int       `json:"msg_type"`
	Payload         []byte     `json:"payload"`
	PayloadSHA256   []byte     `json:"payload_sha256"`
	RSSIDBM         *float64   `json:"rssi_dbm"`
	Backlog         bool       `json:"backlog"`
	ReceiverLatDeg  *float64   `json:"receiver_lat_deg"`
	ReceiverLonDeg  *float64   `json:"receiver_lon_deg"`
	ReceiverAltHAEM *float64   `json:"receiver_alt_hae_m"`
	SentAtMS        int64      `json:"sent_at_ms"`
	Nonce           string     `json:"nonce"`

	// Decoded (WP-8, timeseries 00006). Serial is the Basic ID of ID
	// type 1 as broadcast (case kept, G-05); IDType is the Basic ID's
	// type (the serial's when a pack carries two). The Location columns
	// are the broadcast's units (odid); TSBroadcast is the broadcast time
	// reconstructed in its hour (T-07), null when unknown or invalid.
	Serial       *string    `json:"serial"`
	OperatorReg  *string    `json:"operator_reg"`
	IDType       *int       `json:"id_type"`
	LatDeg       *float64   `json:"lat_deg"`
	LonDeg       *float64   `json:"lon_deg"`
	AltWGS84M    *float64   `json:"alt_wgs84_m"`
	AltPressureM *float64   `json:"alt_pressure_m"`
	HeightM      *float64   `json:"height_m"`
	HeightRef    *string    `json:"height_ref"`
	SpeedMS      *float64   `json:"speed_ms"`
	TrackDeg     *float64   `json:"track_deg"`
	VSpeedMS     *float64   `json:"vspeed_ms"`
	Status       *string    `json:"status"`
	TSBroadcast  *time.Time `json:"ts_broadcast"`
	CapturedAt   *time.Time `json:"captured_at"`
	TimeSource   *string    `json:"time_source"`
	DecodeError  *string    `json:"decode_error"`
}

// Batch is one accepted, authenticated batch of one receiver after the
// dedupe window: what the work queue holds and what the Sink receives.
type Batch struct {
	// ID is "<receiver_id>:<nonce>", unique per receiver within the
	// nonce window and the JetStream message id of the batch.
	ID         string    `json:"id"`
	ReceiverID string    `json:"receiver_id"`
	SentAtMS   int64     `json:"sent_at_ms"`
	Nonce      string    `json:"nonce"`
	Backlog    bool      `json:"backlog"`
	IngestTS   time.Time `json:"ingest_ts"`
	// Cell3 is the receiver's pinned cell (core geodesy/cell Level3),
	// the token of the work-queue subject ingest.v1.<cell3>.
	Cell3 string `json:"cell3"`
	Rows  []Row  `json:"rows"`
	// Tracks are the tracks rows of the observations the Pipeline
	// published from this batch (WP-8), stored after Rows by the worker
	// under the same retry. Never queued: a redelivered batch is decoded
	// again.
	Tracks []track.Row `json:"-"`
}

// Sink takes each queued batch once, before its rows are written. An
// error is counted by the caller and the raw rows are still written
// (LESSONS B-12: nothing is filtered at the edge); Observe must not keep
// the batch after it returns.
type Sink interface {
	Observe(ctx context.Context, b *Batch) error
}

// CounterNotDecoded counts the rows Undecoded let through.
const CounterNotDecoded = "rows_not_decoded"

// Undecoded is the Sink of a rid-ingest built without WP-8's pipeline:
// it decodes nothing and counts every row as not decoded, so the status
// line says that no track came of them (E-02, CLAUDE.md rule 8).
type Undecoded struct {
	Counters *core.Counters
}

// Observe counts the rows of b.
func (u Undecoded) Observe(_ context.Context, b *Batch) error {
	if u.Counters != nil {
		u.Counters.Add(CounterNotDecoded, uint64(len(b.Rows)))
	}
	return nil
}
