package ridpipe

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Row is one rid_observations row as rid-ingest fills it: the raw frame
// and who heard it when (LESSONS R-15). The JSON names are the column
// names of migrations/timeseries/00004_rid_observations.sql; bytea
// columns travel as base64 (encoding/json's []byte). WP-8 adds the
// decoded columns.
type Row struct {
	IngestTS        time.Time  `json:"ingest_ts"`
	FrameID         string     `json:"frame_id"`
	ReceiverID      string     `json:"receiver_id"`
	Transmitter     string     `json:"transmitter"`
	RxTS            *time.Time `json:"rx_ts"`
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
