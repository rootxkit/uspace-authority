package receivers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// Frame is one stored raw frame (a rid_observations row).
type Frame struct {
	IngestTS         time.Time
	FrameID          string
	ReceiverID       string
	Transmitter      string
	ReceiverTS       *time.Time
	MsgType          *int
	Payload          []byte
	PayloadSHA256    []byte
	RSSIDBM          *float64
	Backlog          bool
	ReceiverPosition *Position
	SentAtMS         int64
	Nonce            string
}

// FrameQuery is a window of raw frames.
type FrameQuery struct {
	From, To    time.Time
	Transmitter *string
	ReceiverID  *string
	Limit       int
	Purpose     string
}

// Frames reads the raw frames from the telemetry database as the reader
// role (SELECT only) and records every read with its purpose in the
// audit log before answering (CLAUDE.md rule 6).
type Frames struct {
	Reader *ts.Reader
	DB     *pg.DB
	Audit  *audit.Writer
	// MaxWindow is the longest window answered (24 h, B-13); a longer one
	// is refused, never thinned.
	MaxWindow time.Duration
}

// SlugWindowTooLarge refuses a window above MaxWindow.
const SlugWindowTooLarge = "window_too_large"

// frameFrom maps a raw row; both frame queries select the same raw
// columns (not the decoded ones WP-8 added), so their rows convert.
func frameFrom(o *reader.RIDFramesRow) Frame {
	f := Frame{
		IngestTS: o.IngestTs.UTC(), FrameID: o.FrameID, ReceiverID: o.ReceiverID, Transmitter: o.Transmitter,
		ReceiverTS: o.ReceiverTs, Payload: o.Payload, PayloadSHA256: o.PayloadSha256, Backlog: o.Backlog,
		SentAtMS: o.SentAtMs, Nonce: o.Nonce,
	}
	if o.MsgType != nil {
		v := int(*o.MsgType)
		f.MsgType = &v
	}
	if o.RssiDbm != nil {
		v := float64(*o.RssiDbm)
		f.RSSIDBM = &v
	}
	if o.ReceiverLatDeg != nil && o.ReceiverLonDeg != nil {
		f.ReceiverPosition = &Position{LatDeg: *o.ReceiverLatDeg, LonDeg: *o.ReceiverLonDeg, AltHAEM: o.ReceiverAltHaeM}
	}
	return f
}

func (f *Frames) recordView(ctx context.Context, actor audit.Actor, purpose, entityID string, payload map[string]any) error {
	return f.DB.WithTx(ctx, func(q *gen.Queries) error {
		_, err := f.Audit.Record(ctx, q, audit.Event{
			Actor: actor, Purpose: purpose, EntityType: "rid_observations", EntityID: entityID,
			EventType: audit.EventRIDFramesViewed, Payload: payload,
		})
		return err
	})
}

// List answers the frames of q oldest first, at most q.Limit, and whether
// the window holds more.
func (f *Frames) List(ctx context.Context, actor audit.Actor, q FrameQuery) ([]Frame, bool, error) {
	if q.Purpose == "" {
		return nil, false, core.Fieldf("purpose", "required: raw frames are read for a stated purpose")
	}
	if !q.To.After(q.From) {
		return nil, false, core.Fieldf("to", "must be after from")
	}
	if q.To.Sub(q.From) > f.MaxWindow {
		return nil, false, httpx.Refuse(http.StatusBadRequest, SlugWindowTooLarge,
			"a window longer than the maximum is refused rather than thinned; split it",
			core.Fieldf("to", "the window is %s, at most %s", q.To.Sub(q.From), f.MaxWindow))
	}
	if q.Limit < 1 || q.Limit > 5000 {
		return nil, false, core.Fieldf("limit", "must be 1 to 5000")
	}
	if q.Transmitter != nil {
		// Stored upper-case (the ingest's one spelling per transmitter).
		up := strings.ToUpper(*q.Transmitter)
		q.Transmitter = &up
	}
	rows, err := f.Reader.Q.RIDFrames(ctx, reader.RIDFramesParams{
		FromTs: q.From, ToTs: q.To, Transmitter: q.Transmitter, ReceiverID: q.ReceiverID, RowLimit: int32(q.Limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > q.Limit
	if truncated {
		rows = rows[:q.Limit]
	}
	out := make([]Frame, 0, len(rows))
	for i := range rows {
		out = append(out, frameFrom(&rows[i]))
	}
	payload := map[string]any{"from": q.From, "to": q.To, "frames": len(out), "truncated": truncated}
	if q.Transmitter != nil {
		payload["transmitter"] = *q.Transmitter
	}
	if q.ReceiverID != nil {
		payload["receiver_id"] = *q.ReceiverID
	}
	if err := f.recordView(ctx, actor, q.Purpose, "", payload); err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

// Get answers every stored row of one frame id.
func (f *Frames) Get(ctx context.Context, actor audit.Actor, frameID, purpose string) ([]Frame, error) {
	if purpose == "" {
		return nil, core.Fieldf("purpose", "required: raw frames are read for a stated purpose")
	}
	rows, err := f.Reader.Q.RIDFrameByID(ctx, frameID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such frame")
	}
	out := make([]Frame, 0, len(rows))
	for i := range rows {
		out = append(out, frameFrom((*reader.RIDFramesRow)(&rows[i])))
	}
	if err := f.recordView(ctx, actor, purpose, frameID, map[string]any{"frames": len(out)}); err != nil {
		return nil, err
	}
	return out, nil
}
