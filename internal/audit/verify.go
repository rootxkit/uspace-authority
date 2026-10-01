package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Reasons a row breaks the chain.
const (
	BrokenPrevHash = "prev_hash_mismatch" // the row does not link to the row before it
	BrokenHash     = "hash_mismatch"      // the row's content does not give its hash
	BrokenPayload  = "payload_unreadable" // the payload is not a JSON object
)

// Broken is the first row of a month whose chain does not hold.
type Broken struct {
	ID     int64
	TS     time.Time
	Reason string
	// Want and Got are the expected and stored hash (or prev_hash).
	Want, Got string
}

// Result is what Verify checked: on success it says how many rows from
// which id to which, so "verified" is never an empty claim (E-02).
type Result struct {
	Month    string // "2026-10"
	Rows     int64
	FirstID  int64
	LastID   int64
	LastHash string
	// Broken is the first broken row, or nil when the chain holds.
	Broken *Broken
}

// verifyPage bounds the rows read per query.
const verifyPage = 1000

// Verify recomputes the chain of month (any instant in it, UTC) and
// returns the first broken row in Result.Broken, or nil.
func (w *Writer) Verify(ctx context.Context, month time.Time) (Result, error) {
	return verify(ctx, w.DB.Queries(), MonthStart(month), verifyPage)
}

func verify(ctx context.Context, q *gen.Queries, month time.Time, page int32) (Result, error) {
	res := Result{Month: month.Format("2006-01")}
	end := month.AddDate(0, 1, 0)
	var want string
	after := int64(0)
	for {
		rows, err := q.EventsInRange(ctx, gen.EventsInRangeParams{FromTs: month, ToTs: end, AfterID: after, PageSize: page})
		if err != nil {
			return res, fmt.Errorf("audit verify %s: %w", res.Month, err)
		}
		for i := range rows {
			r := rowFrom(&rows[i])
			if res.Rows == 0 {
				res.FirstID = r.ID
				prev, err := q.LastEventBefore(ctx, gen.LastEventBeforeParams{BeforeTs: month, BeforeID: r.ID})
				switch {
				case store.IsNoRows(err):
					want = GenesisHash
				case err != nil:
					return res, fmt.Errorf("audit verify %s: predecessor: %w", res.Month, err)
				default:
					want = prev.Hash
				}
			}
			res.Rows++
			res.LastID, res.LastHash = r.ID, r.Hash
			if r.PrevHash != want {
				res.Broken = &Broken{ID: r.ID, TS: r.TS, Reason: BrokenPrevHash, Want: want, Got: r.PrevHash}
				return res, nil
			}
			got, err := Hash(r)
			if err != nil {
				res.Broken = &Broken{ID: r.ID, TS: r.TS, Reason: BrokenPayload, Got: r.Hash}
				return res, nil //nolint:nilerr // an unreadable payload is a finding, not a failure to verify
			}
			if got != r.Hash {
				res.Broken = &Broken{ID: r.ID, TS: r.TS, Reason: BrokenHash, Want: got, Got: r.Hash}
				return res, nil
			}
			want = r.Hash
			after = r.ID
		}
		if len(rows) < int(page) {
			return res, nil
		}
	}
}
