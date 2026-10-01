package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Writer records, verifies and reads the audit log.
type Writer struct {
	DB        *pg.DB
	Catalogue Catalogue
	// Now is the clock of an event without TS; nil is time.Now.
	Now func() time.Time
}

// NewWriter returns a Writer on db with the default catalogue.
func NewWriter(db *pg.DB) *Writer {
	return &Writer{DB: db, Catalogue: DefaultCatalogue()}
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Recorded is what Record wrote.
type Recorded struct {
	ID       int64
	TS       time.Time
	PrevHash string
	Hash     string
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Record writes ev inside the caller's transaction q (pg.DB.WithTx), so
// the event commits or rolls back with the act it records. It refuses an
// invalid event before touching the database.
func (w *Writer) Record(ctx context.Context, q *gen.Queries, ev Event) (Recorded, error) {
	if err := w.Catalogue.Validate(ev); err != nil {
		return Recorded{}, err
	}
	payload := []byte("{}")
	if ev.Payload != nil {
		b, err := json.Marshal(ev.Payload)
		if err != nil {
			return Recorded{}, fmt.Errorf("audit payload: %w", err)
		}
		payload = b
	}
	ts := ev.TS
	if ts.IsZero() {
		ts = w.now()
	}
	ts = storedTime(ts)
	month := MonthStart(ts)

	// The month's lock makes its chain linear: id, prev_hash and the
	// insert happen while no other writer of the month runs.
	if err := q.AdvisoryXactLock(ctx, pg.LockKey(monthLockName(month))); err != nil {
		return Recorded{}, fmt.Errorf("audit: month lock: %w", err)
	}
	if _, err := q.EnsureEventsPartition(ctx, ts); err != nil {
		return Recorded{}, fmt.Errorf("audit: partition: %w", err)
	}
	prev, err := w.prevHash(ctx, q, month)
	if err != nil {
		return Recorded{}, err
	}
	id, err := q.NextEventID(ctx)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: next id: %w", err)
	}
	stored, err := q.NormalizeJSONB(ctx, payload)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: payload: %w", err)
	}
	canonical, err := CanonicalPayload([]byte(stored))
	if err != nil {
		return Recorded{}, err
	}
	row := Row{
		ID: id, TS: ts, ActorType: string(ev.Actor.Type), ActorID: ev.Actor.ID,
		Realm: optional(ev.Actor.Realm), Purpose: optional(ev.Purpose),
		EntityType: ev.EntityType, EntityID: optional(ev.EntityID), EventType: ev.EventType,
		Payload: canonical, PrevHash: prev,
	}
	hash, err := Hash(row)
	if err != nil {
		return Recorded{}, err
	}
	err = q.InsertEvent(ctx, gen.InsertEventParams{
		ID: row.ID, Ts: row.TS, ActorType: row.ActorType, ActorID: row.ActorID, Realm: row.Realm,
		Purpose: row.Purpose, EntityType: row.EntityType, EntityID: row.EntityID,
		EventType: row.EventType, Payload: canonical, PrevHash: prev, Hash: hash,
	})
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: insert: %w", err)
	}
	return Recorded{ID: id, TS: ts, PrevHash: prev, Hash: hash}, nil
}

// prevHash is the hash the next row of month links to: the month's last
// row, or for the month's first row the last row written before it in
// an earlier month (taking that month's lock, so a writer still
// finishing the previous month is waited for), or GenesisHash.
func (w *Writer) prevHash(ctx context.Context, q *gen.Queries, month time.Time) (string, error) {
	last, err := q.LastEventInRange(ctx, gen.LastEventInRangeParams{FromTs: month, ToTs: month.AddDate(0, 1, 0)})
	if err == nil {
		return last.Hash, nil
	}
	if !store.IsNoRows(err) {
		return "", fmt.Errorf("audit: last hash: %w", err)
	}
	if err := q.AdvisoryXactLock(ctx, pg.LockKey(monthLockName(month.AddDate(0, -1, 0)))); err != nil {
		return "", fmt.Errorf("audit: previous month lock: %w", err)
	}
	before, err := q.LastEventBefore(ctx, gen.LastEventBeforeParams{BeforeTs: month, BeforeID: maxID})
	if store.IsNoRows(err) {
		return GenesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: previous month hash: %w", err)
	}
	return before.Hash, nil
}

// maxID bounds "written before" when the new row has no id yet.
const maxID = int64(^uint64(0) >> 1)

func rowFrom(e *gen.Event) Row {
	return Row{
		ID: e.ID, TS: e.Ts, ActorType: e.ActorType, ActorID: e.ActorID, Realm: e.Realm,
		Purpose: e.Purpose, EntityType: e.EntityType, EntityID: e.EntityID, EventType: e.EventType,
		Payload: e.Payload, PrevHash: e.PrevHash, Hash: e.Hash,
	}
}
