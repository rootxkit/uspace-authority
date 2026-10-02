package cisp

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// SenderActor is the actor of the sender's events rows.
var SenderActor = audit.SystemActor("cisp-sender")

// entityPublication is the entity_type of the outbox's events rows.
const entityPublication = "publication"

// MaxErrorChars bounds the error text stored with an attempt (the
// column's check, 2000 bytes, holds it in any script).
const MaxErrorChars = 500

// PG is OutboxStore and CacheStore on the relational database, writing
// every outbox state change's events row in the same transaction.
type PG struct {
	DB    *pg.DB
	Audit *audit.Writer
}

var (
	_ OutboxStore = PG{}
	_ CacheStore  = PG{}
)

// EnqueueTx writes p pending inside the caller's transaction q: under
// the dataset's outbox lock it supersedes the dataset's pending row
// (E-10: one pending snapshot per dataset; the superseded row is
// recorded), numbers the row (version, or the dataset's next when 0)
// and records publication_queued. zonesvc calls it from its publication
// transaction, so the row commits with the publication.
func EnqueueTx(ctx context.Context, q *gen.Queries, w *audit.Writer, p Prepared, version int64, actor audit.Actor) (Row, []int64, error) {
	ds := string(p.Dataset)
	if err := q.LockOutbox(ctx, ds); err != nil {
		return Row{}, nil, err
	}
	superseded, err := q.SupersedePendingOutbox(ctx, ds)
	if err != nil {
		return Row{}, nil, err
	}
	if version == 0 {
		if version, err = q.NextPublicationVersion(ctx, ds); err != nil {
			return Row{}, nil, err
		}
	}
	sig, kid, at := p.Signature, p.KID, p.SignedAt
	r, err := q.InsertOutboxRow(ctx, gen.InsertOutboxRowParams{
		Dataset: ds, Version: version, Payload: p.Payload, PayloadHash: p.PayloadHash, FeatureCount: int32(p.FeatureCount),
		ContentType: p.ContentType, Signature: &sig, SignatureKid: &kid, SignedAt: &at, CreatedBy: actor.ID,
	})
	if err != nil {
		return Row{}, nil, err
	}
	ids := make([]int64, 0, len(superseded))
	for _, s := range superseded {
		ids = append(ids, s.ID)
		if _, err := w.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: entityPublication, EntityID: idString(s.ID), EventType: audit.EventPublicationSuperseded,
			Payload: map[string]any{"dataset": ds, "version": s.Version, "superseded_by": r.ID},
		}); err != nil {
			return Row{}, nil, err
		}
	}
	if _, err := w.Record(ctx, q, audit.Event{
		Actor: actor, EntityType: entityPublication, EntityID: idString(r.ID), EventType: audit.EventPublicationQueued,
		Payload: map[string]any{
			"dataset": ds, "version": r.Version, "payload_hash": r.PayloadHash, "feature_count": r.FeatureCount,
			"signature_kid": kid, "superseded": ids,
		},
	}); err != nil {
		return Row{}, nil, err
	}
	return Row{
		ID: r.ID, Dataset: Dataset(r.Dataset), Version: r.Version, PayloadHash: r.PayloadHash, FeatureCount: int(r.FeatureCount),
		Signature: r.Signature, State: r.State, CreatedAt: r.CreatedAt,
	}, ids, nil
}

// Enqueue implements OutboxStore.
func (s PG) Enqueue(ctx context.Context, p Prepared, version int64, actor audit.Actor) (Row, error) {
	var row Row
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		var err error
		row, _, err = EnqueueTx(ctx, q, s.Audit, p, version, actor)
		return err
	})
	return row, err
}

// Due implements OutboxStore.
func (s PG) Due(ctx context.Context) ([]DueRow, error) {
	rows, err := s.DB.Queries().DuePublications(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DueRow, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, DueRow{
			ID: r.ID, Dataset: Dataset(r.Dataset), Version: r.Version, Payload: r.Payload, PayloadHash: r.PayloadHash,
			FeatureCount: int(r.FeatureCount), ContentType: r.ContentType, State: r.State, Attempts: int(r.Attempts),
			NextRetryAt: r.NextRetryAt, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// IfMatch implements OutboxStore.
func (s PG) IfMatch(ctx context.Context, ds Dataset, before int64) (int64, bool, error) {
	v, err := s.DB.Queries().IfMatchVersion(ctx, gen.IfMatchVersionParams{Dataset: string(ds), Before: before})
	if store.IsNoRows(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return v, true, nil
}

// mark runs one state change and its events row in a transaction; a row
// that was no longer in the expected state changes nothing and records
// nothing.
func (s PG) mark(ctx context.Context, r *DueRow, eventType string, payload map[string]any,
	fn func(q *gen.Queries) (int64, error)) (bool, error) {
	changed := false
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		n, err := fn(q)
		if err != nil || n == 0 {
			return err
		}
		changed = true
		payload["dataset"], payload["version"] = string(r.Dataset), r.Version
		_, err = s.Audit.Record(ctx, q, audit.Event{
			Actor: SenderActor, EntityType: entityPublication, EntityID: idString(r.ID), EventType: eventType, Payload: payload,
		})
		return err
	})
	return changed, err
}

// MarkSending implements OutboxStore.
func (s PG) MarkSending(ctx context.Context, r *DueRow, sig, kid string, signedAt time.Time) (bool, error) {
	return s.mark(ctx, r, audit.EventPublicationSent, map[string]any{"attempt": r.Attempts + 1, "signature_kid": kid},
		func(q *gen.Queries) (int64, error) {
			return q.MarkPublicationSending(ctx, gen.MarkPublicationSendingParams{ID: r.ID, Signature: &sig, SignatureKid: &kid, SignedAt: &signedAt})
		})
}

// MarkAcknowledged implements OutboxStore.
func (s PG) MarkAcknowledged(ctx context.Context, r *DueRow, cispVersion int64, o Outcome) error {
	st := int32(o.Status)
	_, err := s.mark(ctx, r, audit.EventPublicationAcknowledged, map[string]any{"cisp_version": cispVersion, "status": o.Status},
		func(q *gen.Queries) (int64, error) {
			return q.MarkPublicationAcknowledged(ctx, gen.MarkPublicationAcknowledgedParams{ID: r.ID, CispVersion: &cispVersion, LastStatus: &st})
		})
	return err
}

// MarkRetry implements OutboxStore.
func (s PG) MarkRetry(ctx context.Context, r *DueRow, next time.Time, o Outcome) error {
	reason := clip(o.Reason)
	_, err := s.mark(ctx, r, audit.EventPublicationRetry,
		map[string]any{"status": o.Status, "reason": reason, "next_retry_at": next.UTC().Format(time.RFC3339)},
		func(q *gen.Queries) (int64, error) {
			return q.MarkPublicationRetry(ctx, gen.MarkPublicationRetryParams{ID: r.ID, NextRetryAt: &next, LastStatus: status(o), LastError: &reason})
		})
	return err
}

// MarkFailed implements OutboxStore.
func (s PG) MarkFailed(ctx context.Context, r *DueRow, o Outcome) error {
	reason := clip(o.Reason)
	_, err := s.mark(ctx, r, audit.EventPublicationFailed, map[string]any{"status": o.Status, "reason": reason},
		func(q *gen.Queries) (int64, error) {
			return q.MarkPublicationFailed(ctx, gen.MarkPublicationFailedParams{ID: r.ID, LastStatus: status(o), LastError: &reason})
		})
	return err
}

// MarkConflict implements OutboxStore.
func (s PG) MarkConflict(ctx context.Context, r *DueRow, current *int64, o Outcome) error {
	reason, st := clip(o.Reason), int32(o.Status)
	_, err := s.mark(ctx, r, audit.EventPublicationConflict, map[string]any{"status": o.Status, "reason": reason, "cisp_current_version": current},
		func(q *gen.Queries) (int64, error) {
			return q.MarkPublicationConflict(ctx, gen.MarkPublicationConflictParams{ID: r.ID, ConflictVersion: current, LastStatus: &st, LastError: &reason})
		})
	return err
}

// List implements OutboxStore.
func (s PG) List(ctx context.Context, f ListFilter) ([]OutboxView, error) {
	p := gen.ListPublicationsParams{MaxRows: int32(f.Limit)}
	if f.Dataset != "" {
		d := string(f.Dataset)
		p.Dataset = &d
	}
	if f.State != "" {
		p.State = &f.State
	}
	rows, err := s.DB.Queries().ListPublications(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]OutboxView, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		v := OutboxView{
			ID: r.ID, Dataset: Dataset(r.Dataset), Version: r.Version, PayloadHash: r.PayloadHash, FeatureCount: int(r.FeatureCount),
			ContentType: r.ContentType, SignatureKID: r.SignatureKid, SignedAt: r.SignedAt, State: r.State, Attempts: int(r.Attempts),
			NextRetryAt: r.NextRetryAt, CISPVersion: r.CispVersion, ConflictVersion: r.ConflictVersion, LastAttemptAt: r.LastAttemptAt,
			LastError: r.LastError, AcknowledgedAt: r.AcknowledgedAt, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
			StateChangedAt: r.StateChangedAt, AgeS: r.AgeS,
		}
		if r.LastStatus != nil {
			n := int(*r.LastStatus)
			v.LastStatus = &n
		}
		out = append(out, v)
	}
	return out, nil
}

// Load implements CacheStore.
func (s PG) Load(ctx context.Context) ([]Cached, error) {
	rows, err := s.DB.Queries().LoadCISCache(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Cached, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		c := Cached{
			Dataset: Dataset(r.Dataset), Version: r.Version, ETag: r.Etag, UpdatedAt: r.CisUpdatedAt, FetchedAt: r.FetchedAt,
			CheckedAt: r.CheckedAt, FeatureCount: int(r.FeatureCount), Payload: r.Payload, AgeS: r.AgeS,
		}
		if r.PublisherKid != nil {
			c.PublisherKID = *r.PublisherKid
		}
		out = append(out, c)
	}
	return out, nil
}

// Save implements CacheStore.
func (s PG) Save(ctx context.Context, c *Cached) error {
	var kid *string
	if c.PublisherKID != "" {
		kid = &c.PublisherKID
	}
	_, err := s.DB.Queries().UpsertCISCache(ctx, gen.UpsertCISCacheParams{
		Dataset: string(c.Dataset), Version: c.Version, Etag: c.ETag, CisUpdatedAt: c.UpdatedAt,
		FeatureCount: int32(c.FeatureCount), PublisherKid: kid, Payload: c.Payload,
	})
	return err
}

// Touch implements CacheStore.
func (s PG) Touch(ctx context.Context, ds Dataset, version int64) error {
	_, err := s.DB.Queries().TouchCISCache(ctx, gen.TouchCISCacheParams{Dataset: string(ds), Version: version})
	return err
}

// RememberJTI implements CacheStore.
func (s PG) RememberJTI(ctx context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (bool, bool, error) {
	r, err := s.DB.Queries().RememberDeliveryJTI(ctx, gen.RememberDeliveryJTIParams{
		Issuer: issuer, Jti: jti, TtlS: ttl.Seconds(), MaxLive: maxLive,
	})
	if err != nil {
		return false, false, err
	}
	switch {
	case r.Inserted > 0:
		return true, false, nil
	case r.Seen:
		return false, false, nil
	}
	return false, true, nil
}

// SweepJTIs implements CacheStore.
func (s PG) SweepJTIs(ctx context.Context) (int64, error) {
	return s.DB.Queries().SweepDeliveryJTIs(ctx)
}

func status(o Outcome) *int32 {
	if o.Status == 0 {
		return nil
	}
	n := int32(o.Status)
	return &n
}

// clip bounds an error text for its column, on a rune boundary.
func clip(s string) string {
	r := []rune(s)
	if len(r) <= MaxErrorChars {
		return s
	}
	return string(r[:MaxErrorChars-1]) + "…"
}
