package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// DeleteViolations deletes the violations closed more than
// ViolationsYears ago in batches of BatchRows, each batch one
// transaction with its retention_rows_deleted events row naming every
// id, at most MaxBatches per run. The database never deletes a held
// one (authority_retention_delete_violations): an active legal hold, an
// incident opened from it, an open incident's aircraft.
func (s *Service) DeleteViolations(ctx context.Context) (map[string]any, error) {
	batch, maxBatches := max(s.BatchRows, 1), max(s.MaxBatches, 1)
	total, batches := 0, 0
	complete := false
	for batches < maxBatches {
		var ids []string
		err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
			var err error
			ids, err = q.DeleteExpiredViolations(ctx, gen.DeleteExpiredViolationsParams{
				Years: int32(s.Periods.ViolationsYears), MaxRows: int32(batch),
			})
			if err != nil || len(ids) == 0 {
				return err
			}
			_, err = s.Audit.Record(ctx, q, audit.Event{Actor: s.actor(), EntityType: EntityViolations,
				EventType: audit.EventRetentionRowsDeleted, Payload: map[string]any{
					"table": "violations", "rows": len(ids), "violation_ids": ids,
					"rule":             fmt.Sprintf("closed more than %d years ago, held by nothing", s.Periods.ViolationsYears),
					"violations_years": s.Periods.ViolationsYears, "pending_gcaa": PendingGCAA,
				}})
			return err
		})
		if err != nil {
			return map[string]any{"deleted": total, "batches": batches}, fmt.Errorf("violations: %w", err)
		}
		batches++
		total += len(ids)
		s.add(CounterViolationsDeleted, int64(len(ids)))
		if len(ids) < batch {
			complete = true
			break
		}
	}
	if !complete {
		s.inc(CounterBatchesBounded)
	}
	s.logger().Info("violations past their retention deleted", slog.Int("deleted", total), slog.Int("batches", batches),
		slog.Int("violations_years", s.Periods.ViolationsYears), slog.Bool("left_for_next_run", !complete))
	return map[string]any{"deleted": total, "batches": batches, "left_for_next_run": !complete}, nil
}

// droppedMonth is authority_retention_drop_events_month's answer.
type droppedMonth struct {
	Partition string  `json:"partition"`
	Held      bool    `json:"held"`
	Rows      int64   `json:"rows"`
	FirstID   *int64  `json:"first_id"`
	LastID    *int64  `json:"last_id"`
	LastHash  *string `json:"last_hash"`
}

// DropAuditMonths drops the oldest months of the audit log that ended
// more than AuditYears ago, one per transaction with its
// audit_month_dropped events row (the month's rows, id range and last
// hash: the anchor the next month's verification links to). The oldest
// month goes first; a held one stops the run, since the anchor must
// always be the newest dropped month.
func (s *Service) DropAuditMonths(ctx context.Context) (map[string]any, error) {
	q := s.DB.Queries()
	var dropped []string
	held := ""
	for range max(s.MaxBatches, 1) {
		part, err := q.OldestEventsPartition(ctx)
		if store.IsNoRows(err) {
			break
		}
		if err != nil {
			return map[string]any{"dropped": dropped}, fmt.Errorf("audit months: %w", err)
		}
		month, err := audit.MonthOfPartition(part)
		if err != nil {
			return map[string]any{"dropped": dropped}, err
		}
		cutoff, err := q.AuditCutoff(ctx, int32(s.Periods.AuditYears))
		if err != nil {
			return map[string]any{"dropped": dropped}, fmt.Errorf("audit months: %w", err)
		}
		if month.AddDate(0, 1, 0).After(cutoff) {
			break
		}
		var res droppedMonth
		err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
			raw, err := q.DropEventsMonth(ctx, gen.DropEventsMonthParams{MonthStart: month, Years: int32(s.Periods.AuditYears)})
			if err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &res); err != nil {
				return fmt.Errorf("audit months: the drop's answer: %w", err)
			}
			if res.Held {
				return nil
			}
			_, err = s.Audit.Record(ctx, q, audit.Event{Actor: s.actor(), EntityType: EntityEvents, EntityID: month.Format("2006-01"),
				EventType: audit.EventAuditMonthDropped, Payload: map[string]any{
					"month": month.Format("2006-01"), "partition": res.Partition, "rows": res.Rows, "first_id": res.FirstID,
					"last_id": res.LastID, "last_hash": res.LastHash, "audit_years": s.Periods.AuditYears,
					"cutoff": cutoff.UTC().Format(time.RFC3339), "pending_gcaa": PendingGCAA,
				}})
			return err
		})
		if err != nil {
			return map[string]any{"dropped": dropped}, fmt.Errorf("audit month %s: %w", month.Format("2006-01"), err)
		}
		if res.Held {
			held = month.Format("2006-01")
			s.inc(CounterAuditMonthsHeld)
			s.logger().Info("the oldest month of the audit log is past its retention and held; it and the months after it stay",
				slog.String("month", held))
			break
		}
		dropped = append(dropped, month.Format("2006-01"))
		s.inc(CounterAuditMonthsDropped)
		s.logger().Info("audit month dropped after its retention; its last hash is the chain's anchor",
			slog.String("month", month.Format("2006-01")), slog.Int64("rows", res.Rows), slog.Int("audit_years", s.Periods.AuditYears))
	}
	return map[string]any{"dropped": dropped, "held": held}, nil
}

// ExpireArchive deletes the archived objects past ArchiveYears: the
// telemetry chunks' objects and manifests, and the USSP daily records
// bundles, at most ChunksPerRun of each per run, unless something holds
// them. An object's deletion and its events row are one relational
// transaction under the hold gate.
func (s *Service) ExpireArchive(ctx context.Context) (map[string]any, error) {
	if s.Store == nil {
		return map[string]any{"deleted": 0}, archive.ErrNotConfigured
	}
	limit := max(s.ChunksPerRun, 1)
	var deleted []string
	heldBy := map[string]string{}
	var errs []error
	if s.TS != nil {
		recs, err := s.TS.ExpiredObjects(ctx, s.Periods.ArchiveYears, limit)
		if err != nil {
			errs = append(errs, err)
		}
		for i := range recs {
			name, why, err := s.expireChunkObject(ctx, &recs[i])
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			case why != "":
				heldBy[name] = why
				s.inc(CounterObjectsHeld)
			default:
				deleted = append(deleted, name)
				s.inc(CounterObjectsDeleted)
			}
		}
	}
	days, err := s.DB.Queries().ExpiredUSSPDays(ctx, gen.ExpiredUSSPDaysParams{Years: int32(s.Periods.ArchiveYears), MaxRows: int32(limit)})
	if err != nil {
		errs = append(errs, err)
	}
	for i := range days {
		name, why, err := s.expireUSSPDay(ctx, &days[i])
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		case why != "":
			heldBy[name] = why
			s.inc(CounterObjectsHeld)
		default:
			deleted = append(deleted, name)
			s.inc(CounterObjectsDeleted)
		}
	}
	s.logger().Info("archived objects past their retention", slog.Int("deleted", len(deleted)), slog.Int("held", len(heldBy)),
		slog.Int("archive_years", s.Periods.ArchiveYears), slog.Int("failed", len(errs)))
	return map[string]any{"deleted": deleted, "held": heldBy}, errors.Join(errs...)
}

func (s *Service) expireChunkObject(ctx context.Context, r *ts.ChunkRecord) (name, held string, err error) {
	name = r.Table + "/" + r.Chunk
	deleted := false
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.HoldsGate(ctx); err != nil {
			return err
		}
		h, err := s.holdsOver(ctx, q, r.RangeStart, r.RangeEnd)
		if err != nil {
			return err
		}
		if h.All != "" {
			held = h.All
			return nil
		}
		open, err := q.OpenIncidentsAround(ctx, gen.OpenIncidentsAroundParams{FromTs: r.RangeStart.Add(-s.IncidentMargin), ToTs: r.RangeEnd.Add(s.IncidentMargin)})
		if err != nil {
			return err
		}
		if open {
			held = "an open incident occurred within the margin of the chunk's range"
			return nil
		}
		if len(h.TrackIDs)+len(h.Serials) > 0 {
			var m Manifest
			b, rerr := archive.Get(s.Store, r.ManifestKey, maxManifestBytes)
			if rerr == nil {
				rerr = json.Unmarshal(b, &m)
			}
			switch {
			case rerr != nil:
				// Unreadable is no reason to delete: the object is kept.
				held = "a hold names aircraft and the manifest cannot be read: " + rerr.Error()
				return nil //nolint:nilerr // an unreadable manifest keeps the object: a finding, not a failure
			case !m.AircraftComplete:
				held = "a hold names aircraft and the manifest does not list every aircraft of the chunk"
				return nil
			case h.matches(m.TrackIDs, m.Serials):
				held = "an aircraft of the chunk is named by a hold or an open incident"
				return nil
			}
		}
		for _, k := range []string{r.ObjectKey, r.ManifestKey} {
			if err := s.Store.Delete(k); err != nil && !errors.Is(err, archive.ErrNotFound) {
				return err
			}
		}
		if err := s.TS.MarkObjectDeleted(ctx, r.Table, r.Chunk); err != nil {
			return err
		}
		deleted = true
		return s.recordOnce(ctx, q, name, audit.EventArchiveObjectDeleted, map[string]any{
			"hypertable": r.Table, "chunk": r.Chunk, "object": r.ObjectKey, "manifest": r.ManifestKey, "sha256": r.SHA256,
			"range_start": r.RangeStart.UTC().Format(time.RFC3339), "range_end": r.RangeEnd.UTC().Format(time.RFC3339),
			"archive_years": s.Periods.ArchiveYears, "pending_gcaa": PendingGCAA,
		})
	})
	if err == nil && deleted {
		if merr := s.TS.MarkAudited(ctx, r.Table, r.Chunk, ts.StepDelete); merr != nil {
			s.logger().Warn("archived object deleted and audited; the ledger's mark is repeated by the next run", slog.String("error", merr.Error()))
		}
	}
	return name, held, err
}

func (s *Service) expireUSSPDay(ctx context.Context, r *gen.UsspDailyRecord) (name, held string, err error) {
	day := r.Day.UTC()
	name = "ussp-records/" + r.UsspCode + "/" + day.Format(time.DateOnly)
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.HoldsGate(ctx); err != nil {
			return err
		}
		h, err := s.holdsOver(ctx, q, day, day.AddDate(0, 0, 1))
		if err != nil {
			return err
		}
		// A bundle is opaque (no contract pins its body): any hold that
		// could cover its day keeps it.
		switch {
		case h.All != "":
			held = h.All
			return nil
		case len(h.TrackIDs)+len(h.Serials) > 0:
			held = "a hold or an open incident names aircraft of the day: " + fmt.Sprint(h.Why)
			return nil
		}
		if r.ArchiveKey != nil {
			if err := s.Store.Delete(*r.ArchiveKey); err != nil && !errors.Is(err, archive.ErrNotFound) {
				return err
			}
		}
		if err := q.MarkUSSPDayDeleted(ctx, gen.MarkUSSPDayDeletedParams{UsspCode: r.UsspCode, Day: r.Day}); err != nil {
			return err
		}
		_, err = s.Audit.Record(ctx, q, audit.Event{Actor: s.actor(), EntityType: EntityUSSPDay, EntityID: r.UsspCode + "/" + day.Format(time.DateOnly),
			EventType: audit.EventArchiveObjectDeleted, Payload: map[string]any{
				"ussp_code": r.UsspCode, "day": day.Format(time.DateOnly), "object": r.ArchiveKey, "sha256": r.Sha256,
				"archive_years": s.Periods.ArchiveYears, "pending_gcaa": PendingGCAA,
			}})
		return err
	})
	return name, held, err
}
