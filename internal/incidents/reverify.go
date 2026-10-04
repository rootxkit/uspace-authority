package incidents

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the monthly re-verification (WP-27, spec 06 §2 T7).
const (
	CounterReverifyRuns   = "evidence_reverify_runs"
	CounterReverifyFailed = "evidence_reverify_failed" // a pack the run could not check, or a run that stopped
)

// ReverifyActor is the actor of the scheduled re-verification.
const ReverifyActor = "evidence-reverify"

// reverifyPage bounds the packs read per query.
const reverifyPage = 200

// ReverifyAll recomputes every stored pack's hash against storage and
// its seal's signature, oldest first, at most maxPacks, recording each
// check as WP-17's evidence_pack_verified row (via "schedule") and the
// run as one evidence_packs_reverified row with its counts and the
// packs found tampered or unreadable. A tampered pack is the alarm
// (counted as evidence_packs_tampered, logged at error level); an
// unreadable one is an outage, not tampering, and is said as such.
// Each check waits for a read slot rather than being refused, so the
// job never skips a pack because a download was running.
func (p *Packs) ReverifyAll(ctx context.Context, maxPacks int) (map[string]any, error) {
	if err := p.storageOK(); err != nil {
		return nil, err
	}
	p.inc(CounterReverifyRuns)
	actor := audit.SystemActor(ReverifyActor)
	var checked, intact, unsigned int
	var tampered, unreadable, failed []string
	after, afterID := time.Unix(0, 0).UTC(), ""
	more := false
	for {
		rows, err := p.Service.DB.Queries().PacksToReverify(ctx, gen.PacksToReverifyParams{
			AfterCreated: after, AfterPack: afterID, MaxRows: reverifyPage,
		})
		if err != nil {
			p.inc(CounterReverifyFailed)
			return nil, fmt.Errorf("evidence reverify: list: %w", err)
		}
		for _, r := range rows {
			if checked >= maxPacks {
				more = true
				break
			}
			after, afterID = r.CreatedAt, r.PackID
			checked++
			v, err := p.reverifyOne(ctx, actor, r.IncidentID, r.PackID)
			switch {
			case err != nil:
				failed = append(failed, r.PackID)
				p.inc(CounterReverifyFailed)
				logger(p.Logger).Error("evidence pack re-verification could not run; the pack is unchecked",
					slog.String("pack_id", r.PackID), slog.String("error", err.Error()))
			case v.tampered():
				tampered = append(tampered, r.PackID)
				logger(p.Logger).Error("evidence pack tampered: the stored archive or its seal no longer matches what was sealed (06 T7); see docs/runbooks/retention.md",
					slog.String("pack_id", r.PackID), slog.String("incident_id", r.IncidentID), slog.String("problem", deref(v.Problem)))
			case v.Unreadable:
				unreadable = append(unreadable, r.PackID)
				logger(p.Logger).Error("evidence pack unreadable: whether it matches its seal is unknown",
					slog.String("pack_id", r.PackID), slog.String("problem", deref(v.Problem)))
			default:
				intact++
				if v.Signature == SigUnsigned || v.Signature == SigUnverifiable {
					unsigned++
				}
			}
		}
		if more || len(rows) < reverifyPage {
			break
		}
	}
	sum := map[string]any{"checked": checked, "intact": intact, "unsigned_or_unverifiable": unsigned,
		"tampered": tampered, "unreadable": unreadable, "failed": failed, "truncated": more}
	err := p.Service.DB.WithTx(ctx, func(q *gen.Queries) error {
		_, err := p.Service.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityType,
			EventType: audit.EventEvidencePacksReverified, Payload: sum})
		return err
	})
	if err != nil {
		return sum, fmt.Errorf("evidence reverify: record: %w", err)
	}
	logger(p.Logger).Info("evidence packs re-verified", slog.Int("checked", checked), slog.Int("intact", intact),
		slog.Int("tampered", len(tampered)), slog.Int("unreadable", len(unreadable)), slog.Int("failed", len(failed)))
	switch {
	case more:
		return sum, fmt.Errorf("evidence reverify: more than %d packs (EVIDENCE_REVERIFY_MAX): the rest were not checked", maxPacks)
	case len(failed) > 0:
		return sum, fmt.Errorf("evidence reverify: %d packs could not be checked", len(failed))
	}
	return sum, nil
}

// reverifyOne checks one pack, waiting for a read slot.
func (p *Packs) reverifyOne(ctx context.Context, actor audit.Actor, incidentID, packID string) (Verification, error) {
	if p.readSem != nil {
		select {
		case p.readSem <- struct{}{}:
			defer func() { <-p.readSem }()
		case <-ctx.Done():
			return Verification{}, ctx.Err()
		}
	}
	row, err := p.Get(ctx, incidentID, packID)
	if err != nil {
		return Verification{}, err
	}
	v, _ := p.check(ctx, &row)
	p.inc(CounterPackVerified)
	p.countCheck(&v)
	if err := p.recordVerification(ctx, actor, &row, &v, audit.ViaSchedule); err != nil {
		return Verification{}, err
	}
	return v, nil
}
