package audit

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the chain verification (WP-27, spec 06 §2 T7).
const (
	CounterChainVerified = "audit_chain_months_verified"
	CounterChainBroken   = "audit_chain_months_broken" // the alarm: a month whose chain does not hold
	CounterChainFailed   = "audit_chain_verify_failed" // a verification that could not run (not a finding)
)

// Verification ways, recorded in the audit_chain_verified row.
const (
	ViaSchedule = "schedule"
	ViaRequest  = "request"
)

// JobActor is the actor of the scheduled verification.
const JobActor = "audit-verify"

// MaxVerifyMonths bounds the months one run verifies (E-10): ten years
// of retention is 120 months, and a run that would need more says so.
const MaxVerifyMonths = 240

// ChainVerifier verifies months of the chain and records each
// verification in the chain itself (an audit_chain_verified row), so a
// verification is evidence too. A broken month is an alarm: counted,
// logged at error level and named on the status line until a later
// verification of that month holds.
type ChainVerifier struct {
	Writer   *Writer
	Counters *core.Counters
	Logger   *slog.Logger

	mu     sync.Mutex
	broken map[string]string // month -> reason of its last broken verification
	last   time.Time
}

// NewChainVerifier returns a verifier on w.
func NewChainVerifier(w *Writer, counters *core.Counters, logger *slog.Logger) *ChainVerifier {
	if counters == nil {
		counters = &core.Counters{}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &ChainVerifier{Writer: w, Counters: counters, Logger: logger, broken: map[string]string{}}
}

// Load reads each month's newest recorded verification, so a month
// found broken before a restart is still named broken after it.
func (v *ChainVerifier) Load(ctx context.Context) error {
	rows, err := v.Writer.DB.Queries().LatestChainVerifications(ctx, MaxVerifyMonths)
	if err != nil {
		return fmt.Errorf("audit verify: last verifications: %w", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, r := range rows {
		if !r.Intact {
			v.broken[r.Month] = r.Reason
		}
		if r.Ts.After(v.last) {
			v.last = r.Ts
		}
	}
	return nil
}

// VerifyMonth verifies the month holding at and records the result,
// attributed to actor, with via (schedule or request).
func (v *ChainVerifier) VerifyMonth(ctx context.Context, actor Actor, at time.Time, via string) (Result, time.Time, error) {
	res, err := v.Writer.Verify(ctx, at)
	if err != nil {
		v.Counters.Inc(CounterChainFailed)
		return res, time.Time{}, err
	}
	payload := map[string]any{
		"month": res.Month, "via": via, "rows": res.Rows, "first_id": res.FirstID, "last_id": res.LastID,
		"last_hash": res.LastHash, "anchored_to": res.AnchoredTo, "intact": res.Broken == nil,
	}
	if res.Broken != nil {
		payload["broken"] = map[string]any{"id": res.Broken.ID, "ts": res.Broken.TS.UTC().Format(time.RFC3339Nano),
			"reason": res.Broken.Reason, "want": res.Broken.Want, "got": res.Broken.Got}
	}
	var recorded Recorded
	err = v.Writer.DB.WithTx(ctx, func(q *gen.Queries) error {
		var err error
		recorded, err = v.Writer.Record(ctx, q, Event{Actor: actor, EntityType: "events", EntityID: res.Month,
			EventType: EventAuditChainVerified, Payload: payload})
		return err
	})
	if err != nil {
		v.Counters.Inc(CounterChainFailed)
		return res, time.Time{}, fmt.Errorf("audit verify %s: record: %w", res.Month, err)
	}
	v.Counters.Inc(CounterChainVerified)
	v.mu.Lock()
	v.last = recorded.TS
	if res.Broken != nil {
		v.broken[res.Month] = res.Broken.Reason
	} else {
		delete(v.broken, res.Month)
	}
	v.mu.Unlock()
	if res.Broken != nil {
		v.Counters.Inc(CounterChainBroken)
		v.Logger.Error("audit chain broken: a row of the month does not hold its hash or its link (spec 06 T7); see docs/runbooks/retention.md",
			slog.String("month", res.Month), slog.Int64("row_id", res.Broken.ID), slog.String("reason", res.Broken.Reason),
			slog.Int64("rows_checked", res.Rows), slog.String("via", via))
	} else {
		v.Logger.Info("audit chain verified", slog.String("month", res.Month), slog.Int64("rows", res.Rows),
			slog.Int64("first_id", res.FirstID), slog.Int64("last_id", res.LastID), slog.String("anchored_to", res.AnchoredTo),
			slog.String("via", via))
	}
	return res, recorded.TS, nil
}

// VerifyAll verifies every month the log holds, oldest first, and
// returns a summary for the job ledger. A month that cannot be verified
// fails the run after the others were tried.
func (v *ChainVerifier) VerifyAll(ctx context.Context) (map[string]any, error) {
	parts, err := v.Writer.DB.Queries().EventsMonths(ctx, MaxVerifyMonths+1)
	if err != nil {
		v.Counters.Inc(CounterChainFailed)
		return nil, fmt.Errorf("audit verify: months: %w", err)
	}
	if len(parts) > MaxVerifyMonths {
		v.Counters.Inc(CounterChainFailed)
		return nil, fmt.Errorf("audit verify: the log holds more than %d months; verify them on request (GET /v1/audit/verify)", MaxVerifyMonths)
	}
	actor := SystemActor(JobActor)
	var rows int64
	var intact, broken, failed []string
	for _, p := range parts {
		month, err := monthOfPartition(p)
		if err != nil {
			failed = append(failed, p)
			continue
		}
		res, _, err := v.VerifyMonth(ctx, actor, month, ViaSchedule)
		switch {
		case err != nil:
			failed = append(failed, month.Format("2006-01"))
			v.Logger.Error("audit chain verification could not run; the month is unverified",
				slog.String("month", month.Format("2006-01")), slog.String("error", err.Error()))
		case res.Broken != nil:
			broken = append(broken, res.Month)
		default:
			intact = append(intact, res.Month)
		}
		rows += res.Rows
	}
	sum := map[string]any{"months": len(parts), "rows": rows, "intact": len(intact), "broken": broken, "failed": failed}
	if len(failed) > 0 {
		return sum, fmt.Errorf("audit verify: %d months could not be verified: %s", len(failed), strings.Join(failed, ", "))
	}
	return sum, nil
}

// monthOfPartition is the month of an events partition (events_YYYY_MM).
func monthOfPartition(name string) (time.Time, error) {
	rest, ok := strings.CutPrefix(name, "events_")
	if !ok {
		return time.Time{}, fmt.Errorf("audit: %q is not a month partition of events", name)
	}
	t, err := time.Parse("2006_01", rest)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit: %q is not a month partition of events", name)
	}
	return t.UTC(), nil
}

// MonthOfPartition is monthOfPartition for the retention job.
func MonthOfPartition(name string) (time.Time, error) { return monthOfPartition(name) }

// StatusAttrs name the months whose last verification found the chain
// broken (an empty list says every month verified so far holds) and
// when the last verification was recorded.
func (v *ChainVerifier) StatusAttrs() []slog.Attr {
	v.mu.Lock()
	defer v.mu.Unlock()
	months := make([]string, 0, len(v.broken))
	for m := range v.broken {
		months = append(months, m)
	}
	slices.Sort(months)
	attrs := []slog.Attr{slog.Any("audit_chain_broken_months", months)}
	if !v.last.IsZero() {
		attrs = append(attrs, slog.String("audit_chain_last_verified", v.last.UTC().Format(time.RFC3339)))
	} else {
		attrs = append(attrs, slog.String("audit_chain_last_verified", "never"))
	}
	return attrs
}
