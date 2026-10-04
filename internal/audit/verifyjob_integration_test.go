package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// WP-27, spec 06 T7: the scheduled verification passes a clean chain
// and records each month's verification as an events row in the chain
// (presence of the success line, E-02); a tampered row is found, counted
// and named on the status line (the alarm), and a verifier started
// after a restart still names the broken month before it verifies
// anything.
func TestIntegrationScheduledVerificationRecordsItselfAndAlarmsOnABreak(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var recs []Recorded
	for i := range 3 {
		recs = append(recs, f.record(t, jan.Add(time.Duration(i)*time.Millisecond), map[string]any{"n": i}))
	}
	f.record(t, feb, map[string]any{"n": 9})
	counters := &core.Counters{}
	v := NewChainVerifier(f.w, counters, slog.New(slog.DiscardHandler))

	sum, err := v.VerifyAll(ctx)
	if err != nil || sum["intact"] != 2 || len(sum["broken"].([]string)) != 0 || sum["rows"] != int64(4) {
		t.Fatalf("clean: %v %v", sum, err)
	}
	var n int
	if err := f.admin.QueryRow(`SELECT count(*) FROM events WHERE event_type = $1 AND payload->>'intact' = 'true'`, EventAuditChainVerified).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d verification rows: %v", n, err)
	}
	if counters.Get(CounterChainVerified) != 2 || counters.Get(CounterChainBroken) != 0 {
		t.Fatalf("counters %v", counters.Snapshot())
	}

	conn, err := f.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE events SET payload = '{"n": 1000}' WHERE id = $1`, recs[1].ID); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	sum, err = v.VerifyAll(ctx)
	if err != nil || !slices.Equal(sum["broken"].([]string), []string{"2026-01"}) {
		t.Fatalf("tampered: %v %v", sum, err)
	}
	if counters.Get(CounterChainBroken) != 1 {
		t.Fatalf("the break is not counted: %v", counters.Snapshot())
	}
	if got := brokenOf(v); !slices.Equal(got, []string{"2026-01"}) {
		t.Fatalf("status %v", got)
	}
	var raw []byte
	var broken map[string]any
	if err := f.admin.QueryRow(`SELECT payload->'broken' FROM events WHERE event_type = $1 AND entity_id = '2026-01' ORDER BY id DESC LIMIT 1`,
		EventAuditChainVerified).Scan(&raw); err != nil || json.Unmarshal(raw, &broken) != nil || broken["id"] == nil || broken["reason"] != BrokenHash {
		t.Fatalf("recorded break %s %v", raw, err)
	}

	restarted := NewChainVerifier(f.w, nil, nil)
	if err := restarted.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got := brokenOf(restarted); !slices.Equal(got, []string{"2026-01"}) {
		t.Fatalf("after a restart %v", got)
	}
}

func brokenOf(v *ChainVerifier) []string {
	for _, a := range v.StatusAttrs() {
		if a.Key == "audit_chain_broken_months" {
			if m, ok := a.Value.Any().([]string); ok {
				return m
			}
		}
	}
	return nil
}
