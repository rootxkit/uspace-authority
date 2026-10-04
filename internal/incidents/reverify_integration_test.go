package incidents

import (
	"context"
	"slices"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/violations"
)

// WP-27, spec 06 T7: the monthly re-verification recomputes every
// stored pack's hash: on untouched packs every check holds and the run
// is recorded with its counts (the success line, E-02); a pack changed
// in storage is found, named in the run's events row and counted as
// tampered (the alarm), each check recorded as evidence_pack_verified
// via schedule. A bound below the packs held fails the run and says so.
func TestIntegrationMonthlyReverificationFindsATamperedPack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	zoneID, _ := f.violations()
	f.telemetry()
	if _, err := f.vio.Review(ctx, inspector, zoneID, violations.DecisionEscalated, sp("note")); err != nil {
		t.Fatal(err)
	}
	rows, _ := f.inc.List(ctx, listByViolation(zoneID))
	incID := rows[0].IncidentID
	first, err := f.packs.Create(ctx, inspector, false, incID, f.request(KindOversight))
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.packs.Create(ctx, inspector, false, incID, f.request(KindOversight))
	if err != nil {
		t.Fatal(err)
	}

	sum, err := f.packs.ReverifyAll(ctx, 100)
	if err != nil || sum["checked"] != 2 || sum["intact"] != 2 || len(sum["tampered"].([]string)) != 0 {
		t.Fatalf("clean run %v %v", sum, err)
	}
	if _, payload := f.lastEvent(incID, audit.EventEvidencePackVerified); payload["via"] != audit.ViaSchedule {
		t.Fatalf("check recorded %v", payload)
	}

	f.tamperFile(second.StorageRef)
	tampered := f.packs.Counters.Get(CounterPackTampered)
	sum, err = f.packs.ReverifyAll(ctx, 100)
	if err != nil || sum["intact"] != 1 || !slices.Equal(sum["tampered"].([]string), []string{second.PackID}) {
		t.Fatalf("tampered run %v %v", sum, err)
	}
	if f.packs.Counters.Get(CounterPackTampered) != tampered+1 {
		t.Fatal("the tampered pack is not counted")
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM events WHERE event_type = $1 AND payload->'tampered' ? $2`,
		audit.EventEvidencePacksReverified, second.PackID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("run rows naming the pack: %d %v", n, err)
	}

	sum, err = f.packs.ReverifyAll(ctx, 1)
	if err == nil || sum["truncated"] != true || sum["checked"] != 1 {
		t.Fatalf("bounded run %v %v", sum, err)
	}
	_ = first
}
