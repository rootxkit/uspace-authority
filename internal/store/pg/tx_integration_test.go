package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

func TestIntegrationWithTxCommitsOnNilAndRollsBackOnError(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	db := open(t, u, pg.AppRole)
	ctx := context.Background()
	count := func() int64 {
		v, err := db.Queries().MaxPolicyVersion(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	insert := func(q *gen.Queries, v int64) error {
		_, err := q.InsertPolicy(ctx, gen.InsertPolicyParams{
			Version: v, HeightLimitAglM: 120, PressureUncertaintyM: 250, ZoneConditionalSeverity: "warning",
			MismatchSeverity: "warning", IdentificationSeverity: "critical", SpoofDistanceM: 300, IdentityTtlS: 15,
			MaxGapS: 3, IdentifyWithinS: 4, BroadcastToleranceS: 1, MaxLatencyS: 5, LiveMaxAgeS: 10, ClearAfterS: 3,
			StaleAfterS: 15, DpViewDiagonalKm: 7, DpPollHz: 1, CisStaleBoundS: 300, HeightLimitInUspace: "evaluate", RegistrationNumberPattern: "^[A-Z]{3}[A-Za-z0-9]{8,16}$", CertificateLapseUnusedMonths: 6, CertificateLapseCeasedMonths: 12,
			NoAuthorisationGraceS: 10, NoAuthorisationSeverity: "warning", CreatedBy: "test",
		})
		return err
	}
	boom := errors.New("boom")
	err := db.WithTx(ctx, func(q *gen.Queries) error {
		if err := insert(q, 2); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) || count() != 1 {
		t.Fatalf("rollback: err %v, max version %d", err, count())
	}
	if err := db.WithTx(ctx, func(q *gen.Queries) error { return insert(q, 2) }); err != nil || count() != 2 {
		t.Fatalf("commit: err %v, max version %d", err, count())
	}
}

func TestIntegrationAppRoleCannotUpdatePolicyThresholds(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	db := open(t, u, pg.AppRole)
	ctx := context.Background()
	q := db.Queries()
	// The activation columns are granted ...
	if err := q.DeactivatePolicies(ctx); err != nil {
		t.Fatalf("UPDATE of active refused: %v", err)
	}
	// ... the thresholds are not: a version is never edited.
	_, err := db.Exec(ctx, "UPDATE authority_policy SET height_limit_agl_m = 500")
	if store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("UPDATE of a threshold as %s: %v", pg.AppRole, err)
	}
}
