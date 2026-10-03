package cisp

import (
	"context"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// Audit A-N4, E-10: the live delivery ids are bounded per issuer. One
// issuer past the bound is refused (full) and the other's next delivery
// is still remembered; a replay is a replay, not a refusal.
func TestIntegrationDeliveryIDsAreBoundedPerIssuer(t *testing.T) {
	ctx := context.Background()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(ctx, store.PoolOptions{URL: u, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	st := PG{DB: db, Audit: audit.NewWriter(db)}
	remember := func(issuer, jti string) (bool, bool) {
		t.Helper()
		fresh, full, err := st.RememberJTI(ctx, issuer, jti, time.Hour, 2)
		if err != nil {
			t.Fatal(err)
		}
		return fresh, full
	}
	for _, j := range []string{"a-1", "a-2"} {
		if fresh, full := remember("https://cisp.test", j); !fresh || full {
			t.Fatalf("%s: fresh %v full %v", j, fresh, full)
		}
	}
	if fresh, full := remember("https://cisp.test", "a-3"); fresh || !full {
		t.Fatalf("past the bound: fresh %v full %v", fresh, full)
	}
	if fresh, full := remember("https://cisp.test", "a-1"); fresh || full {
		t.Fatalf("a replay: fresh %v full %v", fresh, full)
	}
	if fresh, full := remember("https://ansp.test", "b-1"); !fresh || full {
		t.Fatalf("the other issuer is refused by the first one's flood: fresh %v full %v", fresh, full)
	}
}
