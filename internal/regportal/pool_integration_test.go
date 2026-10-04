package regportal

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// smallPool bounds the relational pool of the pool tests; more
// applications than that are worked on at once.
const (
	smallPool    = 3
	poolAtOnce   = 3 * smallPool
	poolDeadline = 30 * time.Second
)

// atOnce runs fn for every application at the same time, each bounded
// by poolDeadline, and fails the test on any error. A step that held
// one pooled connection while it waited for a second never finished
// once every connection was held that way: pgxpool waits for a free
// connection until the context ends.
func atOnce(t *testing.T, apps []Application, fn func(ctx context.Context, a Application) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), poolDeadline)
	defer cancel()
	start := make(chan struct{})
	errs := make([]error, len(apps))
	var wg sync.WaitGroup
	for i := range apps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(ctx, apps[i])
		}()
	}
	began := time.Now()
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("%s: %v", apps[i].ID, err)
		}
	}
	if took := time.Since(began); took >= poolDeadline {
		t.Fatalf("%d at once on a pool of %d took %v", len(apps), smallPool, took)
	}
}

func (it *itest) manyUnderReview(t *testing.T, n int) []Application {
	t.Helper()
	apps := make([]Application, n)
	for i := range apps {
		apps[i] = it.underReview(t, fmt.Sprintf("198.51.100.%d", 10+i))
	}
	return apps
}

// More first approvals at once than the pool has connections choose
// their numbers: the number is checked on the connection that holds the
// application's row lock, so none waits for another connection.
func TestIntegrationChooseNumberBeyondThePool(t *testing.T) {
	it := newIntegrationPool(t, func(u string) string { return u }, smallPool)
	apps := it.manyUnderReview(t, poolAtOnce)
	atOnce(t, apps, func(ctx context.Context, a Application) error {
		_, _, _, err := it.svc.chooseNumber(ctx, a.ID, nil)
		return err
	})
	if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE issued_number IS NOT NULL AND secret_enc IS NOT NULL`); n != poolAtOnce {
		t.Fatalf("%d applications hold a number, want %d", n, poolAtOnce)
	}
}

// More approvals at once than the pool has connections all finish: the
// registration and the decision run on the one connection that holds
// the application's row lock, so no approval holds a connection while
// it waits for another. Each ends approved with one operator.
func TestIntegrationApprovalsBeyondThePool(t *testing.T) {
	it := newIntegrationPool(t, func(u string) string { return u }, smallPool)
	apps := it.manyUnderReview(t, poolAtOnce)
	atOnce(t, apps, func(ctx context.Context, a Application) error {
		r, err := it.svc.Approve(ctx, a.ID, nil, registrar)
		if err == nil && r.State != StateApproved {
			return fmt.Errorf("approved as %s", r.State)
		}
		return err
	})
	for i := range apps {
		if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, apps[i].ID); n != 1 {
			t.Fatalf("%s: %d operators", apps[i].ID, n)
		}
	}
}
