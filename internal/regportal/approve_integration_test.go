package regportal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// stubRegistry is the registry with CreateOperator replaced by create
// when it is set.
type stubRegistry struct {
	Registry
	create func(ctx context.Context, in registry.NewOperator, actor audit.Actor) (registry.Operator, error)
}

func (r *stubRegistry) CreateOperator(ctx context.Context, in registry.NewOperator, actor audit.Actor) (registry.Operator, error) {
	if r.create != nil {
		return r.create(ctx, in, actor)
	}
	return r.Registry.CreateOperator(ctx, in, actor)
}

// stub replaces the service's registry with a stubRegistry over it.
func (it *itest) stub(t *testing.T) *stubRegistry {
	t.Helper()
	s := &stubRegistry{Registry: it.svc.Registry}
	it.svc.Registry = s
	t.Cleanup(func() { it.svc.Registry = s.Registry })
	return s
}

// underReview submits an application from ip, follows its link and
// takes it for review.
func (it *itest) underReview(t *testing.T, ip string) Application {
	t.Helper()
	ctx := context.Background()
	app, err := it.svc.Submit(ctx, applicant(), "en", ip)
	if err != nil {
		t.Fatal(err)
	}
	it.send(t)
	if _, err := it.svc.Verify(ctx, app.ID, tokenOf(t, it.mail.last(t).body)); err != nil {
		t.Fatal(err)
	}
	r, err := it.svc.StartReview(ctx, app.ID, registrar)
	if err != nil || r.State != StateUnderReview {
		t.Fatalf("review %+v %v", r, err)
	}
	return r
}

// An approval that chose a number and then failed in the registry
// leaves the number and its sealed secret part on the application; a
// refusal of it must still go through and drop both. Both ways an
// approval half-fails: a registry fault (the secret stays) and a number
// taken meanwhile (ClearApplicationIssuedNumber drops it first).
func TestIntegrationRefuseAfterAHalfFailedApproval(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	reg := it.stub(t)
	for i, c := range []struct {
		name       string
		err        error
		wantSecret int
	}{
		{"registry fault", errors.New("registry unavailable"), 1},
		{"number taken", httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "this registration number is registered already"), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			app := it.underReview(t, fmt.Sprintf("192.0.2.%d", 50+i))
			reg.create = func(context.Context, registry.NewOperator, audit.Actor) (registry.Operator, error) {
				return registry.Operator{}, c.err
			}
			if _, err := it.svc.Approve(ctx, app.ID, nil, registrar); err == nil {
				t.Fatal("the approval did not fail")
			}
			if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE id = $1 AND state = 'under_review' AND secret_enc IS NOT NULL`, app.ID); n != c.wantSecret {
				t.Fatalf("%d applications under review hold a secret part, want %d", n, c.wantSecret)
			}
			r, err := it.svc.Refuse(ctx, app.ID, "documents incomplete", registrar)
			if err != nil || r.State != StateRefused || r.IssuedNumber != "" || r.ValidUntil != nil {
				t.Fatalf("refuse %+v %v", r, err)
			}
			if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE id = $1 AND (secret_enc IS NOT NULL OR issued_number IS NOT NULL)`, app.ID); n != 0 {
				t.Fatal("the refused application kept what the approval chose")
			}
			if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, app.ID); n != 0 {
				t.Fatal("an operator was registered for the refused application")
			}
		})
	}
}

// A refusal racing an approval: while the approval registers the
// operator it holds the application's row lock, so the refusal cannot
// decide the application under it; once the approval commits, the
// refusal finds it approved (409). Without the lock the refusal
// committed in between and the registry kept an operator for a refused
// application.
func TestIntegrationRefusalWaitsForAnApprovalInFlight(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	reg := it.stub(t)
	app := it.underReview(t, "192.0.2.60")
	var refuseErr error
	reg.create = func(ctx context.Context, in registry.NewOperator, actor audit.Actor) (registry.Operator, error) {
		// The refusal runs to its end, or to its deadline, while the
		// registration is still in progress.
		rctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := it.svc.Refuse(rctx, app.ID, "documents incomplete", registrar)
			done <- err
		}()
		refuseErr = <-done
		return reg.Registry.CreateOperator(ctx, in, actor)
	}
	approved, err := it.svc.Approve(ctx, app.ID, nil, registrar)
	if refuseErr == nil {
		t.Fatal("a refusal decided the application while its approval was registering the operator")
	}
	if err != nil || approved.State != StateApproved {
		t.Fatalf("approve %+v %v", approved, err)
	}
	reg.create = nil
	if _, err := it.svc.Refuse(ctx, app.ID, "documents incomplete", registrar); httpx.ProblemFromError(err).Status != http.StatusConflict {
		t.Fatalf("refused after the approval: %v", err)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE id = $1 AND state = 'approved'`, app.ID); n != 1 {
		t.Fatal("the approval did not stand")
	}
}

// An approval that registered the operator and then failed before its
// decision is finished by approving again; a refusal of it is 409, so
// the registry never keeps an operator for a refused application.
func TestIntegrationHalfFinishedApprovalIsNotRefused(t *testing.T) {
	it := newIntegration(t)
	reg := it.stub(t)
	app := it.underReview(t, "192.0.2.61")
	actx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg.create = func(ctx context.Context, in registry.NewOperator, actor audit.Actor) (registry.Operator, error) {
		op, err := reg.Registry.CreateOperator(ctx, in, actor)
		cancel() // the decision's statements fail after the registration committed
		return op, err
	}
	if _, err := it.svc.Approve(actx, app.ID, nil, registrar); err == nil {
		t.Fatal("the approval did not fail")
	}
	reg.create = nil
	ctx := context.Background()
	if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, app.ID); n != 1 {
		t.Fatalf("%d operators registered", n)
	}
	if _, err := it.svc.Refuse(ctx, app.ID, "documents incomplete", registrar); httpx.ProblemFromError(err).Status != http.StatusConflict {
		t.Fatalf("a half-finished approval was refused: %v", err)
	}
	approved, err := it.svc.Approve(ctx, app.ID, nil, registrar)
	if err != nil || approved.State != StateApproved {
		t.Fatalf("approve again %+v %v", approved, err)
	}
	if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, app.ID); n != 1 {
		t.Fatal("the retried approval registered the operator twice")
	}
}

// Many approvals and refusals of the same applications at once: each
// application ends approved with one operator, or refused with none.
func TestIntegrationApproveAndRefuseRace(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	apps := make([]Application, 3)
	for i := range apps {
		apps[i] = it.underReview(t, fmt.Sprintf("192.0.2.%d", 70+i))
	}
	var wg sync.WaitGroup
	for _, a := range apps {
		for range 2 {
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = it.svc.Approve(ctx, a.ID, nil, registrar) }()
			go func() { defer wg.Done(); _, _ = it.svc.Refuse(ctx, a.ID, "documents incomplete", registrar) }()
		}
	}
	wg.Wait()
	for _, a := range apps {
		approved := it.count(t, `SELECT count(*) FROM registry_applications WHERE id = $1 AND state = 'approved'`, a.ID)
		refused := it.count(t, `SELECT count(*) FROM registry_applications WHERE id = $1 AND state = 'refused'`, a.ID)
		ops := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, a.ID)
		if approved+refused != 1 || ops != approved {
			t.Fatalf("%s: approved %d refused %d operators %d", a.ID, approved, refused, ops)
		}
	}
}

// A retried approval approves what the first one chose: with another
// valid_until it is 409 and nothing changes; with the same one, or none,
// it finishes the approval with the first one's validity.
func TestIntegrationRetriedApprovalKeepsItsValidity(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	reg := it.stub(t)
	app := it.underReview(t, "192.0.2.90")
	first := time.Now().UTC().Add(400 * 24 * time.Hour).Truncate(time.Second)
	reg.create = func(context.Context, registry.NewOperator, audit.Actor) (registry.Operator, error) {
		return registry.Operator{}, errors.New("registry unavailable")
	}
	if _, err := it.svc.Approve(ctx, app.ID, &first, registrar); err == nil {
		t.Fatal("the approval did not fail")
	}
	reg.create = nil
	other := first.Add(24 * time.Hour)
	_, err := it.svc.Approve(ctx, app.ID, &other, registrar)
	if p := httpx.ProblemFromError(err); p.Status != http.StatusConflict || len(p.Errors) != 1 || p.Errors[0].Field != "valid_until" {
		t.Fatalf("retried with another valid_until: %v", err)
	}
	if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE source_ref = $1`, app.ID); n != 0 {
		t.Fatal("the refused retry registered the operator")
	}
	approved, err := it.svc.Approve(ctx, app.ID, &first, registrar)
	if err != nil || approved.State != StateApproved || approved.ValidUntil == nil || !approved.ValidUntil.Equal(first) {
		t.Fatalf("retried with the same valid_until %+v %v", approved, err)
	}
	app2 := it.underReview(t, "192.0.2.91")
	reg.create = func(context.Context, registry.NewOperator, audit.Actor) (registry.Operator, error) {
		return registry.Operator{}, errors.New("registry unavailable")
	}
	if _, err := it.svc.Approve(ctx, app2.ID, &first, registrar); err == nil {
		t.Fatal("the approval did not fail")
	}
	reg.create = nil
	approved, err = it.svc.Approve(ctx, app2.ID, nil, registrar)
	if err != nil || approved.ValidUntil == nil || !approved.ValidUntil.Equal(first) {
		t.Fatalf("retried without a valid_until %+v %v", approved, err)
	}
}

// dbAhead is how far the shifted database clock runs ahead of the
// process's in TestIntegrationApprovalTimesByTheDatabaseClock.
const dbAhead = 2 * time.Hour

// An approval's instants are the database's, never the replica's: with
// the database clock dbAhead ahead (now() resolved through a schema
// ahead of pg_catalog for the service's connections), a valid_until
// that is future only by the replica's clock is refused, and the
// default validity runs from the database's now.
func TestIntegrationApprovalTimesByTheDatabaseClock(t *testing.T) {
	it := newIntegrationWith(t, func(u string) string {
		if _, err := storetest.Open(t, u).ExecContext(context.Background(), `CREATE SCHEMA clock;
			CREATE FUNCTION clock.now() RETURNS timestamptz LANGUAGE sql STABLE AS $$ SELECT pg_catalog.now() + interval '2 hours' $$;
			GRANT USAGE ON SCHEMA clock TO PUBLIC`); err != nil {
			t.Fatal(err)
		}
		return u + "&search_path=clock,public,pg_catalog"
	})
	ctx := context.Background()
	if now, err := it.svc.DB.Queries().DBNow(ctx); err != nil || time.Until(now) < dbAhead-time.Minute {
		t.Fatalf("the database clock is not shifted: %v %v", now, err)
	}
	app := it.underReview(t, "192.0.2.95")
	soon := time.Now().Add(dbAhead / 2)
	_, err := it.svc.Approve(ctx, app.ID, &soon, registrar)
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "valid_until" {
		t.Fatalf("a valid_until past by the database clock: %v", err)
	}
	approved, err := it.svc.Approve(ctx, app.ID, nil, registrar)
	if err != nil || approved.ValidUntil == nil {
		t.Fatalf("approve %+v %v", approved, err)
	}
	if early := time.Now().Add(it.svc.Config.Validity + dbAhead - time.Minute); approved.ValidUntil.Before(early) {
		t.Fatalf("valid until %v runs from the replica's clock (want after %v)", approved.ValidUntil, early)
	}
}
