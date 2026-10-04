package regportal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
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
