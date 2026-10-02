package zonesvc

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/auth"
)

// WP-6: a publication's outbox row carries the detached JWS of its exact
// bytes, which verifies with the publication key and not over other
// bytes (E-01 beside the refusal below).
func TestPublishSignsThePayloadForTheCISP(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	if _, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{})), true, inspector); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetZones, "TST001", 1, admin); err != nil {
		t.Fatal(err)
	}
	p, err := s.Publish(ctx, DatasetZones, admin)
	if err != nil {
		t.Fatal(err)
	}
	if p.Publication.Signature == nil || *p.Publication.Signature == "" {
		t.Fatalf("the outbox row is unsigned: %+v", p.Publication)
	}
	v, err := auth.NewDetachedVerifier(ctx, auth.DetachedConfig{
		Publishers: map[string]auth.IssuerConfig{"authority": {Keys: outboxRing.JWKS()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := st.payload(p.Publication.ID)
	sig, err := v.Verify(ctx, "authority", *p.Publication.Signature, payload)
	if err != nil || sig.KID != "test-publication" {
		t.Fatalf("%v %+v", err, sig)
	}
	other := []byte(strings.Replace(string(payload), "TST001", "TST002", 1))
	if _, err := v.Verify(ctx, "authority", *p.Publication.Signature, other); err == nil {
		t.Fatal("the signature verified over other bytes")
	}
}

// WP-6: a dataset the CISP would refuse (a DAR reason: dynamic
// restrictions are the ANSP's) is refused whole at publication, with the
// problem by path, before anything is signed or queued.
func TestPublishRefusesWhatTheCISPWouldRefuse(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	dar := strings.Replace(feature(zoneOpts{}), `"reason":["SENSITIVE"]`, `"reason":["DAR"]`, 1)
	if _, err := s.Draft(ctx, DatasetZones, draftIn(dar), true, inspector); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetZones, "TST001", 1, admin); err != nil {
		t.Fatal(err)
	}
	_, err := s.Publish(ctx, DatasetZones, admin)
	mustProblem(t, err, http.StatusBadRequest, "features[0].properties.reason", "published by the ANSP")
	if n := len(st.publications()); n != 0 {
		t.Fatalf("%d rows queued for a refused publication", n)
	}
}
