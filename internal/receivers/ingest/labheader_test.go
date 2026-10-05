package ingest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// postLab is fixture.post with the lab scenario header set.
func (f *fixture) postLab(t *testing.T, bearer, body, sig string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	f.h.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/rid/observations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	req.Header.Set(receivers.SignatureHeader, sig)
	req.Header.Set(receivers.LabScenarioHeader, "SC-07")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// T11: a batch naming a lab scenario is refused by an ingest that does
// not admit lab headers (the default), naming the header, storing
// nothing and counting the reason; the same batch is accepted where
// LAB_HEADERS_ALLOWED is true (E-01); and a request without a
// credential is still told 401 first.
func TestLabScenarioHeaderRefusedUnlessAdmitted(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-lab-01", nil)
	body := func(f *fixture, nonce string) string {
		return batchBody("rx-lab-01", f.now.UnixMilli(), nonce, false, obs(tx1, payload(1, 3), "2026-10-02T09:15:05.000Z"))
	}

	t.Run("refused by default", func(t *testing.T) {
		f := newFixture(t, r)
		b := body(f, "n-lab-1")
		rec := f.postLab(t, r.bearer, b, sign(r.secret, b))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		p := problemOf(t, rec.Body.String())
		if !strings.HasSuffix(p.Type, "/"+receivers.SlugLabHeader) || len(p.Errors) != 1 || p.Errors[0].Field != receivers.LabScenarioHeader {
			t.Fatalf("problem %+v", p)
		}
		if len(f.queue.batches) != 0 || f.counters.Get(receivers.ReasonLabHeader) != 1 || f.counters.Get(CounterBatchesRefused) != 1 {
			t.Fatalf("queued %d, counters %v", len(f.queue.batches), f.counters.Snapshot())
		}
	})

	t.Run("accepted where admitted", func(t *testing.T) {
		f := newFixture(t, r)
		f.h.LabHeadersAllowed = true
		b := body(f, "n-lab-2")
		rec := f.postLab(t, r.bearer, b, sign(r.secret, b))
		if rec.Code != http.StatusAccepted || len(f.queue.batches) != 1 || f.counters.Get(receivers.ReasonLabHeader) != 0 {
			t.Fatalf("%d %s, queued %d, counters %v", rec.Code, rec.Body.String(), len(f.queue.batches), f.counters.Snapshot())
		}
	})

	t.Run("no credential is 401 before the header is judged", func(t *testing.T) {
		f := newFixture(t, r)
		b := body(f, "n-lab-3")
		rec := f.postLab(t, "", b, sign(r.secret, b))
		if rec.Code != http.StatusUnauthorized || !strings.HasSuffix(problemOf(t, rec.Body.String()).Type, "/"+httpx.SlugUnauthn) ||
			f.counters.Get(receivers.ReasonLabHeader) != 0 {
			t.Fatalf("%d %s, counters %v", rec.Code, rec.Body.String(), f.counters.Snapshot())
		}
	})
}
