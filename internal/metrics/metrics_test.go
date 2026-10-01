package metrics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

func TestCountersCollectorExposesEveryCounterAsAGauge(t *testing.T) {
	reg := NewRegistry()
	c := &core.Counters{}
	reg.MustRegister(NewCountersCollector("ridpipe", c))
	if out := scrape(t, Handler(reg)); strings.Contains(out, "rejected_signature") {
		t.Fatal("a counter that never moved should not be exposed yet")
	}
	c.Add("rejected_signature", 7)
	c.Inc("Bad-Name")
	out := scrape(t, Handler(reg))
	for _, want := range []string{
		`uspace_authority_rejected_signature{component="ridpipe"} 7`,
		`uspace_authority_bad_name{component="ridpipe"} 1`,
		"# TYPE uspace_authority_rejected_signature gauge",
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
}

func TestHTTPMiddlewareLabelsByPattern(t *testing.T) {
	reg := NewRegistry()
	m := NewHTTP(reg, "public")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/things/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := m.Middleware(mux)
	for _, p := range []string{"/v1/things/1", "/v1/things/2", "/nope"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	out := scrape(t, Handler(reg))
	if !strings.Contains(out, `uspace_authority_http_request_duration_seconds_count{code="418",method="GET",route="GET /v1/things/{id}",server="public"} 2`) {
		t.Errorf("pattern label missing:\n%s", out)
	}
	if !strings.Contains(out, `code="404",method="GET",route="unmatched"`) {
		t.Errorf("unmatched label missing")
	}
}

func TestNATSWrapTimesByOutcome(t *testing.T) {
	reg := NewRegistry()
	m := NewNATS(reg)
	ok := m.Wrap("trk.v1.>", func([]byte) error { return nil })
	bad := m.Wrap("trk.v1.>", func([]byte) error { return errors.New("x") })
	_ = ok(nil)
	if err := bad(nil); err == nil {
		t.Fatal("the handler's error was swallowed")
	}
	out := scrape(t, Handler(reg))
	for _, want := range []string{`nats_message_duration_seconds_count{outcome="ok",subject="trk.v1.>"} 1`, `outcome="error",subject="trk.v1.>"} 1`} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
}

func TestMetricName(t *testing.T) {
	if got := MetricName("dp_unavailable"); got != "uspace_authority_dp_unavailable" {
		t.Errorf("got %s", got)
	}
}
