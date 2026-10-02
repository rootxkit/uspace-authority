package receivers

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/auth"
)

func intp(v int) *int           { return &v }
func floatp(v float64) *float64 { return &v }

var testDefaults = Defaults{BatchIntervalMS: 1000, BacklogCap: 50000, HeartbeatIntervalS: 10, PositionToleranceM: 100}

// E-01, E-15: a valid config passes; each member out of bounds is named,
// and a zero or non-finite tolerance is refused rather than disarming
// the deviation check.
func TestConfigValidate(t *testing.T) {
	ok := Config{BatchIntervalMS: intp(500), BacklogCap: intp(10), HeartbeatIntervalS: intp(10), PositionToleranceM: floatp(50),
		ReportingFields: []string{"transmitter", "rx_ts"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := testDefaults.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, c := range map[string]Config{
		"interval":      {BatchIntervalMS: intp(1001)},
		"backlog":       {BacklogCap: intp(0)},
		"heartbeat":     {HeartbeatIntervalS: intp(301)},
		"zero tol":      {PositionToleranceM: floatp(0)},
		"nan tol":       {PositionToleranceM: floatp(math.NaN())},
		"inf tol":       {PositionToleranceM: floatp(math.Inf(1))},
		"unknown field": {ReportingFields: []string{"altitude"}},
		"twice":         {ReportingFields: []string{"rx_ts", "rx_ts"}},
		"too many":      {ReportingFields: []string{"a", "b", "c", "d", "e", "f"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (Defaults{}).Validate(); err == nil {
		t.Error("zero defaults accepted")
	}
}

func TestConfigResolveFillsOnlyWhatIsMissing(t *testing.T) {
	r := Config{BatchIntervalMS: intp(200)}.Resolve(testDefaults)
	if *r.BatchIntervalMS != 200 || *r.BacklogCap != 50000 || *r.HeartbeatIntervalS != 10 || *r.PositionToleranceM != 100 ||
		len(r.ReportingFields) != len(ReportingFields) {
		t.Fatalf("%+v", r)
	}
	r2 := Config{ReportingFields: []string{"rx_ts"}}.Resolve(testDefaults)
	if len(r2.ReportingFields) != 1 {
		t.Fatalf("%+v", r2)
	}
}

// Every refusal of core's verifier maps to its status and slug: never
// 403 (B-10), replay 409, skew 401 skew, the rest of authentication 401
// signature, malformed 400; the detail is core's phrase.
func TestVerifyRefusalMapsEveryCoreCounter(t *testing.T) {
	cases := map[string][3]any{
		auth.CounterRejectedUnsigned:        {http.StatusUnauthorized, SlugSignature, ReasonUnsigned},
		auth.CounterRejectedUnknownReceiver: {http.StatusUnauthorized, SlugSignature, ReasonUnknownReceiver},
		auth.CounterRejectedBadSignature:    {http.StatusUnauthorized, SlugSignature, ReasonBadSignature},
		auth.CounterRejectedSkew:            {http.StatusUnauthorized, SlugSkew, ReasonSkew},
		auth.CounterRejectedReplay:          {http.StatusConflict, SlugReplay, ReasonReplay},
		auth.CounterRejectedMalformed:       {http.StatusBadRequest, SlugValidation, ReasonMalformed},
	}
	for counter, want := range cases {
		f := VerifyRefusal(&auth.ReceiverError{Counter: counter, Reason: "phrase of " + counter})
		if f.Status != want[0] || f.Slug != want[1] || f.Counter != want[2] || f.Detail != "phrase of "+counter {
			t.Errorf("%s: %+v", counter, f)
		}
	}
	if f := VerifyRefusal(http.ErrBodyNotAllowed); f.Status != http.StatusBadRequest {
		t.Errorf("foreign error: %+v", f)
	}
}

// B-10: a 503 carries Retry-After; a 401 names the bearer realm; the
// body is a problem with the slug.
func TestRefusalWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	AuthRefusal(ErrBusy).Write(rec, httptest.NewRequest(http.MethodPost, "/v1/rid/observations", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), "/busy") {
		t.Fatalf("busy: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	rec = httptest.NewRecorder()
	AuthRefusal(ErrUnauthenticated).Write(rec, httptest.NewRequest(http.MethodPost, "/v1/rid/observations", nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("unauthenticated: %d %v", rec.Code, rec.Header())
	}
}

func TestNewReceiverValidate(t *testing.T) {
	ok := NewReceiver{ID: "rx-tbs-01", Name: "Tbilisi 1", LatDeg: 41.7, LonDeg: 44.8, Owner: OwnerAuthority}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 201)
	for name, mutate := range map[string]func(n *NewReceiver){
		"id":         func(n *NewReceiver) { n.ID = "Rx 1" },
		"label":      func(n *NewReceiver) { n.Name = "" },
		"position":   func(n *NewReceiver) { n.LonDeg = 181 },
		"owner":      func(n *NewReceiver) { n.Owner = "gcaa" },
		"owner name": func(n *NewReceiver) { n.OwnerName = &long },
		"config":     func(n *NewReceiver) { n.Config.BatchIntervalMS = intp(5) },
	} {
		n := ok
		mutate(&n)
		if err := n.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
