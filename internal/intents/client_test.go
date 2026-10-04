package intents

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/internal/dp"
)

type fakeTokens struct {
	mu     sync.Mutex
	err    error
	asked  []string
	scopes []string
}

func (f *fakeTokens) Token(_ context.Context, baseURL string, scopes ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, baseURL)
	f.scopes = append(f.scopes, scopes...)
	if f.err != nil {
		return "", f.err
	}
	return "tok", nil
}

func validResponse(refs ...f3548.OperationalIntentReference) []byte {
	if refs == nil {
		refs = []f3548.OperationalIntentReference{}
	}
	raw, _ := json.Marshal(f3548.QueryOperationalIntentReferenceResponse{OperationalIntentReferences: refs})
	return raw
}

// The query goes to /dss/v1/operational_intent_references/query with the
// area of interest as the body and a token for the DSS's host granting
// utm.conformance_monitoring_sa only (Q-A5); the answer is read through
// ParseQueryResponse.
func TestClientQueriesTheDSSWithTheConformanceMonitoringScope(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody f3548.QueryOperationalIntentReferenceParameters
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.Method+" "+r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write(validResponse(refOf("a", f3548.Activated, t0, t0.Add(time.Hour))))
	}))
	defer srv.Close()
	tok := &fakeTokens{}
	c := &Client{Tokens: tok, DSS: srv.URL + "/"}
	aoi, _ := zoneArea(uspaceZone("U1", 41.7, 44.8), t0, t0.Add(time.Hour))
	refs, err := c.Query(context.Background(), aoi)
	if err != nil || len(refs) != 1 || refs[0].Id != "a" {
		t.Fatalf("query: %v %v", refs, err)
	}
	if gotPath != "POST /dss/v1/operational_intent_references/query" || gotAuth != "Bearer tok" || gotBody.AreaOfInterest == nil ||
		gotBody.AreaOfInterest.Volume.OutlinePolygon == nil || len(gotBody.AreaOfInterest.Volume.OutlinePolygon.Vertices) != 4 {
		t.Fatalf("request %s %q %+v", gotPath, gotAuth, gotBody)
	}
	if len(tok.scopes) != 1 || tok.scopes[0] != string(f3548.ScopeConformanceMonitoringForSituationalAwareness) || tok.asked[0] != srv.URL+"/" {
		t.Fatalf("token asked %v %v", tok.asked, tok.scopes)
	}
}

// Every refusal of the client beside the accepted query above (E-01):
// no tokens, a token refused, a status other than 200, a body over the
// bound, a plain-http DSS that is not loopback, an answer that does not
// parse.
func TestClientRefusals(t *testing.T) {
	status, body := http.StatusOK, validResponse()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	aoi, _ := zoneArea(uspaceZone("U1", 41.7, 44.8), t0, t0.Add(time.Hour))
	ctx := context.Background()

	if _, err := (&Client{DSS: srv.URL}).Query(ctx, aoi); !errors.Is(err, ErrNoTokens) {
		t.Fatalf("no tokens: %v", err)
	}
	if _, err := (&Client{DSS: srv.URL, Tokens: &fakeTokens{err: errors.New("invalid_client")}}).Query(ctx, aoi); err == nil ||
		!strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("token refused: %v", err)
	}
	ok := &Client{DSS: srv.URL, Tokens: &fakeTokens{}}
	if refs, err := ok.Query(ctx, aoi); err != nil || len(refs) != 0 {
		t.Fatalf("empty answer: %v %v", refs, err)
	}
	status = http.StatusForbidden
	if _, err := ok.Query(ctx, aoi); dp.StatusOf(err) != http.StatusForbidden {
		t.Fatalf("403: %v", err)
	}
	status, body = http.StatusOK, []byte(`{"operational_intent_references":[`+strings.Repeat(" ", 2048)+`]}`)
	small := &Client{DSS: srv.URL, Tokens: &fakeTokens{}, MaxBody: 1024}
	if _, err := small.Query(ctx, aoi); !errors.Is(err, dp.ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	body = []byte(`{"operational_intent_references":[{"id":""}]}`)
	if _, err := ok.Query(ctx, aoi); err == nil {
		t.Fatal("an invalid reference was accepted")
	}
	if _, err := (&Client{DSS: "http://dss.example.test", Tokens: &fakeTokens{}}).Query(ctx, aoi); !errors.Is(err, dp.ErrPlainHTTP) {
		t.Fatalf("plain http: %v", err)
	}
}

// ParseQueryResponse refuses each member the matching rests on, naming
// it, beside the valid answer it starts from (E-01).
func TestParseQueryResponseRefusesEachMemberItChecks(t *testing.T) {
	good := refOf("a", f3548.Activated, t0, t0.Add(time.Hour))
	if refs, err := ParseQueryResponse(validResponse(good), 10); err != nil || len(refs) != 1 {
		t.Fatalf("valid: %v %v", refs, err)
	}
	// Unknown members are ignored.
	if _, err := ParseQueryResponse([]byte(`{"operational_intent_references":[],"extra":1}`), 10); err != nil {
		t.Fatalf("unknown member: %v", err)
	}
	long := strings.Repeat("x", maxIDBytes+1)
	cases := map[string]struct {
		mutate func(*f3548.OperationalIntentReference)
		field  string
	}{
		"no id":         {func(r *f3548.OperationalIntentReference) { r.Id = "" }, ".id"},
		"long manager":  {func(r *f3548.OperationalIntentReference) { r.Manager = long }, ".manager"},
		"long base url": {func(r *f3548.OperationalIntentReference) { r.UssBaseUrl = long }, ".uss_base_url"},
		"state":         {func(r *f3548.OperationalIntentReference) { r.State = "Ended" }, ".state"},
		"start format":  {func(r *f3548.OperationalIntentReference) { r.TimeStart.Format = "unix" }, ".time_start"},
		"no end":        {func(r *f3548.OperationalIntentReference) { r.TimeEnd = f3548.Time{Format: f3548.RFC3339} }, ".time_end"},
		"end first":     {func(r *f3548.OperationalIntentReference) { r.TimeEnd.Value = t0.Add(-time.Second) }, ".time_end"},
	}
	for name, c := range cases {
		r := good
		c.mutate(&r)
		_, err := ParseQueryResponse(validResponse(good, r), 10)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != "response.operational_intent_references[1]"+c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"not json": `{`, "no list": `{}`, "wrong type": `{"operational_intent_references":[{"id":7}]}`,
	} {
		if _, err := ParseQueryResponse([]byte(raw), 10); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// E-10: one past the bound is refused whole; at the bound it is read.
	if _, err := ParseQueryResponse(validResponse(good, good), 1); !errors.Is(err, ErrTooManyRefs) {
		t.Fatalf("over the bound: %v", err)
	}
	if refs, err := ParseQueryResponse(validResponse(good, good), 2); err != nil || len(refs) != 2 {
		t.Fatalf("at the bound: %v %v", refs, err)
	}
	if _, err := ParseQueryResponse(make([]byte, f3548.MaxMessageBytes+1), 10); err == nil {
		t.Fatal("an answer over MaxMessageBytes was read")
	}
}

// ParseQueryResponse never panics, and whatever it accepts holds the
// checks the matching rests on.
func FuzzParseQueryResponse(f *testing.F) {
	f.Add(validResponse(refOf("a", f3548.Activated, t0, t0.Add(time.Hour))))
	f.Add([]byte(`{"operational_intent_references":[{"id":"x","state":"Accepted","time_start":{"format":"RFC3339","value":"2026-10-04T12:00:00Z"},"time_end":{"format":"RFC3339","value":"2026-10-04T11:00:00Z"}}]}`))
	f.Add([]byte(`{"operational_intent_references":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		refs, err := ParseQueryResponse(raw, 8)
		if err != nil {
			return
		}
		if len(refs) > 8 {
			t.Fatalf("%d references past the bound", len(refs))
		}
		for i := range refs {
			if err := checkRef(&refs[i]); err != nil {
				t.Fatalf("accepted a reference that fails its checks: %v", err)
			}
		}
	})
}
