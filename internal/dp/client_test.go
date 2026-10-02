package dp_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const issuerURL = "https://authority.example.test"

// issuer gives tokens as tokens.Client does: aud the host of the target
// base URL (M18), the scopes asked, signed with a run-time key.
type issuer struct {
	t   testing.TB
	iss *auth.Issuer
	mu  sync.Mutex
	n   int
	err error
}

func newIssuer(t testing.TB) *issuer {
	t.Helper()
	iss, err := auth.NewIssuer(issuerURL, tokentest.Key(t, 0), "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{t: t, iss: iss}
}

func (i *issuer) Token(_ context.Context, baseURL string, scopes ...string) (string, error) {
	i.mu.Lock()
	i.n++
	err := i.err
	i.mu.Unlock()
	if err != nil {
		return "", err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	return i.iss.Issue("authority-01", u.Hostname(), scopes, 10*time.Minute, time.Now())
}

func (i *issuer) issue(sub, aud string, scopes ...string) string {
	tok, err := i.iss.Issue(sub, aud, scopes, 10*time.Minute, time.Now())
	if err != nil {
		i.t.Fatal(err)
	}
	return tok
}

func (i *issuer) verifier(t testing.TB, audiences ...string) *auth.Verifier {
	t.Helper()
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{issuerURL: {Keys: i.iss.JWKS()}}, Audiences: audiences, StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

var (
	lat, lon = 41.7151, 44.8271
	box      = dp.Box{MinLat: lat - 0.005, MinLon: lon - 0.006, MaxLat: lat + 0.005, MaxLon: lon + 0.006}
)

func f32(v float32) *float32 { return &v }
func f64(v float64) *float64 { return &v }
func str(v string) *string   { return &v }

func ridFlight(id string, ts time.Time, la, lo float64) f3411.RIDFlight {
	st := f3411.Airborne
	return f3411.RIDFlight{Id: id, AircraftType: f3411.Helicopter, CurrentState: &f3411.RIDAircraftState{
		Timestamp: f3411.Time{Format: f3411.RFC3339, Value: ts.UTC()}, TimestampAccuracy: 0.1, SpeedAccuracy: f3411.SA1mps,
		Position: f3411.RIDAircraftPosition{Lat: f64(la), Lng: f64(lo), Alt: f32(600)}, Speed: f32(5), Track: f32(90),
		OperationalStatus: &st,
	}}
}

// The client speaks the pinned contract against a server generated from
// the same file: the DSS calls carry rid.display_provider with aud the
// DSS's host, the poll aud the Service Provider's host (M18); the
// flights are read through core's reader with their bytes kept.
func TestClientAgainstTheGeneratedFakes(t *testing.T) {
	dss, sp := fakedss.NewDSS(), fakedss.NewSP()
	defer dss.Close()
	defer sp.Close()
	iss := newIssuer(t)
	c := &dp.Client{Tokens: iss, MaxBody: 1 << 20, DSS: dss.URL(), HTTP: dp.NoRedirectClient()}
	now := time.Now()
	dss.PutISA("isa-1", "ussp-lab-01", sp.URL(), box, now.Add(-time.Minute), now.Add(time.Hour))
	isas, err := c.SearchISAs(context.Background(), box, now, now.Add(time.Minute))
	if err != nil || len(isas) != 1 || isas[0].UssBaseUrl != sp.URL() {
		t.Fatalf("%+v %v", isas, err)
	}
	resp, err := c.PutSubscription(context.Background(), dp.NewUUID(), "", box, now, now.Add(24*time.Hour), "http://127.0.0.1:1")
	if err != nil || resp.Subscription.Version == "" || resp.ServiceAreas == nil || len(*resp.ServiceAreas) != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	sp.SetFlights([]f3411.RIDFlight{ridFlight("fl-1", now, lat, lon)},
		map[string]f3411.RIDFlightDetails{"fl-1": {Id: "fl-1", UasId: &f3411.UASID{SerialNumber: str("TESTA0000000001")}}})
	fr, raws, err := c.Flights(context.Background(), sp.URL(), box)
	if err != nil || fr.Flights == nil || len(*fr.Flights) != 1 || len(raws) != 1 || !strings.Contains(string(raws[0]), `"fl-1"`) {
		t.Fatalf("%+v %v", fr, err)
	}
	d, raw, err := c.Details(context.Background(), sp.URL(), "fl-1")
	if err != nil || *d.UasId.SerialNumber != "TESTA0000000001" || !strings.Contains(string(raw), "TESTA0000000001") {
		t.Fatalf("%+v %v", d, err)
	}
	host := func(raw string) string { u, _ := url.Parse(raw); return u.Hostname() }
	for _, cl := range dss.Claims() {
		if cl.Aud != host(dss.URL()) || cl.Scope != string(f3411.ScopeDisplayProvider) {
			t.Errorf("DSS call %s: aud %q scope %q", cl.Path, cl.Aud, cl.Scope)
		}
	}
	for _, cl := range sp.Claims() {
		if cl.Aud != host(sp.URL()) || cl.Scope != string(f3411.ScopeDisplayProvider) {
			t.Errorf("SP call %s: aud %q scope %q", cl.Path, cl.Aud, cl.Scope)
		}
	}
}

// R-14: an answer over the body cap is refused (ErrTooLarge), one under
// it read; a 413 is an HTTPError with its status; without tokens nothing
// is sent; plain http to a non-loopback host is refused before any call.
func TestClientBoundsAndRefusals(t *testing.T) {
	sp := fakedss.NewSP()
	defer sp.Close()
	now := time.Now()
	var many []f3411.RIDFlight
	for i := range 50 {
		many = append(many, ridFlight("fl-"+string(rune('A'+i)), now, lat, lon))
	}
	sp.SetFlights(many, nil)
	c := &dp.Client{Tokens: newIssuer(t), MaxBody: 2048}
	if _, _, err := c.Flights(context.Background(), sp.URL(), box); !errors.Is(err, dp.ErrTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
	c.MaxBody = 1 << 20
	if _, _, err := c.Flights(context.Background(), sp.URL(), box); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	sp.SetStatus(413)
	if _, _, err := c.Flights(context.Background(), sp.URL(), box); dp.StatusOf(err) != 413 {
		t.Fatalf("413: %v", err)
	}
	sp.SetStatus(0)
	polls, _ := sp.Counts()
	none := &dp.Client{MaxBody: 1 << 20}
	if _, _, err := none.Flights(context.Background(), sp.URL(), box); !errors.Is(err, dp.ErrNoTokens) {
		t.Fatalf("without tokens: %v", err)
	}
	if _, _, err := c.Flights(context.Background(), "http://sp.example.test", box); !errors.Is(err, dp.ErrPlainHTTP) {
		t.Fatalf("plain http: %v", err)
	}
	if after, _ := sp.Counts(); after != polls {
		t.Fatalf("%d calls sent without a token or over plain http", after-polls)
	}
}

// ParseDetails bounds every identifier and refuses an operator location
// outside WGS84; a well-formed details body is read (E-01).
func TestParseDetailsBounds(t *testing.T) {
	ok := `{"details":{"id":"fl-1","uas_id":{"serial_number":"TESTA0000000001"},"operator_id":"GEO-OP-1","operator_location":{"position":{"lat":41.7,"lng":44.8}}}}`
	d, err := dp.ParseDetails([]byte(ok))
	if err != nil || *d.OperatorId != "GEO-OP-1" {
		t.Fatalf("%+v %v", d, err)
	}
	for name, raw := range map[string]string{
		"no id":         `{"details":{}}`,
		"long serial":   `{"details":{"id":"x","uas_id":{"serial_number":"` + strings.Repeat("S", 300) + `"}}}`,
		"bad location":  `{"details":{"id":"x","operator_location":{"position":{"lat":91,"lng":0}}}}`,
		"not json":      `{`,
		"wrong type":    `{"details":{"id":7}}`,
		"too large":     `{"details":{"id":"` + strings.Repeat("x", 70<<10) + `"}}`,
		"long operator": `{"details":{"id":"x","operator_id":"` + strings.Repeat("o", 300) + `"}}`,
	} {
		if _, err := dp.ParseDetails([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseDetails(f *testing.F) {
	f.Add([]byte(`{"details":{"id":"fl-1","uas_id":{"serial_number":"TESTA0000000001"},"operator_id":"GEO-OP-1"}}`))
	f.Add([]byte(`{"details":{"id":"x","operator_location":{"position":{"lat":41,"lng":44}}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := dp.ParseDetails(raw)
		if err != nil {
			return
		}
		if d.Id == "" {
			t.Fatal("accepted without an id")
		}
		if l := d.OperatorLocation; l != nil && !l.Position.LatLon().Valid() {
			t.Fatal("accepted a location outside WGS84")
		}
	})
}

func FuzzParseFlights(f *testing.F) {
	f.Add([]byte(`{"timestamp":{"value":"2026-10-02T12:00:00Z","format":"RFC3339"},"flights":[]}`))
	f.Add([]byte(`{"timestamp":{"value":"2026-10-02T12:00:00Z","format":"RFC3339"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, raws, err := dp.ParseFlights(raw)
		if err != nil {
			return
		}
		n := 0
		if r.Flights != nil {
			n = len(*r.Flights)
		}
		if n != len(raws) {
			t.Fatalf("%d flights, %d raw", n, len(raws))
		}
	})
}
