package zonesvc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/cisp"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Invented zones around Tbilisi for tests; no real restriction.

var (
	t0        = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	t1        = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
	testNow   = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) // a Monday
	inspector = audit.Actor{Type: audit.ActorUser, ID: "inspector-1", Realm: audit.RealmConsole}
	admin     = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}
)

// zoneOpts shapes a test feature.
type zoneOpts struct {
	typ        string
	geometry   string // a whole geometry member; default a square polygon
	limited    string // a limitedApplicability member value; default absent
	upperRef   string
	extended   string
	identifier string
}

// square is a closed ring around (lat, lon) of half-side d degrees.
func square(lat, lon, d float64) string {
	return fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`,
		lon-d, lat-d, lon+d, lat-d, lon+d, lat+d, lon-d, lat+d, lon-d, lat-d)
}

func polygon(lat, lon, d float64, upperRef string) string {
	return fmt.Sprintf(`{"type":"Polygon","coordinates":%s,"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":%q,"uom":"m"}}`,
		square(lat, lon, d), upperRef)
}

func circle(lat, lon, radiusM float64) string {
	return fmt.Sprintf(`{"type":"Point","coordinates":[%g,%g],"extent":{"subType":"Circle","radius":%g},"layer":{"lower":0,"lowerReference":"AGL","upper":2500,"upperReference":"AMSL","uom":"ft"}}`,
		lon, lat, radiusM)
}

func feature(o zoneOpts) string {
	if o.typ == "" {
		o.typ = "PROHIBITED"
	}
	if o.upperRef == "" {
		o.upperRef = "AMSL"
	}
	if o.geometry == "" {
		o.geometry = polygon(41.7, 44.8, 0.01, o.upperRef)
	}
	if o.identifier == "" {
		o.identifier = "TST001"
	}
	props := fmt.Sprintf(`"identifier":%q,"country":"GEO","name":[{"text":"Test zone %s","lang":"en-GB"}],"type":%q,"variant":"COMMON","reason":["SENSITIVE"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]`,
		o.identifier, o.identifier, o.typ)
	if o.limited != "" {
		props += `,"limitedApplicability":` + o.limited
	}
	if o.extended != "" {
		props += `,"extendedProperties":` + o.extended
	}
	return fmt.Sprintf(`{"type":"Feature","geometry":%s,"properties":{%s}}`, o.geometry, props)
}

func collection(features ...string) string {
	return `{"type":"FeatureCollection","features":[` + strings.Join(features, ",") + `]}`
}

func ptr[T any](v T) *T { return &v }

func newService(t *testing.T) (*Service, *memStore, *memProjection, *memPublisher) {
	t.Helper()
	st, pr, pub := newMemStore(testNow), newMemProjection(), &memPublisher{}
	s := &Service{Store: st, Projection: pr, Publisher: pub, Daylight: NoDaylight{}, Counters: &core.Counters{},
		Meta: Meta{ProviderName: "Test authority", ProviderLang: "en-GB"}, Outbox: testOutbox(t)}
	return s, st, pr, pub
}

var (
	outboxOnce sync.Once
	outboxRing *auth.KeyRing
	errOutbox  error
)

// testOutbox is WP-6's outbox with a publication key generated at run
// time: every publication these tests make is held to the CISP's
// checks (the pinned api/clients/cisp-schemas) and signed, as in api.
func testOutbox(t *testing.T) *cisp.Outbox {
	t.Helper()
	outboxOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			errOutbox = err
			return
		}
		outboxRing, errOutbox = auth.NewKeyRing(auth.SigningKey{KID: "test-publication", Key: key})
	})
	if errOutbox != nil {
		t.Fatal(errOutbox)
	}
	schemas, err := cisp.LoadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	return cisp.NewOutbox(schemas, outboxRing, nil, nil)
}

// problemOf is the problem err carries.
func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	if err == nil {
		t.Fatal("no error, want a problem")
	}
	return httpx.ProblemFromError(err)
}

// hasField reports whether p names a field ending with suffix whose
// reason contains reason.
func hasField(p *httpx.Problem, suffix, reason string) bool {
	for _, e := range p.Errors {
		if strings.HasSuffix(e.Field, suffix) && strings.Contains(e.Reason, reason) {
			return true
		}
	}
	return false
}

func mustProblem(t *testing.T, err error, status int, suffix, reason string) {
	t.Helper()
	p := problemOf(t, err)
	if p.Status != status || (suffix != "" && !hasField(p, suffix, reason)) {
		t.Fatalf("got %d %s %+v, want %d with a field ending %q containing %q", p.Status, p.Slug(), p.Errors, status, suffix, reason)
	}
}

// sameJSON compares two JSON documents by value.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("%v: %s", err, a)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

func draftIn(f string) DraftInput {
	return DraftInput{Feature: []byte(f), ValidFrom: ptr(t0), ValidTo: ptr(t1)}
}
