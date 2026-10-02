package cisp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	var pe *httpx.ProblemError
	if !errors.As(err, &pe) {
		t.Fatalf("not a problem: %v", err)
	}
	return pe.Problem
}

// The detached JWS round trip through core's helpers with a run-time
// key: the header declares b64 false in crit, the signing input is the
// payload bytes unencoded (RFC 7797), and the signature verifies over
// those bytes and over no others.
func TestPrepareSignsTheExactBytesAsADetachedJWS(t *testing.T) {
	authority, _ := rings(t)
	o := NewOutbox(schemas(t), authority, &memOutbox{}, nil)
	payload := zoneCollection(zoneFeature("TST001", "SENSITIVE"))
	p, err := o.Prepare(DatasetZones, payload)
	if err != nil {
		t.Fatal(err)
	}
	head, _, ok := strings.Cut(p.Signature, "..")
	if !ok {
		t.Fatalf("not a detached JWS: %s", p.Signature)
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h["alg"] != "RS256" || h["b64"] != false || h["kid"] != authority.ActiveKID() || h["iat"] == nil {
		t.Fatalf("header %v", h)
	}
	if crit, _ := h["crit"].([]any); len(crit) != 1 || crit[0] != "b64" {
		t.Fatalf("crit %v", h["crit"])
	}
	if p.KID != authority.ActiveKID() || p.FeatureCount != 1 || p.ContentType != "application/geo+json" || len(p.PayloadHash) != 64 {
		t.Fatalf("%+v", p)
	}
	v, err := auth.NewDetachedVerifier(context.Background(), auth.DetachedConfig{
		Publishers: map[string]auth.IssuerConfig{"authority": {Keys: authority.JWKS()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), "authority", p.Signature, payload); err != nil {
		t.Fatalf("does not verify over its payload: %v", err)
	}
	tampered := []byte(strings.Replace(string(payload), "TST001", "TST002", 1))
	if _, err := v.Verify(context.Background(), "authority", p.Signature, tampered); err == nil {
		t.Fatal("verified over other bytes")
	}
}

// countingSigner counts signatures: a refused payload is never signed.
type countingSigner struct {
	Signer
	n int
}

func (c *countingSigner) SignDetached(payload []byte, now time.Time) (string, error) {
	c.n++
	return c.Signer.SignDetached(payload, now)
}

func usspExample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../api/clients/cisp-schemas/cis/ussp_list/examples/lab.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The USSP list (WP-16's dataset) against the pinned cis/ussp_list/v1:
// the CISP's own example passes and is signed; one with an unknown
// member, a malformed URL, a repeated ussp_id or a served-only member is
// refused before anything is signed (E-01 pair).
func TestPrepareHoldsTheUSSPListToThePinnedSchema(t *testing.T) {
	authority, _ := rings(t)
	sig := &countingSigner{Signer: authority}
	o := NewOutbox(schemas(t), sig, &memOutbox{}, nil)
	good := usspExample(t)
	p, err := o.Prepare(DatasetUSSPList, good)
	if err != nil || sig.n != 1 || p.ContentType != "application/json" || p.FeatureCount < 1 {
		t.Fatalf("%v %d %+v", err, sig.n, p)
	}
	var list map[string]any
	if err := json.Unmarshal(good, &list); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		edit          func(m map[string]any)
		field, reason string
	}{
		"unknown member": {func(m map[string]any) { m["extra"] = true }, "$", "additional"},
		"bad url":        {func(m map[string]any) { first(m)["base_url"] = "not a url" }, "ussps[0].base_url", ""},
		"repeated id":    {func(m map[string]any) { m["ussps"] = append(m["ussps"].([]any), m["ussps"].([]any)[0]) }, "ussps[", "is also ussps[0]"},
		"served member":  {func(m map[string]any) { m["cis_version"] = 3 }, "cis_version", "written by the CISP"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(good, &m)
			c.edit(m)
			b, _ := json.Marshal(m)
			before := sig.n
			_, err := o.Prepare(DatasetUSSPList, b)
			pr := problemOf(t, err)
			if pr.Status != http.StatusBadRequest || pr.Slug() != SlugPublicationRefused {
				t.Fatalf("%+v", pr)
			}
			found := false
			for _, e := range pr.Errors {
				if strings.HasPrefix(e.Field, c.field) && strings.Contains(e.Reason, c.reason) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%+v, want %s: %s", pr.Errors, c.field, c.reason)
			}
			if sig.n != before {
				t.Fatal("a refused payload was signed")
			}
		})
	}
	if o.Counters.Get(CounterPublicationsRefused) != uint64(len(cases)) {
		t.Fatalf("refused %d", o.Counters.Get(CounterPublicationsRefused))
	}
}

func first(m map[string]any) map[string]any { return m["ussps"].([]any)[0].(map[string]any) }

// The CISP's dataset rules on an ED-318 publication: each refusal beside
// the accepted collection above.
func TestPrepareHoldsZonesToTheCISPDatasetRules(t *testing.T) {
	authority, _ := rings(t)
	o := NewOutbox(schemas(t), authority, &memOutbox{}, nil)
	uspace := strings.Replace(zoneFeature("TSU001", "SENSITIVE"), `"type":"PROHIBITED"`, `"type":"USPACE"`, 1)
	block, err := os.ReadFile("../../api/clients/cisp-schemas/cis/uspace_requirements/examples/tbilisi.json")
	if err != nil {
		t.Fatal(err)
	}
	withBlock := strings.Replace(uspace, `"zoneAuthority"`, `"extendedProperties":{"uspace_requirements":`+string(block)+`},"zoneAuthority"`, 1)
	badBlock := strings.Replace(uspace, `"zoneAuthority"`, `"extendedProperties":{"uspace_requirements":{"adjacent":[]}},"zoneAuthority"`, 1)
	cases := map[string]struct {
		ds            Dataset
		body          []byte
		field, reason string
	}{
		"not ED-318":              {DatasetZones, []byte(`{"type":"FeatureCollection","features":[{}]}`), "features[0]", ""},
		"USPACE in zones":         {DatasetZones, zoneCollection(withBlock), "features[0].properties.type", "uspace_airspace dataset"},
		"zone in uspace_airspace": {DatasetUSpace, zoneCollection(zoneFeature("TST001", "SENSITIVE")), "features[0].properties.type", "only USPACE"},
		"DAR reason":              {DatasetZones, zoneCollection(zoneFeature("TST001", "DAR")), "features[0].properties.reason", "ANSP"},
		"repeated identifier":     {DatasetZones, zoneCollection(zoneFeature("TST001", "SENSITIVE"), zoneFeature("TST001", "SENSITIVE")), "features[1].properties.identifier", "features[0]"},
		"no requirements block":   {DatasetUSpace, zoneCollection(uspace), "features[0].properties.extendedProperties.uspace_requirements", "required"},
		"bad requirements block":  {DatasetUSpace, zoneCollection(badBlock), "features[0].properties.extendedProperties.uspace_requirements", ""},
		"served member":           {DatasetZones, []byte(strings.Replace(string(zoneCollection(zoneFeature("TST001", "SENSITIVE"))), `"metadata"`, `"cis_dataset":"zones","metadata"`, 1)), "cis_dataset", "CISP"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := o.Prepare(c.ds, c.body)
			pr := problemOf(t, err)
			found := false
			for _, e := range pr.Errors {
				if strings.HasPrefix(e.Field, c.field) && strings.Contains(e.Reason, c.reason) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%+v, want %s: %s", pr.Errors, c.field, c.reason)
			}
		})
	}
	if _, err := o.Prepare(DatasetUSpace, zoneCollection(withBlock)); err != nil {
		t.Fatalf("a U-space publication with the CISP's example block: %v", err)
	}
}

// Without a publication key nothing is queued (503), beside the signed
// row Enqueue writes and wakes the sender for.
func TestEnqueueNeedsTheKeyAndWakesTheSender(t *testing.T) {
	authority, _ := rings(t)
	st := &memOutbox{}
	unsigned := NewOutbox(schemas(t), nil, st, nil)
	_, err := unsigned.Enqueue(context.Background(), DatasetUSSPList, usspExample(t), admin)
	if p := problemOf(t, err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugPublicationKeyMissing {
		t.Fatalf("%+v", p)
	}
	if len(st.rows) != 0 || unsigned.Counters.Get(CounterPublicationsUnsigned) != 1 {
		t.Fatalf("%d rows", len(st.rows))
	}
	o := NewOutbox(schemas(t), authority, st, nil)
	row, err := o.Enqueue(context.Background(), DatasetUSSPList, usspExample(t), admin)
	if err != nil || row.State != StatePending || row.Signature == nil || row.Version != 1 {
		t.Fatalf("%v %+v", err, row)
	}
	select {
	case <-o.Woken():
	default:
		t.Fatal("the sender was not woken")
	}
}

// E-10: one pending snapshot per dataset; a newer one supersedes it and
// the superseded one is recorded as such (another dataset's row stays).
func TestOutboxKeepsOnePendingSnapshotPerDataset(t *testing.T) {
	authority, _ := rings(t)
	st := &memOutbox{}
	o := NewOutbox(schemas(t), authority, st, nil)
	ctx := context.Background()
	a, _ := o.Enqueue(ctx, DatasetUSSPList, usspExample(t), admin)
	z, err := o.Enqueue(ctx, DatasetZones, zoneCollection(zoneFeature("TST001", "SENSITIVE")), admin)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := o.Enqueue(ctx, DatasetUSSPList, usspExample(t), admin)
	if st.state(a.ID).State != StateSuperseded || st.state(b.ID).State != StatePending || st.state(z.ID).State != StatePending {
		t.Fatalf("%s %s %s", st.state(a.ID).State, st.state(b.ID).State, st.state(z.ID).State)
	}
	if b.Version != 2 {
		t.Fatalf("version %d", b.Version)
	}
	due, _ := st.Due(ctx)
	if len(due) != 2 {
		t.Fatalf("%d due", len(due))
	}
}
