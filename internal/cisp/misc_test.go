package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakecisp"
)

// The CIS delivery operation is the same in the contract (x-cis-delivery),
// in apiserver.Delivery and in the generator's exclusions, served on the
// contract's method and path, and public at the bearer level.
func TestDeliveryOperationMatchesTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pathRe := regexp.MustCompile(`^  (/\S+):$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):$`)
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	ops := map[string]string{}
	var path, method, op string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			path = m[1]
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			method = strings.ToUpper(m[1])
		}
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
		}
		if strings.TrimSpace(line) == "x-cis-delivery: true" {
			ops[op] = method + " " + path
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(ops)), slices.Sorted(maps.Keys(apiserver.Delivery))) {
		t.Fatalf("contract %v, apiserver.Delivery %v", ops, apiserver.Delivery)
	}
	if ops["ReceiveCISNotification"] != PatternNotifications {
		t.Fatalf("served on %q, the contract says %q", PatternNotifications, ops["ReceiveCISNotification"])
	}
	cfg, err := os.ReadFile("../../api/oapi-codegen.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "receiveCISNotification") {
		t.Fatal("the delivery operation is not excluded from the generated server")
	}
	for op := range ops {
		if !apiserver.Public[op] {
			t.Fatalf("%s carries no bearer and must be public", op)
		}
		if _, ok := apiserver.Roles[op]; ok {
			t.Fatalf("%s has a role", op)
		}
	}
}

// The pinned schemas compile and the CISP's own examples validate; the
// subset this system uses is all there.
func TestPinnedSchemasCompileAndTheExamplesValidate(t *testing.T) {
	s := schemas(t)
	for name, path := range map[string]string{
		SchemaUSSPList:           "../../api/clients/cisp-schemas/cis/ussp_list/examples/lab.json",
		SchemaUSpaceRequirements: "../../api/clients/cisp-schemas/cis/uspace_requirements/examples/tbilisi.json",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if probs := s.Validate(name, b, ""); len(probs) > 0 {
			t.Fatalf("%s: %v", name, probs)
		}
		if probs := s.Validate(name, []byte(`{"unexpected":true}`), "x"); len(probs) == 0 || !strings.HasPrefix(probs[0].Field, "x") {
			t.Fatalf("%s accepted an object without its members: %v", name, probs)
		}
	}
	if probs := s.Validate("cis/none/v1", []byte(`{}`), ""); len(probs) != 1 {
		t.Fatal("an unknown schema validated")
	}
	if probs := s.Validate(SchemaUSSPList, []byte(`not json`), ""); len(probs) != 1 || probs[0].Field != "$" {
		t.Fatalf("%v", probs)
	}
}

// The restriction example of the CISP's cis/restriction/v1 becomes a
// projection row whose state and window are the CISP block's; a state
// this build does not know is projected as unknown, never dropped.
func TestRestrictionRows(t *testing.T) {
	v, rf := ParseVersion(schemas(t), DatasetRestrictions, mustCollection(restrictionFeature("DAR0001", "planned"),
		json.RawMessage(strings.Replace(string(restrictionFeature("DAR0002", "active")), `"state":"active"`, `"state":"paused"`, 1))), "", 5)
	if rf != nil {
		t.Fatal(rf)
	}
	rows := RestrictionRows(v)
	if len(rows) != 2 || rows[0].State != "planned" || rows[1].State != "unknown" || rows[1].Identifier != "DAR0002" {
		t.Fatalf("%+v", rows)
	}
}

func mustCollection(fs ...json.RawMessage) []byte {
	b, _ := json.Marshal(map[string]any{"type": "FeatureCollection", "features": fs, "cis_dataset": "restrictions", "cis_version": 5})
	return b
}

// ParseVersion names the version and refuses a body that names another
// dataset or another version than its header.
func TestParseVersionRefusals(t *testing.T) {
	s := schemas(t)
	body := zoneCollection(zoneFeature("TST001", "SENSITIVE"))
	if _, rf := ParseVersion(s, DatasetZones, body, "", 0); rf == nil || !strings.Contains(rf.First, "cis_version") {
		t.Fatalf("%v", rf)
	}
	v, rf := ParseVersion(s, DatasetZones, body, "", 3)
	if rf != nil || v.Number != 3 || v.ETag != `"zones:3"` {
		t.Fatalf("%v %+v", rf, v)
	}
	other := []byte(strings.Replace(string(body), `"metadata"`, `"cis_dataset":"uspace_airspace","cis_version":3,"metadata"`, 1))
	if _, rf := ParseVersion(s, DatasetZones, other, "", 3); rf == nil || !strings.Contains(rf.First, "cis_dataset") {
		t.Fatalf("%v", rf)
	}
	mismatch := []byte(strings.Replace(string(body), `"metadata"`, `"cis_version":4,"metadata"`, 1))
	if _, rf := ParseVersion(s, DatasetZones, mismatch, "", 3); rf == nil || !strings.Contains(rf.Error(), "X-CIS-Version") {
		t.Fatalf("%v", rf)
	}
	if _, rf := ParseVersion(s, DatasetZones, []byte(`[]`), "", 3); rf == nil {
		t.Fatal("an array was accepted")
	}
}

// A delta that does not apply to the version held is never guessed.
func TestMergeDeltaRefusesWhatDoesNotApply(t *testing.T) {
	cur := &Version{Dataset: DatasetZones, Number: 2, Features: []Feature{{Identifier: "A", Raw: json.RawMessage(`{"properties":{"identifier":"A"}}`)}}}
	delta := func(from, to int64, added, changed, removed string) []byte {
		return []byte(`{"dataset":"zones","from_version":` + itoa(from) + `,"to_version":` + itoa(to) +
			`,"added":{"type":"FeatureCollection","features":[` + added + `]},"changed":{"type":"FeatureCollection","features":[` + changed +
			`]},"removed":[` + removed + `]}`)
	}
	b := `{"properties":{"identifier":"B"}}`
	a := `{"properties":{"identifier":"A"}}`
	bad := map[string][]byte{
		"from":            delta(1, 3, "", "", ""),
		"to":              delta(2, 2, "", "", ""),
		"removed unknown": delta(2, 3, "", "", `"Z"`),
		"changed unknown": delta(2, 3, "", b, ""),
		"added held":      delta(2, 3, a, "", ""),
		"no identifier":   delta(2, 3, `{"properties":{}}`, "", ""),
		"not JSON":        []byte(`nope`),
		"other dataset":   []byte(`{"dataset":"restrictions","from_version":2,"to_version":3,"added":{"features":[]},"changed":{"features":[]},"removed":[]}`),
	}
	for name, d := range bad {
		if _, _, err := mergeDelta(cur, d); !errors.Is(err, errDeltaUnusable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	body, to, err := mergeDelta(cur, delta(2, 3, b, "", `"A"`))
	if err != nil || to != 3 || !strings.Contains(string(body), `"B"`) || strings.Contains(string(body), `"identifier":"A"`) {
		t.Fatalf("%v %d %s", err, to, body)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func lazyConfig(f *fakecisp.Fake) auth.CompactConfig {
	c := auth.CompactConfig{Audiences: []string{"127.0.0.1"}}
	if f != nil {
		c.Issuers = map[string]auth.IssuerConfig{fakecisp.Issuer: {Keys: f.Ring.JWKS()}}
	}
	return c
}

// The base URL is https, or http to a loopback host only.
func TestCheckBaseURL(t *testing.T) {
	for _, ok := range []string{"https://cisp.test", "https://cisp.test:8443/", "http://127.0.0.1:9", "http://localhost:9"} {
		if _, err := CheckBaseURL(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://cisp.test", "ftp://cisp.test", "https://u@cisp.test", "https://cisp.test/?a=1", "/v1", ""} {
		if _, err := CheckBaseURL(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

// The ETag of a version reads back as the version, for its dataset only.
func TestETags(t *testing.T) {
	if v, ok := ParseETag(DatasetZones, ETagOf(DatasetZones, 12)); !ok || v != 12 {
		t.Fatal(v)
	}
	for _, bad := range []string{`"uspace_airspace:1"`, `"zones:x"`, `zones`, ""} {
		if _, ok := ParseETag(DatasetZones, bad); ok {
			t.Fatalf("%s read", bad)
		}
	}
}

// GET /v1/publications: rows newest first, "not yet published" age only
// while pending or sent; the cache, the heartbeat and the subscription
// beside them.
func TestHandlerListsTheOutboxAndTheCache(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	w.enqueueZones(t, zoneFeature("TST002", "SENSITIVE"))
	hb := &Heartbeat{CISP: w.client}
	h := Handler{Store: w.store, Subscriber: w.sub, Heartbeat: hb, Configured: true}
	resp, err := h.ListPublications(ctx, gen.ListPublicationsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	out := resp.(gen.ListPublications200JSONResponse)
	if !out.CispConfigured || len(out.Publications) != 2 || len(out.Cache) != 4 {
		t.Fatalf("%+v", out)
	}
	pending, acked := out.Publications[0], out.Publications[1]
	if pending.State != "pending" || pending.AgeS == nil || acked.State != "acknowledged" || acked.AgeS != nil || acked.CispVersion == nil {
		t.Fatalf("%+v %+v", pending, acked)
	}
	if out.Cache[0].Dataset != "zones" || !out.Cache[0].Stale || out.Heartbeat.IntervalS != 15 {
		t.Fatalf("%+v %+v", out.Cache[0], out.Heartbeat)
	}
	st := gen.ListPublicationsParamsState("acknowledged")
	resp, _ = h.ListPublications(ctx, gen.ListPublicationsRequestObject{Params: gen.ListPublicationsParams{State: &st}})
	if out := resp.(gen.ListPublications200JSONResponse); len(out.Publications) != 1 {
		t.Fatalf("%+v", out.Publications)
	}
}

// The lazy notification verifier refuses until it is built, says why on
// the status line, and with no issuer configured refuses everything.
func TestLazyCompactVerifier(t *testing.T) {
	l := NewLazyCompactVerifier(lazyConfig(nil))
	if err := l.Build(context.Background()); !errors.Is(err, errNoNotifyIssuers) || !strings.Contains(l.LastError(), "AUTHORITY_CIS_NOTIFY_ISSUERS") {
		t.Fatalf("%v", err)
	}
	if _, _, err := l.Verify(context.Background(), "x"); err == nil {
		t.Fatal("verified with no issuer")
	}
	w := newWorld(t)
	l = NewLazyCompactVerifier(lazyConfig(w.fake))
	if _, _, err := l.Verify(context.Background(), "x"); err == nil || l.Counters() == nil {
		t.Fatal("verified before it was built")
	}
	if err := l.Build(context.Background()); err != nil || l.LastError() != "" {
		t.Fatalf("%v", err)
	}
	tok := signAs(t, w.fake.Ring, "https://cisp.test", "127.0.0.1", change("zones", "publication", 1, ""))
	if _, body, err := l.Verify(context.Background(), tok); err != nil || len(body) == 0 {
		t.Fatalf("%v", err)
	}
}

// E-02: the status line names what is missing (no CISP, the keys not
// fetched) and every dataset's stale state.
func TestStatusAttrsWithoutACISP(t *testing.T) {
	p := &Parts{
		Subscriber: NewSubscriber(SubscriberConfig{Schemas: schemas(t), Now: time.Now}),
		Publishers: NewPublishers(nil, 0, nil),
		Notify:     NewLazyCompactVerifier(lazyConfig(nil)),
	}
	_ = p.Notify.Build(context.Background())
	got := map[string]string{}
	for _, a := range p.StatusAttrs() {
		got[a.Key] = a.Value.String()
	}
	if got["cisp_configured"] != "false" || got["cis_stale"] != "zones,uspace_airspace,ussp_list,restrictions" ||
		!strings.Contains(got["cis_notify_keys"], "AUTHORITY_CIS_NOTIFY_ISSUERS") {
		t.Fatalf("%v", got)
	}
}

// The cis.v1.<dataset> body (CacheMessage) names exactly the members of
// schemas/cache/cis/v1.json, which this repository owns.
func TestCacheMessageMatchesItsSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/cache/cis/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		ID         string `json:"$id"`
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
			Body struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"body"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.Properties.Schema.Const != CacheSchema || s.ID != "https://schemas.uspace.ge/"+CacheSchema+".json" {
		t.Fatalf("%s %s", s.Properties.Schema.Const, s.ID)
	}
	updated := time.Now()
	b, err := json.Marshal(CacheMessage{Dataset: "zones", CISVersion: 1, ETag: `"zones:1"`, CISUpdatedAt: &updated, FeatureCount: 1, FetchedAt: updated})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if got, want := slices.Sorted(maps.Keys(m)), slices.Sorted(maps.Keys(s.Properties.Body.Properties)); !slices.Equal(got, want) {
		t.Fatalf("message %v, schema %v", got, want)
	}
	for _, r := range s.Properties.Body.Required {
		if _, ok := m[r]; !ok {
			t.Fatalf("required %s missing", r)
		}
	}
}
