package zonesvc

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// itest is the zone service on the real databases: PostgreSQL as
// authority_app, the projection written as authority_ts_projector and
// read as authority_ts_reader, scratch databases migrated from scratch.
type itest struct {
	svc     *Service
	pgAdmin *sql.DB
	tsAdmin *sql.DB
	reader  *ProjectionReader
}

func newIntegration(t *testing.T) *itest {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	proj, err := ts.OpenProjector(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proj.Close)
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test-reader"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	parts, err := Assemble(Setup{DB: db, Audit: audit.NewWriter(db), Projector: proj, Meta: Meta{ProviderName: "Test authority", ProviderLang: "en-GB"}})
	if err != nil {
		t.Fatal(err)
	}
	return &itest{
		svc: parts.Service, pgAdmin: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL),
		reader: &ProjectionReader{Source: TSSource{R: rd}, Counters: &core.Counters{}},
	}
}

func (it *itest) count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// periodNow is a period of validity around the databases' now.
func periodNow() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now.Add(-24 * time.Hour), now.Add(365 * 24 * time.Hour)
}

// ringAround is a closed ED-269 ring of n vertices on a circle of radius
// deg degrees (a large synthetic zone, Luxembourg's largest is 1400).
func ringAround(lat, lon, deg float64, n int) string {
	pts := make([]string, 0, n+1)
	for i := range n {
		a := 2 * math.Pi * float64(i) / float64(n)
		pts = append(pts, fmt.Sprintf("[%.7f,%.7f]", lon+deg*math.Cos(a), lat+deg*math.Sin(a)))
	}
	pts = append(pts, pts[0])
	return "[[" + strings.Join(pts, ",") + "]]"
}

// luxembourgSized is a synthetic ED-269 file of about the size of
// Luxembourg's live one: n small zones on a grid and one zone of 1400
// vertices, plus a circle.
func luxembourgSized(n int) string {
	zones := make([]string, 0, n+2)
	for i := range n {
		lat, lon := 41.0+float64(i/20)*0.05, 43.0+float64(i%20)*0.05
		zones = append(zones, ed269Zone(fmt.Sprintf("L%05d", i), "REQ_AUTHORISATION", ed269Volume(lat, lon, 0.01)))
	}
	big := fmt.Sprintf(`{"uomDimensions":"M","lowerVerticalReference":"AGL","upperVerticalReference":"AMSL","upperLimit":900,
		"horizontalProjection":{"type":"Polygon","coordinates":%s}}`, ringAround(42.3, 44.5, 0.2, 1400))
	zones = append(zones, ed269Zone("BIG0001", "PROHIBITED", big))
	circle := `{"uomDimensions":"M","lowerVerticalReference":"AGL","upperVerticalReference":"AMSL","upperLimit":600,
		"horizontalProjection":{"type":"Circle","center":[44.8271,41.7151],"radius":1500}}`
	zones = append(zones, ed269Zone("CIR0001", "PROHIBITED", circle))
	return ed269Doc(zones...)
}

func (it *itest) approveAll(t *testing.T, ds Dataset, vs []Version) {
	t.Helper()
	for i := range vs {
		if _, err := it.svc.Approve(context.Background(), ds, vs[i].Identifier, vs[i].ZoneVersion, admin); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationLuxembourgSizedImportPublishProjectAndRead(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	from, to := periodNow()
	doc := luxembourgSized(200)
	format, vs, err := it.svc.Import(ctx, ImportInput{Body: []byte(doc), ValidFrom: &from, ValidTo: &to, Source: "file"}, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatED269 || len(vs) != 202 {
		t.Fatalf("%s %d", format, len(vs))
	}
	// A circle is its centre and radius; the polygon drawn for it is for
	// display only (Z-11).
	var geomNull, centreSet, displaySet bool
	var radiusM float64
	if err := it.pgAdmin.QueryRow(`SELECT geom IS NULL, center IS NOT NULL, display_geom IS NOT NULL, radius_m
		FROM geo_zones WHERE identifier = 'CIR0001'`).Scan(&geomNull, &centreSet, &displaySet, &radiusM); err != nil {
		t.Fatal(err)
	}
	if !geomNull || !centreSet || !displaySet || radiusM != 1500 {
		t.Fatalf("circle columns geom null %v centre %v display %v radius %v", geomNull, centreSet, displaySet, radiusM)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM geo_zones WHERE identifier = 'BIG0001' AND ST_NPoints(geom) = 1401`); n != 1 {
		t.Fatalf("the 1400-vertex zone's geometry: %d", n)
	}
	it.approveAll(t, DatasetZones, vs)
	p, err := it.svc.Publish(ctx, DatasetZones, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Versions) != 202 || p.Publication.FeatureCount != 202 {
		t.Fatalf("%d published, %d in the payload", len(p.Versions), p.Publication.FeatureCount)
	}
	// The outbox row: pending, and no signature until WP-6 signs it.
	var state string
	var unsigned bool
	var payloadBytes int
	if err := it.pgAdmin.QueryRow(`SELECT state, signature IS NULL, octet_length(payload) FROM publications WHERE id = $1`,
		p.Publication.ID).Scan(&state, &unsigned, &payloadBytes); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || !unsigned || payloadBytes == 0 {
		t.Fatalf("outbox row %s unsigned %v %d bytes", state, unsigned, payloadBytes)
	}
	if n := it.count(t, it.tsAdmin, `SELECT count(*) FROM proj_zones WHERE zones_version = $1`, p.ZonesVersion); n != 202 {
		t.Fatalf("%d projected rows", n)
	}
	// The projection read back is a zones.Index with the right
	// candidates: the big zone at its centre, nothing far away.
	if err := it.reader.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	cands := it.reader.Index().Candidates(core.LatLon{LatDeg: 42.3, LonDeg: 44.5})
	if len(cands) != 1 || cands[0].Identifier != "BIG0001" || cands[0].Type != core.ZoneProhibited {
		t.Fatalf("%+v", cands)
	}
	if c := it.reader.Index().Candidates(core.LatLon{LatDeg: 40.0, LonDeg: 40.0}); len(c) != 0 {
		t.Fatalf("far away: %+v", c)
	}
	if it.reader.Version() != p.ZonesVersion || len(it.reader.NotJudged()) != 0 {
		t.Fatalf("version %d not judged %v", it.reader.Version(), it.reader.NotJudged())
	}

	// A deleted projection row is restored by the re-projection, and a
	// row the relational state does not hold is deleted.
	if _, err := it.tsAdmin.Exec(`DELETE FROM proj_zones WHERE identifier = 'BIG0001'`); err != nil {
		t.Fatal(err)
	}
	if _, err := it.tsAdmin.Exec(`INSERT INTO proj_zones SELECT 'zones', 'GHOST', 1, feature, valid_from, valid_to, type,
		bbox_min_lat_deg, bbox_min_lon_deg, bbox_max_lat_deg, bbox_max_lon_deg, projected_at, zones_version
		FROM proj_zones WHERE identifier = 'L00000'`); err != nil {
		t.Fatal(err)
	}
	r, err := it.svc.Reproject(ctx)
	if err != nil || !r.Ran || r.Rows != 202 {
		t.Fatalf("%v %+v", err, r)
	}
	if n := it.count(t, it.tsAdmin, `SELECT count(*) FROM proj_zones WHERE identifier IN ('BIG0001', 'GHOST')`); n != 1 {
		t.Fatalf("after the repair %d of BIG0001 and GHOST", n)
	}
	if it.svc.Counters.Get(CounterProjectionDeleted) != 1 {
		t.Fatal(it.svc.Counters.Snapshot())
	}
	// Every change is an events row.
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type IN ('zones_imported', 'zone_approved', 'zones_published')`); n != 1+202+1 {
		t.Fatalf("%d events", n)
	}
}

func publishAt(t *testing.T, it *itest, f string, from, to time.Time, replace bool) Version {
	t.Helper()
	ctx := context.Background()
	in := DraftInput{Feature: []byte(f), ValidFrom: &from, ValidTo: &to}
	if replace {
		fc, _ := ed318.Parse(wrapFeature([]byte(f)), ed318.Limits{})
		in.Identifier = fc.Features[0].Properties.Identifier
	}
	v, err := it.svc.Draft(ctx, DatasetZones, in, !replace, inspector)
	if err != nil {
		t.Fatal(err)
	}
	it.approveAll(t, DatasetZones, []Version{v})
	if _, err := it.svc.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
	return v
}

func exportTypes(t *testing.T, out []byte) map[string]string {
	t.Helper()
	fc, probs := ed318.Parse(out, ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	got := map[string]string{}
	for i := range fc.Features {
		p := &fc.Features[i].Properties
		got[p.Identifier] = string(p.Type) + "/" + strings.Trim(string(p.ExtendedProperties[ApplicabilityKey]), `"`)
	}
	return got
}

// export?at= gives the version in force at two instants around a change;
// export?applies_at= annotates every feature with each of the three
// values (E-01: one of each).
func TestIntegrationExportAroundAChangeAndAnnotated(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	from, to := periodNow()
	change := from.Add(48 * time.Hour)
	publishAt(t, it, feature(zoneOpts{}), from, to, false)
	publishAt(t, it, feature(zoneOpts{typ: "CONDITIONAL"}), change, to, true)
	before, err := it.svc.Export(ctx, ExportInput{At: ptr(change.Add(-time.Minute))}, admin)
	if err != nil {
		t.Fatal(err)
	}
	after, err := it.svc.Export(ctx, ExportInput{At: ptr(change.Add(time.Minute))}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if b, a := exportTypes(t, before), exportTypes(t, after); b["TST001"] != "PROHIBITED/" || a["TST001"] != "CONDITIONAL/" {
		t.Fatalf("before %v after %v", b, a)
	}

	now := time.Now().UTC()
	notNow := fmt.Sprintf(`[{"schedule":[{"day":["ANY"],"startTime":%q,"endTime":%q}]}]`,
		now.Add(2*time.Hour).Format("15:04:05Z"), now.Add(3*time.Hour).Format("15:04:05Z"))
	daylight := fmt.Sprintf(`[{"startDateTime":%q,"endDateTime":%q,"schedule":[{"day":["ANY"],"startEvent":"SR","endEvent":"SS"}]}]`,
		now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(48*time.Hour).Format(time.RFC3339))
	publishAt(t, it, feature(zoneOpts{identifier: "NOT001", limited: notNow}), from, to, false)
	publishAt(t, it, feature(zoneOpts{identifier: "UNK001", limited: daylight}), from, to, false)
	// Assemble wires ground.Daylight, which resolves SR and SS at the
	// test zone on any date; a source that cannot resolve them gives the
	// unknown value (daylight_test.go covers the resolved half).
	it.svc.Daylight = ed318.FixedDaylight{}
	out, err := it.svc.Export(ctx, ExportInput{AppliesAt: &now}, admin)
	if err != nil {
		t.Fatal(err)
	}
	got := exportTypes(t, out)
	if got["TST001"] != "PROHIBITED/applies" || got["NOT001"] != "PROHIBITED/not_applicable" || got["UNK001"] != "PROHIBITED/unknown" {
		t.Fatalf("%v", got)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = 'zones_exported'`); n != 3 {
		t.Fatalf("%d export events", n)
	}
}

// G-08 on the real databases: a projection that cannot be written rolls
// the publication back, and nothing is queued.
func TestIntegrationPublishRolledBackWithoutTheProjection(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	from, to := periodNow()
	v, err := it.svc.Draft(ctx, DatasetZones, DraftInput{Feature: []byte(feature(zoneOpts{})), ValidFrom: &from, ValidTo: &to}, true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	it.approveAll(t, DatasetZones, []Version{v})
	good := it.svc.Projection
	it.svc.Projection = failingProjection{}
	_, err = it.svc.Publish(ctx, DatasetZones, admin)
	if p := problemOf(t, err); p.Slug() != SlugProjection {
		t.Fatalf("%+v", p)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM publications`); n != 0 {
		t.Fatalf("%d outbox rows after a rollback", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM geo_zones WHERE state = 'approved'`); n != 1 {
		t.Fatal("the version did not stay approved")
	}
	it.svc.Projection = good
	if _, err := it.svc.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
}

type failingProjection struct{}

func (failingProjection) Replace(context.Context, []ProjectedZone, time.Time, int64) (int64, error) {
	return 0, errInjected
}

func TestIntegrationUSpaceDesignationStoredAndPublished(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	from, to := periodNow()
	in := DraftInput{Feature: []byte(uspaceFeature("TSU001")), ValidFrom: &from, ValidTo: &to, Designation: testDesignation()}
	v, err := it.svc.Draft(ctx, DatasetUSpace, in, true, admin)
	if err != nil {
		t.Fatal(err)
	}
	got, err := it.svc.Get(ctx, DatasetUSpace, "TSU001")
	if err != nil || got.Designation == nil || got.Designation.Name != "Tbilisi U-space (test)" ||
		!sameJSON(t, got.Designation.ServicePerformance, testDesignation().ServicePerformance) {
		t.Fatalf("%v %+v", err, got.Designation)
	}
	if _, err := it.svc.Approve(ctx, DatasetUSpace, "TSU001", v.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	p, err := it.svc.Publish(ctx, DatasetUSpace, admin)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := it.pgAdmin.QueryRow(`SELECT payload FROM publications WHERE id = $1 AND dataset = 'uspace_airspace'`, p.Publication.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	fc, probs := ed318.Parse(payload, ed318.Limits{})
	if probs != nil || len(fc.Features) != 1 {
		t.Fatalf("%v", probs)
	}
	if errs := validateAgainst(t, cispSchema(t), "#", fc.Features[0].Properties.ExtendedProperties[RequirementsKey]); len(errs) > 0 {
		t.Fatal(errs)
	}
	if n := it.count(t, it.tsAdmin, `SELECT count(*) FROM proj_zones WHERE dataset = 'uspace_airspace' AND type = 'USPACE'`); n != 1 {
		t.Fatalf("%d projected", n)
	}
}

// The announcement on the bus: KV zones_version holds the version and a
// reader following zones.v1.changed re-reads at once (and without the
// push its periodic re-read still would).
func TestIntegrationAnnouncedOnTheBusAndFollowed(t *testing.T) {
	nc, js := bustest.Connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg, _ := bus.NewTopology(bus.Limits{}).Bucket(bus.BucketZonesVersion)
	cfg.Bucket = bustest.Name("zones_version")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), cfg.Bucket) })
	pub := &BusPublisher{NC: nc, JS: js, Bucket: cfg, Timeout: 5 * time.Second}

	src := &fakeSource{rows: []ProjectedRow{}}
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}}
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	followed := make(chan struct{})
	go func() { Follow(ctx, nc, r, logging.Discard()); close(followed) }()
	defer func() { cancel(); <-done; <-followed }()
	waitFor(t, func() bool { return r.Index() != nil })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the subscription is registered

	src.set([]ProjectedRow{projected("TST001", 1, feature(zoneOpts{}), t0.Add(-time.Hour*24*365), t1.Add(time.Hour*24*365))}, nil)
	if err := pub.PublishZonesVersion(ctx, 7); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(candidateTypes(r)) == 1 })
	kv, err := js.KeyValue(ctx, cfg.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	e, err := kv.Get(ctx, VersionKey)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		ZonesVersion int64 `json:"zones_version"`
	}
	if err := json.Unmarshal(e.Value(), &m); err != nil || m.ZonesVersion != 7 {
		t.Fatalf("%v %s", err, e.Value())
	}
	// A bucket that cannot take the value fails the announcement (the
	// publication stands and the failure is counted by the service).
	bad := *pub
	bad.Bucket = jetstream.KeyValueConfig{Bucket: bustest.Name("zv_small"), MaxValueSize: 4}
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bad.Bucket.Bucket) })
	if err := bad.PublishZonesVersion(ctx, 8); err == nil {
		t.Fatal("a value past the bucket's bound was accepted")
	}
}
