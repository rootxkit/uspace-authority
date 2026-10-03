package incidents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/violation"
	"github.com/rootxkit/uspace-authority/internal/violations"
)

type pgGen = gen.Queries

func listByViolation(id string) gen.ListIncidentsParams {
	return gen.ListIncidentsParams{ViolationID: &id, Lim: 10}
}

// asApp runs q as the application role on a connection of its own.
func (f *fixture) asApp(q string) error {
	f.t.Helper()
	ctx := context.Background()
	conn, err := f.pg.Conn(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "SET ROLE authority_app"); err != nil {
		f.t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, q)
	if _, rerr := conn.ExecContext(ctx, "RESET ROLE"); rerr != nil {
		f.t.Fatal(rerr)
	}
	return err
}

var inspector = audit.Actor{Type: audit.ActorUser, ID: "inspector-1", Realm: audit.RealmConsole}

// fixture is api's side of incidents on scratch databases of both trees:
// the violations service with the escalation hook, the incidents service
// and the packs, stored under a temporary EVIDENCE_DIR, signed by a key
// generated at test time.
type fixture struct {
	t       *testing.T
	db      *pgstore.DB
	pg      *sql.DB
	tsAdmin *sql.DB
	vio     *violations.Service
	inc     *Service
	packs   *Packs
	dir     string
	base    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db, err := pgstore.Open(ctx, store.PoolOptions{URL: pgURL, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test-evidence"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	w := audit.NewWriter(db)
	counters := &core.Counters{}
	inc := &Service{DB: db, Audit: w, PublicPart: PublicPartOf(nil), WriteTimeout: 10 * time.Second, Counters: counters}
	vio := &violations.Service{DB: db, Audit: w, MaxExcerptSamples: 600, WriteTimeout: 10 * time.Second, Counters: &core.Counters{},
		OnEscalate: inc.OpenFromViolation}
	r := ring(t, "pub-int-1", 2)
	v, err := coreauth.NewDetachedVerifier(ctx, coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{PublisherAuthority: {Keys: r.JWKS()}}, MaxAge: signatureMaxAge})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	packs := NewPacks(&Packs{Service: inc, Storage: Dir{Root: dir}, Sealer: sealer(t), Signer: r, Verifier: v,
		Builder: &Builder{Sources: db.Queries(), Telemetry: rd.Q, Records: &Records{Tokens: fakeTokens{}, MaxBytes: 1 << 20},
			MaxRows: 1000, MaxRecords: 4, MaxZones: 50, PublicPart: PublicPartOf(nil)},
		MaxWindow: 6 * time.Hour, MaxBytes: 64 << 20, BuildTimeout: time.Minute, Counters: counters}, 2)
	return &fixture{t: t, db: db, pg: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL), vio: vio, inc: inc, packs: packs,
		dir: dir, base: time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)}
}

func (f *fixture) exec(db *sql.DB, q string, args ...any) {
	f.t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		f.t.Fatalf("%v\n%s", err, q)
	}
}

func (f *fixture) ts(s float64) time.Time { return f.base.Add(time.Duration(s * float64(time.Second))) }

// events are the event types recorded for an entity, in order.
func (f *fixture) events(entityType, id string) []string {
	f.t.Helper()
	rows, err := f.pg.Query(`SELECT event_type FROM events WHERE entity_type = $1 AND entity_id = $2 ORDER BY id`, entityType, id)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// lastEvent is the newest row of an event type of the incident.
func (f *fixture) lastEvent(incidentID, eventType string) (purpose *string, payload map[string]any) {
	f.t.Helper()
	var raw []byte
	if err := f.pg.QueryRow(`SELECT purpose, payload FROM events WHERE entity_type = 'incident' AND entity_id = $1 AND event_type = $2
		ORDER BY id DESC LIMIT 1`, incidentID, eventType).Scan(&purpose, &raw); err != nil {
		f.t.Fatalf("%s: %v", eventType, err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		f.t.Fatal(err)
	}
	return purpose, payload
}

const (
	itSerial = "TESTINT00001"
	itReg    = "GEOTESTINT000001"
	itTrack  = "track-int-1"
	itTx     = "AA:BB:CC:DD:EE:01"
	itUSSP   = "USSPT"
)

// zone writes SC7 version 1, published, a square around (41.50, 44.60).
func (f *fixture) zone() {
	d := 0.002
	ring := fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`, 44.6-d, 41.5-d, 44.6+d, 41.5-d, 44.6+d, 41.5+d, 44.6-d, 41.5+d, 44.6-d, 41.5-d)
	geom := `{"type":"Polygon","coordinates":` + ring + `}`
	feature := `{"type":"Feature","geometry":` + geom + `,"properties":{"identifier":"SC7","country":"GEO","type":"PROHIBITED"}}`
	f.exec(f.pg, `INSERT INTO geo_zones (dataset, identifier, zone_version, state, country, type, variant, geometry_type, geom, layers,
		zone_authority, feature, valid_from, valid_to, published_version, published_at, published_by, created_by, approved_at, approved_by)
		VALUES ('zones', 'SC7', 1, 'published', 'GEO', 'PROHIBITED', 'COMMON', 'Polygon', ST_SetSRID(ST_GeomFromGeoJSON($1), 4326),
		'[]', '[]', $2, now() - interval '1 day', now() + interval '1 day', 1, now(), 'admin-1', 'inspector-1', now(), 'admin-1')`,
		geom, feature)
}

func (f *fixture) message(id string, kind violation.Kind, state violation.State, s float64) *violation.Message {
	capt := bus.Stamp(f.ts(s))
	b := violation.Body{ViolationID: id, Kind: kind, State: state, Severity: core.SeverityCritical, AlertKey: string(kind) + ":" + id,
		TrackRef: itTrack, Serial: sp(itSerial), OperatorReg: sp(itReg + "-xyz"), CapturedAt: capt, OpenedAt: bus.Stamp(f.ts(1)),
		PolicyVersion: 1, Detail: map[string]any{}, EvidenceTrust: core.TrustBroadcast, Cell5: "c5:1317:2248",
		EvidenceRefs: []violation.EvidenceRef{{Type: violation.RefTrack, ID: itTrack}},
		EvidenceExcerpt: []violation.Sample{{MsgID: bus.NewULID(f.ts(s)), CapturedAt: capt, RxTS: capt, Lat: 41.5, Lng: 44.6,
			AltSource: core.AltGeodetic}}}
	if kind == violation.KindZoneIncursion {
		v := int64(1)
		b.ZoneID, b.ZoneVersion, b.ZoneType = sp("GEO/SC7"), &v, sp("PROHIBITED")
	} else {
		b.Peak = &violation.Peak{Name: "height_agl_m", Value: 178}
		b.TerrainSource = &violation.TerrainSource{Dataset: "COP-DEM GLO-30", SpacingM: 30, Attribution: "test"}
	}
	if state == violation.StateCleared {
		b.ClearReason, b.ClosedAt = sp("resolved"), sp(bus.Stamp(f.ts(s)))
	}
	m := bus.SystemEnvelope(violation.Schema, violation.Producer, f.ts(s), b)
	return &m
}

// violations raise and clear a zone incursion and a height violation of
// the aircraft, as detect reports them (WP-12's SC-07 and SC-04 shape).
func (f *fixture) violations() (zoneID, heightID string) {
	f.t.Helper()
	zoneID, heightID = bus.NewULID(f.ts(1)), bus.NewULID(f.ts(1.5))
	for _, m := range []*violation.Message{
		f.message(zoneID, violation.KindZoneIncursion, violation.StateRaised, 1),
		f.message(heightID, violation.KindHeight120m, violation.StateRaised, 1.5),
		f.message(zoneID, violation.KindZoneIncursion, violation.StateCleared, 12),
		f.message(heightID, violation.KindHeight120m, violation.StateCleared, 12),
	} {
		if _, err := f.vio.Apply(context.Background(), m); err != nil {
			f.t.Fatal(err)
		}
	}
	return zoneID, heightID
}

// telemetry writes the aircraft's tracks (1-4 s, a silence, 10-12 s),
// its raw frames (with a Location without a position at 3.5 s and a
// System frame), a recorded writer gap at 7 s and a Display Provider
// row, as tsdb-writer and dp-poller leave them.
func (f *fixture) telemetry() {
	f.t.Helper()
	for i, s := range []float64{1, 2, 3, 4, 10, 11, 12} {
		f.exec(f.tsAdmin, `INSERT INTO tracks (captured_at, track_id, dedupe_key, msg_id, rx_ts, time_source, backlog, source,
			source_instance, trust, lat_deg, lon_deg, alt_amsl_m, alt_source, emergency, ident_status, ident_reason, ident_mismatch,
			ident_basis, serial, operator_reg, ussp_id, flight_id)
			VALUES ($1, $2, $3, $4, $1, 'broadcast', false, 'direct_rid', 'rx-int', 'broadcast', 41.5, 44.6, 600, 'geodetic', false,
			'registered', 'matched', false, 'as_broadcast', $5, $6, $7, 'FLIGHT-INT-1')`,
			f.ts(s), itTrack, fmt.Sprintf("d%d", i), bus.NewULID(f.ts(s)), itSerial, itReg, itUSSP)
	}
	frame := func(n int, s float64, msgType int, serial *string, lat *float64) {
		payload := []byte{byte(msgType << 4), byte(n)}
		sum := sha256.Sum256(payload)
		f.exec(f.tsAdmin, `INSERT INTO rid_observations (ingest_ts, frame_id, receiver_id, transmitter, msg_type, payload,
			payload_sha256, backlog, sent_at_ms, nonce, serial, lat_deg, lon_deg, captured_at)
			VALUES ($1, $2, 'rx-int', $3, $4, $5, $6, false, 0, $2, $7, $8, $8, $1)`,
			f.ts(s), fmt.Sprintf("%032x", n), itTx, msgType, payload, sum[:], serial, lat)
	}
	lat := 41.5
	frame(1, 1, 0, sp(itSerial), nil)
	frame(2, 1, 1, nil, &lat)
	frame(3, 2, 4, nil, nil)
	frame(4, 3.5, 1, nil, nil)
	f.exec(f.tsAdmin, `INSERT INTO writer_gaps (dedupe_key, table_name, stream, from_seq, to_seq, cause, count, count_unit, at)
		VALUES ('gap-int-1', 'tracks', 'TSW', 10, 12, 'spill_expired', 3, 'rows', $1)`, f.ts(7))
	f.exec(f.tsAdmin, `INSERT INTO ussp_flights (rx_ts, dedupe_key, ussp_id, uss_base_url, flight_id, track_id, state_ts,
		provider_unknown, flight, details)
		VALUES ($1, 'uf-1', $2, 'https://ussp.example.test/rid/v2', 'FLIGHT-INT-1', $3, $1, false, '{"id":"FLIGHT-INT-1"}',
		'{"operator_location":{"lat":41.49,"lng":44.59}}')`, f.ts(2), itUSSP, itTrack)
	// The ANSP's manned traffic (WP-15): one aircraft 2 km away inside
	// the window, one 50 km away (outside the margin), one after it.
	manned := func(key string, s, lat, lon float64) {
		f.exec(f.tsAdmin, `INSERT INTO manned_tracks (source_captured_at, captured_at, dedupe_key, msg_id, rx_ts, time_source,
			backlog, icao24, lat_deg, lon_deg, alt_pressure_m, source_class, trust, source, source_instance, state)
			VALUES ($1, $1, $2, $3, $1, 'provider', false, '4ca7b5', $4, $5, 450, 'ads_b', 'surveillance', 'ansp_feed', 'adsb-tbs', 'live')`,
			f.ts(s), key, bus.NewULID(f.ts(s)), lat, lon)
	}
	manned("m-near", 2, 41.518, 44.6)
	manned("m-far", 2, 41.95, 44.6)
	manned("m-late", 7200, 41.5, 44.6)
}

// usspCertificate records the USSP's certificate (WP-16) with its base
// URL at baseURL: where its service records are fetched from.
func (f *fixture) usspCertificate(baseURL string) {
	f.exec(f.pg, `INSERT INTO oauth_clients (client_id, system, scopes, auth_method, secret_hash, created_at, created_by, updated_at, updated_by)
		VALUES ('ussp-'||$1||'-01', 'ussp', '{registry.validate}', 'client_secret_post', 'x', now(), 'test', now(), 'test')
		ON CONFLICT (client_id) DO NOTHING`, itUSSP)
	f.exec(f.pg, `INSERT INTO certificates (id, holder, holder_name, code, client_id, base_url, services, terms_url, issued_at, valid_until,
		status_changed_at, status_changed_by, lapse_unused_after_months, lapse_ceased_after_months, row_version,
		created_at, created_by, updated_at, updated_by)
		VALUES (md5($1), 'ussp', 'Test USSP', $1, 'ussp-'||$1||'-01', $2, '{network_identification}', 'https://ussp.example.test/terms',
		now() - interval '1 day', now() + interval '1 year', now(), 'test', 6, 12, nextval('certificates_version_seq'),
		now(), 'test', now(), 'test')
		ON CONFLICT (code) DO UPDATE SET base_url = excluded.base_url`, itUSSP, baseURL)
}

func (f *fixture) request(kind string) PackRequest {
	r := PackRequest{Kind: kind, From: f.ts(0), To: f.ts(60), Purpose: "A-M3 review of SC-07"}
	if kind == KindLegal {
		r.CaseRef = "CASE-TEST-17"
	}
	return r
}

func manifestOf(t *testing.T, raw []byte) Manifest {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A-M3: a violation of the WP-12 scenario escalated opens an incident in
// the review's transaction; an evidence pack is built with the raw
// frames, the zone version and the holes labelled; its hash is recorded
// in evidence_packs and in the audit log with the purpose; a download is
// audited with its purpose and is the sealed bytes; the verification
// passes; a tampered copy is detected and refused.
func TestIntegrationEscalatedViolationToAVerifiedPack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.zone()
	zoneID, heightID := f.violations()
	f.telemetry()
	usspDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(usspDown.Close)
	f.usspCertificate(usspDown.URL)

	// Broadcast-only evidence is escalated with a note; the incident is
	// opened in the same transaction.
	if _, err := f.vio.Review(ctx, inspector, zoneID, violations.DecisionEscalated, sp("SC-07 over the park")); err != nil {
		t.Fatal(err)
	}
	if got := f.events("violation", zoneID); !slices.Equal(got, []string{"violation_raised", "violation_cleared", "violation_escalated", "incident_requested"}) {
		t.Fatalf("violation events %v", got)
	}
	rows, err := f.inc.List(ctx, listByViolation(zoneID))
	if err != nil || len(rows) != 1 {
		t.Fatalf("incidents %v %v", rows, err)
	}
	incID := rows[0].IncidentID
	view, err := f.inc.Get(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Incident.Kind != KindViolationEscalated || view.Incident.Narrative != "SC-07 over the park" || len(view.Aircraft) != 1 ||
		*view.Aircraft[0].OperatorReg != itReg || *view.Aircraft[0].Serial != itSerial {
		t.Fatalf("incident %+v aircraft %+v", view.Incident, view.Aircraft)
	}
	if got := f.events("incident", incID); !slices.Equal(got, []string{"incident_opened"}) {
		t.Fatalf("incident events %v", got)
	}
	// The opening is idempotent: a second call returns the same incident.
	err = f.db.WithTx(ctx, func(q *pgGen) error {
		v, err := q.GetViolationForUpdate(ctx, zoneID)
		if err != nil {
			return err
		}
		again, err := f.inc.OpenFromViolation(ctx, q, inspector, &v)
		if err == nil && again != incID {
			err = fmt.Errorf("opened %s beside %s", again, incID)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	row, err := f.packs.Create(ctx, officer, false, incID, f.request(KindOversight))
	if err != nil {
		t.Fatal(err)
	}
	m := manifestOf(t, row.Manifest)
	for _, s := range []string{SecViolations, SecTracks, SecFrames, SecZones, SecPolicies, SecEvents, SecWriterGaps, SecUSSPFlights, SecGround, SecManned} {
		if m.Sections[s].State != StateIncluded {
			t.Errorf("%s: %+v", s, m.Sections[s])
		}
	}
	if m.Sections[SecManned].Count != 1 {
		t.Errorf("manned traffic around the evidence: %+v", m.Sections[SecManned])
	}
	if m.Sections[SecViolations].Count != 2 || m.Sections[SecFrames].Count != 4 || m.FramesWithheld != 1 {
		t.Errorf("violations %d frames %d withheld %d", m.Sections[SecViolations].Count, m.Sections[SecFrames].Count, m.FramesWithheld)
	}
	if len(m.Tracks) != 1 || m.Tracks[0].Segments != 3 || m.Tracks[0].Holes != 2 {
		t.Errorf("tracks %+v", m.Tracks)
	}
	if len(m.AGLNumbers) != 1 || m.AGLNumbers[0].ViolationID != heightID || m.AGLNumbers[0].State != StateIncluded {
		t.Errorf("agl %+v", m.AGLNumbers)
	}
	// The fake USSP's record endpoint is down: said, never missing.
	if len(m.USSPRecords) != 1 || m.USSPRecords[0].State != StateUnavailable || !strings.Contains(m.USSPRecords[0].Reason, "answered 503") {
		t.Errorf("ussp_record %+v", m.USSPRecords)
	}
	data := f.stored(row.StorageRef)
	files := entries(t, data)
	var zones []map[string]any
	if err := json.Unmarshal(files["zones.json"], &zones); err != nil || len(zones) != 1 || zones[0]["zone_id"] != "GEO/SC7" ||
		zones[0]["named_by_violations"].([]any)[0] != zoneID {
		t.Fatalf("zones %v %v", zones, err)
	}
	holes := string(files["tracks/0001.json"])
	for _, want := range []string{CauseNoPosition, CauseWriterGap, CauseSilence, "spill_expired"} {
		if !strings.Contains(holes, want) {
			t.Errorf("no %q in the track file", want)
		}
	}

	// The hash is recorded in evidence_packs and in the audit log.
	if ContentHash(data) != row.ContentHash || row.Signature == nil {
		t.Fatal("the stored archive is not what was sealed")
	}
	purpose, payload := f.lastEvent(incID, audit.EventEvidencePackBuilt)
	if purpose == nil || *purpose != "A-M3 review of SC-07" || payload["content_hash"] != row.ContentHash || payload["pack_id"] != row.PackID {
		t.Fatalf("built event %v %v", purpose, payload)
	}

	// A download is audited with its purpose and serves the sealed bytes.
	got, _, err := f.packs.Download(ctx, officer, false, incID, row.PackID, "court request 17")
	if err != nil || ContentHash(got) != row.ContentHash {
		t.Fatalf("download %v", err)
	}
	purpose, payload = f.lastEvent(incID, audit.EventEvidencePackDownloaded)
	if *purpose != "court request 17" || payload["signature"] != SigVerified {
		t.Fatalf("download event %v %v", *purpose, payload)
	}
	v, err := f.packs.Verify(ctx, officer, incID, row.PackID)
	if err != nil || !v.HashMatches || v.Signature != SigVerified {
		t.Fatalf("verify %+v %v", v, err)
	}

	// A tampered copy: one byte of the stored file changed.
	f.tamperFile(row.StorageRef)
	v, err = f.packs.Verify(ctx, officer, incID, row.PackID)
	if err != nil || v.HashMatches || v.Problem == nil || v.RecomputedHash == nil || *v.RecomputedHash == row.ContentHash {
		t.Fatalf("a tampered pack verified: %+v %v", v, err)
	}
	_, payload = f.lastEvent(incID, audit.EventEvidencePackVerified)
	if payload["hash_matches"] != false {
		t.Fatalf("verified event %v", payload)
	}
	_, _, err = f.packs.Download(ctx, officer, false, incID, row.PackID, "court request 18")
	if p := httpx.ProblemFromError(err); err == nil || p.Status != http.StatusConflict || p.Slug() != SlugTampered {
		t.Fatalf("a tampered pack served: %v", err)
	}
	if got := f.events("incident", incID); !slices.Equal(got, []string{"incident_opened", "evidence_pack_built", "evidence_pack_downloaded",
		"evidence_pack_verified", "evidence_pack_verified", "evidence_pack_verified"}) {
		t.Fatalf("chain of custody %v", got)
	}

	// The pack row is immutable for the application role.
	for _, q := range []string{`UPDATE evidence_packs SET content_hash = content_hash`, `DELETE FROM evidence_packs`} {
		if err := f.asApp(q); err == nil || !strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The trigger refuses even the owner.
	for _, q := range []string{`UPDATE evidence_packs SET content_hash = content_hash`, `DELETE FROM evidence_packs`} {
		if _, err := f.pg.Exec(q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s as the owner: %v", q, err)
		}
	}
	// Its twin: the role reads the row.
	if err := f.asApp(`SELECT content_hash FROM evidence_packs`); err != nil {
		t.Fatal(err)
	}
}

// B-13 and its twin: with the alert store unreadable the pack says
// violations: unavailable (and is still built and verifiable); readable
// again, the next pack includes them.
func TestIntegrationUnreadableAlertStoreIsReported(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	zoneID, _ := f.violations()
	if _, err := f.vio.Review(ctx, inspector, zoneID, violations.DecisionEscalated, sp("note")); err != nil {
		t.Fatal(err)
	}
	rows, err := f.inc.List(ctx, listByViolation(zoneID))
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	incID := rows[0].IncidentID
	f.exec(f.pg, `REVOKE SELECT ON violations FROM authority_app`)
	row, err := f.packs.Create(ctx, officer, false, incID, f.request(KindOversight))
	f.exec(f.pg, `GRANT SELECT ON violations TO authority_app`)
	if err != nil {
		t.Fatal(err)
	}
	m := manifestOf(t, row.Manifest)
	if s := m.Sections[SecViolations]; s.State != StateUnavailable || !strings.Contains(s.Reason, "permission denied") {
		t.Fatalf("violations %+v", s)
	}
	if v, err := f.packs.Verify(ctx, officer, incID, row.PackID); err != nil || !v.HashMatches {
		t.Fatalf("%+v %v", v, err)
	}
	_, payload := f.lastEvent(incID, audit.EventEvidencePackBuilt)
	if fmt.Sprint(payload["sections_unavailable"]) == "[]" || !strings.Contains(fmt.Sprint(payload["sections_unavailable"]), SecViolations) {
		t.Fatalf("the build event does not say what was unavailable: %v", payload)
	}
	row, err = f.packs.Create(ctx, officer, false, incID, f.request(KindOversight))
	if err != nil {
		t.Fatal(err)
	}
	if s := manifestOf(t, row.Manifest).Sections[SecViolations]; s.State != StateIncluded {
		t.Fatalf("readable again: %+v", s)
	}
}

// A legal pack: the USSP record fetched (the endpoint up) and kept, the
// personal data resolved and inside the archive only, the archive sealed
// at rest (no plaintext on disk), served to a personal-data role only.
func TestIntegrationLegalPackIsSealedAndRoleGated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"flight_id":"FLIGHT-INT-1","authorisation":"TEST-AUTH-1"}`))
	}))
	t.Cleanup(up.Close)
	f.usspCertificate(up.URL)
	zoneID, _ := f.violations()
	f.telemetry()
	if _, err := f.vio.Review(ctx, inspector, zoneID, violations.DecisionEscalated, sp("note")); err != nil {
		t.Fatal(err)
	}
	rows, _ := f.inc.List(ctx, listByViolation(zoneID))
	incID := rows[0].IncidentID
	pd := &fakePersonal{known: map[string]map[string]string{itReg: {"full_name": piiName}}}
	f.packs.Builder.Personal = pd
	if _, err := f.packs.Create(ctx, officer, false, incID, f.request(KindLegal)); httpx.ProblemFromError(err).Status != http.StatusForbidden {
		t.Fatalf("a legal pack built without a personal-data role: %v", err)
	}
	row, err := f.packs.Create(ctx, inspector, true, incID, f.request(KindLegal))
	if err != nil {
		t.Fatal(err)
	}
	m := manifestOf(t, row.Manifest)
	if len(m.USSPRecords) != 1 || m.USSPRecords[0].State != StateIncluded || calls.Load() != 1 {
		t.Fatalf("records %+v calls %d", m.USSPRecords, calls.Load())
	}
	if strings.Contains(string(row.Manifest), piiName) || strings.Contains(string(f.stored(row.StorageRef)), piiName) {
		t.Fatal("personal data in the manifest or in plaintext on disk")
	}
	if _, _, err := f.packs.Download(ctx, officer, false, incID, row.PackID, "review"); httpx.ProblemFromError(err).Status != http.StatusForbidden {
		t.Fatalf("a legal pack served without a personal-data role: %v", err)
	}
	data, _, err := f.packs.Download(ctx, inspector, true, incID, row.PackID, "court case 17")
	if err != nil {
		t.Fatal(err)
	}
	files := entries(t, data)
	if !strings.Contains(string(files["personal_data/operators.json"]), piiName) || !strings.Contains(string(files[m.USSPRecords[0].File]), "TEST-AUTH-1") {
		t.Fatal("the legal pack lacks what it carries")
	}
	if len(pd.reads) != 1 || !strings.Contains(pd.reads[0], "CASE-TEST-17") {
		t.Fatalf("registry reads %v", pd.reads)
	}
	if v, err := f.packs.Verify(ctx, inspector, incID, row.PackID); err != nil || !v.HashMatches || v.Signature != SigVerified {
		t.Fatalf("%+v %v", v, err)
	}
	f.tamperFile(row.StorageRef)
	if v, err := f.packs.Verify(ctx, inspector, incID, row.PackID); err != nil || v.HashMatches || v.Problem == nil {
		t.Fatalf("a tampered sealed pack verified: %+v %v", v, err)
	}
}

// The case file: opened by hand, assigned, noted, closed and reopened,
// every change audited; the bounds of aircraft and notes (E-10); notes
// append-only; the backfill opens the incident of an escalation recorded
// without the hook, once.
func TestIntegrationCaseFileLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	v, err := f.inc.Open(ctx, officer, NewIncident{Kind: KindAirprox, OccurredAt: f.ts(0), OpenedFrom: FromANSPNotice,
		NoticeRef: sp("ANSP-TEST-1"), Severity: "warning", Aircraft: []Aircraft{{Serial: sp(itSerial), OperatorReg: sp("FIN87astrdge12k8-xyz")}}})
	if err != nil {
		t.Fatal(err)
	}
	id := v.Incident.IncidentID
	if *v.Aircraft[0].OperatorReg != "FIN87astrdge12k8" {
		t.Fatalf("stored %q", *v.Aircraft[0].OperatorReg)
	}
	steps := []Patch{
		{Status: sp(StatusAssigned), Assignee: sp("officer-2")},
		{Note: sp("called the ANSP")},
		{Status: sp(StatusClosed)},
		{Status: sp(StatusOpen)},
	}
	for i, p := range steps {
		if v, err = f.inc.Update(ctx, officer, id, p); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if v.Incident.Status != StatusOpen || v.Incident.ClosedAt != nil || len(v.Notes) != 1 {
		t.Fatalf("after reopening %+v", v.Incident)
	}
	if _, err := f.inc.Update(ctx, officer, id, Patch{Status: sp(StatusAssigned)}); err != nil {
		t.Fatalf("assigned to the assignee held: %v", err)
	}
	if got := f.events("incident", id); len(got) != 6 || got[0] != "incident_opened" {
		t.Fatalf("events %v", got)
	}
	// Nothing changed: no event.
	if _, err := f.inc.Update(ctx, officer, id, Patch{Status: sp(StatusAssigned)}); err != nil {
		t.Fatal(err)
	}
	if got := f.events("incident", id); len(got) != 6 {
		t.Fatalf("a no-op was audited: %v", got)
	}
	// E-10: aircraft up to the bound, then refused.
	add := make([]Aircraft, MaxAircraft-1)
	for i := range add {
		add[i] = Aircraft{Serial: sp(fmt.Sprintf("TESTBOUND%03d", i))}
	}
	if _, err := f.inc.Update(ctx, officer, id, Patch{AddAircraft: add}); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	_, err = f.inc.Update(ctx, officer, id, Patch{AddAircraft: []Aircraft{{Serial: sp("TESTBOUNDX")}}})
	if p := httpx.ProblemFromError(err); p.Status != http.StatusConflict || p.Slug() != SlugIncidentFull {
		t.Fatalf("past the bound: %v", err)
	}
	// Notes are append-only: the role has no grant, and the trigger
	// refuses even the owner.
	if err := f.asApp(`UPDATE incident_notes SET body = 'x'`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("a note was changed: %v", err)
	}
	for _, q := range []string{`UPDATE incident_notes SET body = 'x'`, `DELETE FROM incident_notes`} {
		if _, err := f.pg.Exec(q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s as the owner: %v", q, err)
		}
	}
	if _, err := f.inc.Get(ctx, "01K6A000000000000000000000"); httpx.ProblemFromError(err).Status != http.StatusNotFound {
		t.Fatalf("missing incident: %v", err)
	}

	// An escalation recorded without the hook (before WP-17) is opened by
	// the backfill, once.
	f.vio.OnEscalate = nil
	zoneID, _ := f.violations()
	if _, err := f.vio.Review(ctx, inspector, zoneID, violations.DecisionEscalated, sp("before WP-17")); err != nil {
		t.Fatal(err)
	}
	if rows, _ := f.inc.List(ctx, listByViolation(zoneID)); len(rows) != 0 {
		t.Fatal("opened without the hook")
	}
	n, err := f.inc.OpenRequested(ctx, 10)
	if err != nil || n != 1 {
		t.Fatalf("backfill %d %v", n, err)
	}
	if n, err := f.inc.OpenRequested(ctx, 10); err != nil || n != 0 {
		t.Fatalf("second backfill %d %v", n, err)
	}
	if rows, _ := f.inc.List(ctx, listByViolation(zoneID)); len(rows) != 1 || rows[0].Kind != KindViolationEscalated {
		t.Fatalf("backfilled %v", rows)
	}
}

func (f *fixture) stored(ref string) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, filepath.FromSlash(strings.TrimPrefix(ref, refPrefix))))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) tamperFile(ref string) {
	f.t.Helper()
	path := filepath.Join(f.dir, filepath.FromSlash(strings.TrimPrefix(ref, refPrefix)))
	b := f.stored(ref)
	b[len(b)/2] ^= 0x01
	if err := os.Chmod(path, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func entries(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	es, err := ReadArchive(archive, 1<<26)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range es {
		out[e.Path] = e.Data
	}
	return out
}
