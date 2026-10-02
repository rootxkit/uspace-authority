package picture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The test kit: the lab's schemas (testdata/lab, verbatim) and this
// repository's extras compiled once, a fake connection, track and
// violation messages built with the producers' own types, and a session
// issuer whose keys exist only for the test.

// Tbilisi, inside Georgia's cells.
const (
	baseLatDeg = 41.7151
	baseLonDeg = 44.8271
)

var (
	schemasOnce sync.Once
	schemas     map[string]*jsonschema.Schema
	errSchemas  error
)

// schemaIDs are the schemas a frame is checked against.
const (
	idStatus          = "https://schemas.uspace.ge/console/status/v1.json"
	idSnapshot        = "https://schemas.uspace.ge/console/snapshot/v1.json"
	idSubscribe       = "https://schemas.uspace.ge/console/subscribe/v1.json"
	idTrack           = "https://schemas.uspace.ge/track/telemetry/v1.json"
	idSource          = "https://schemas.uspace.ge/source/status/v1.json"
	idPictureStatus   = "https://schemas.uspace.ge/picture/status/v1.json"
	idPictureTrack    = "https://schemas.uspace.ge/picture/track/v1.json"
	idViolation       = "https://schemas.uspace.ge/violation/v1.json"
	idPictureSnapshot = "https://schemas.uspace.ge/picture/snapshot/v1.json"
)

func compileSchemas() (map[string]*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	files := []string{
		"testdata/lab/envelope/v1/schema.json", "testdata/lab/console/status/v1/schema.json",
		"testdata/lab/console/snapshot/v1/schema.json", "testdata/lab/console/subscribe/v1/schema.json",
		"testdata/lab/track/telemetry/v1/schema.json", "testdata/lab/source/status/v1/schema.json",
		"../../schemas/picture/status/v1.json", "../../schemas/picture/track/v1.json", "../../schemas/violation/v1.json",
		"../../schemas/picture/snapshot/v1.json",
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		id, _ := doc.(map[string]any)["$id"].(string)
		if err := c.AddResource(id, doc); err != nil {
			return nil, err
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, id := range []string{idStatus, idSnapshot, idSubscribe, idTrack, idSource, idPictureStatus, idPictureTrack, idViolation, idPictureSnapshot} {
		s, err := c.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		out[id] = s
	}
	return out, nil
}

// validate checks raw against the schema id.
func validate(t testing.TB, id string, raw []byte) {
	t.Helper()
	if err := validateErr(id, raw); err != nil {
		t.Fatalf("%s: %v\n%s", id, err, raw)
	}
}

func validateErr(id string, raw []byte) error {
	schemasOnce.Do(func() { schemas, errSchemas = compileSchemas() })
	if errSchemas != nil {
		return errSchemas
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schemas[id].Validate(inst)
}

// validateFrame checks a frame against every schema it must meet: the
// lab's for its schema name and, for the status and track frames, this
// repository's extras; the items of a snapshot one by one.
func validateFrame(t testing.TB, raw []byte) frame {
	t.Helper()
	f := decodeFrame(t, raw)
	switch f.Schema {
	case SchemaStatus:
		validate(t, idStatus, raw)
		validate(t, idPictureStatus, raw)
	case SchemaSnapshot:
		validate(t, idSnapshot, raw)
		validate(t, idPictureSnapshot, raw)
		var b SnapshotBody
		if err := json.Unmarshal(f.Body, &b); err != nil {
			t.Fatal(err)
		}
		for _, tr := range b.Tracks {
			validate(t, idTrack, tr)
			validate(t, idPictureTrack, tr)
		}
		for _, a := range b.Alerts {
			validate(t, idViolation, a)
		}
	case SchemaTrack:
		validate(t, idTrack, raw)
		validate(t, idPictureTrack, raw)
	case SchemaSource:
		validate(t, idSource, raw)
	case SchemaViolation:
		validate(t, idViolation, raw)
	case SchemaManned:
	default:
		t.Fatalf("unexpected frame schema %q", f.Schema)
	}
	return f
}

// frame is a received frame: its envelope and raw body.
type frame struct {
	Schema   string          `json:"schema"`
	MsgID    string          `json:"msg_id"`
	Producer string          `json:"producer"`
	Body     json.RawMessage `json:"body"`
}

func decodeFrame(t testing.TB, raw []byte) frame {
	t.Helper()
	var f frame
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("frame does not decode: %v: %s", err, raw)
	}
	return f
}

func statusOf(t testing.TB, f frame) StatusBody {
	t.Helper()
	var b StatusBody
	if err := json.Unmarshal(f.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func snapshotOf(t testing.TB, f frame) SnapshotBody {
	t.Helper()
	var b SnapshotBody
	if err := json.Unmarshal(f.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// trackFrameBody is what a test reads of a track frame's body.
type trackFrameBody struct {
	TrackID          string              `json:"track_id"`
	Trust            core.Trust          `json:"trust"`
	Identification   core.Identification `json:"identification"`
	AgeS             *float64            `json:"age_s"`
	SourceState      string              `json:"source_state"`
	OperatorPosition *track.Position     `json:"operator_position"`
}

func trackOf(t testing.TB, raw []byte) trackFrameBody {
	t.Helper()
	var f struct {
		Body trackFrameBody `json:"body"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Body
}

// ---- messages ----

func f64(v float64) *float64 { return &v }

// trackMsg is a track message as rid-ingest produces it: direct Remote
// ID, as broadcast and unverified, at lat, lon captured at at.
func trackMsg(t testing.TB, id string, lat, lon float64, at time.Time, status core.IdentStatus) []byte {
	t.Helper()
	return trackMsgWith(t, id, lat, lon, at, status, nil)
}

func trackMsgWith(t testing.TB, id string, lat, lon float64, at time.Time, status core.IdentStatus, operator *track.Position) []byte {
	t.Helper()
	reason := core.ReasonMatched
	switch status {
	case core.IdentSuspended:
		reason = core.ReasonUASSuspended
	case core.IdentUnknownOperator:
		reason = core.ReasonOperatorMismatch
	case core.IdentUnidentified:
		reason = core.ReasonNoSerial
	case core.IdentRegistered:
	}
	ref := f3411.TakeoffLocation
	body := track.Body{
		TrackID: id, Trust: core.TrustBroadcast, Source: track.SourceDirectRID, SourceInstance: "rx-1",
		Position: track.Position{Lat: lat, Lng: lon}, AltAMSLM: f64(500), AltSource: core.AltGeodetic,
		HeightM: f64(40), HeightRef: &ref,
		Identification: core.Identification{Status: status, Reason: reason, Mismatch: reason == core.ReasonOperatorMismatch, Basis: core.BasisAsBroadcast},
	}
	m, err := track.New("authority/rid-ingest", core.Times{RxTS: at, CapturedAt: at, Source: core.TimeReceiver}, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if operator == nil {
		return raw
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["body"].(map[string]any)["operator_position"] = map[string]any{"lat": operator.Lat, "lng": operator.Lng}
	raw, err = json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// violationMsg is a violation/v1 message of detect for track at lat,
// lon in state.
func violationMsg(t testing.TB, id string, lat, lon float64, state violation.State, at time.Time) []byte {
	t.Helper()
	c5, err := cell.Of(core.LatLon{LatDeg: lat, LonDeg: lon}, cell.Level5)
	if err != nil {
		t.Fatal(err)
	}
	b := violation.Body{
		ViolationID: id, Kind: violation.KindZoneIncursion, State: state, Severity: core.SeverityWarning,
		AlertKey: "zone:" + id, TrackRef: "trk-1", CapturedAt: bus.Stamp(at), OpenedAt: bus.Stamp(at), PolicyVersion: 1,
		Detail: map[string]any{}, EvidenceTrust: core.TrustBroadcast, EvidenceRefs: []violation.EvidenceRef{}, EvidenceExcerpt: []violation.Sample{},
		Cell5: c5.String(),
	}
	if state == violation.StateCleared {
		b.ClosedAt, b.ClearReason = ptr(bus.Stamp(at)), ptr("resolved")
	}
	m := bus.Envelope[violation.Body]{
		Schema: violation.Schema, MsgID: bus.NewULID(at), Producer: violation.Producer, TS: bus.Stamp(at),
		RxTS: bus.Stamp(at), CapturedAt: bus.Stamp(at), TimeSource: "system", Body: b,
	}
	if err := violation.Validate(&m); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func subscribeFrameOf(w, s, e, n float64, layers ...string) []byte {
	if layers == nil {
		layers = []string{LayerTracks, LayerManned, LayerAlerts, LayerZones}
	}
	raw, _ := json.Marshal(map[string]any{"schema": SchemaSubscribe, "body": map[string]any{"bbox": []float64{w, s, e, n}, "layers": layers}})
	return raw
}

// ---- a fake connection ----

type fakeConn struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	block  bool

	mu     sync.Mutex
	code   websocket.StatusCode
	reason string
	once   sync.Once
}

func newFakeConn(buffer int) *fakeConn {
	return &fakeConn{in: make(chan []byte, 16), out: make(chan []byte, buffer), closed: make(chan struct{})}
}

func (c *fakeConn) Read(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("closed")
	case b := <-c.in:
		return b, nil
	}
}

func (c *fakeConn) Write(ctx context.Context, f []byte) error {
	if c.block {
		<-ctx.Done()
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return errors.New("closed")
	case c.out <- f:
		return nil
	}
}

func (c *fakeConn) Close(code websocket.StatusCode, reason string) error {
	c.once.Do(func() {
		c.mu.Lock()
		c.code, c.reason = code, reason
		c.mu.Unlock()
		close(c.closed)
	})
	return nil
}

func (c *fakeConn) closeCode() (websocket.StatusCode, string, bool) {
	select {
	case <-c.closed:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.code, c.reason, true
	default:
		return 0, "", false
	}
}

// next is the next frame within d, validated.
func (c *fakeConn) next(t testing.TB, d time.Duration) (frame, []byte) {
	t.Helper()
	select {
	case raw := <-c.out:
		return validateFrame(t, raw), raw
	case <-time.After(d):
		t.Fatalf("no frame within %s", d)
	}
	return frame{}, nil
}

// until reads frames until one of schema arrives, within d.
func (c *fakeConn) until(t testing.TB, schema string, d time.Duration) (frame, []byte) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case raw := <-c.out:
			f := validateFrame(t, raw)
			if f.Schema == schema {
				return f, raw
			}
		case <-deadline:
			t.Fatalf("no %s within %s", schema, d)
		}
	}
}

// drain discards the frames already queued.
func (c *fakeConn) drain() {
	for {
		select {
		case <-c.out:
		default:
			return
		}
	}
}

// ---- sessions ----

type fakeChecker struct {
	mu   sync.Mutex
	sess Session
	err  error
}

func (f *fakeChecker) Check(context.Context, string) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sess, f.err
}

func (f *fakeChecker) set(s Session, err error) {
	f.mu.Lock()
	f.sess, f.err = s, err
	f.mu.Unlock()
}

func consoleSession() Session {
	return Session{Subject: "u-1", JTI: "j-1", Realm: RealmConsole, Roles: []string{"viewer"}}
}

// testIssuer is this issuer with a key generated for the test (no key
// in git, CLAUDE.md rule 11).
type testIssuer struct {
	iss *auth.Issuer
}

const (
	issuerURL = "https://authority.example.test"
	ownHost   = "authority.example.test"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func newTestIssuer(t testing.TB) *testIssuer {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	iss, err := auth.NewIssuer(issuerURL, testKey, "test-kid-1")
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{iss: iss}
}

func (ti *testIssuer) session(t testing.TB, realm, jti string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	tok, err := ti.iss.IssueSession(auth.SessionClaims{
		Audience: ownHost, Subject: "u-1", Roles: []string{"viewer"}, Realm: realm, IssuedAt: now, ExpiresAt: now.Add(ttl), JTI: jti,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (ti *testIssuer) machine(t testing.TB) string {
	t.Helper()
	tok, err := ti.iss.Issue("cisp-01", ownHost, []string{"cis.read"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (ti *testIssuer) verifier(t testing.TB) *auth.Verifier {
	t.Helper()
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{issuerURL: {Keys: ti.iss.JWKS()}}, Audiences: []string{ownHost}, StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- hubs ----

// testHub is a hub with small bounds and fast periods, no bus behind it.
func testHub(t testing.TB, mutate func(*Config, *Inputs)) *Hub {
	t.Helper()
	cfg := Config{SendBuffer: 256, StatusInterval: 50 * time.Millisecond, WriteTimeout: time.Second, ThrottleEvery: 500 * time.Millisecond}
	in := Inputs{}
	if mutate != nil {
		mutate(&cfg, &in)
	}
	h := NewHub(cfg, in, nil, nil)
	t.Cleanup(h.Close)
	return h
}

// connect attaches a console with sess to h over a fake connection and
// returns it after its first status and snapshot.
func connect(t testing.TB, h *Hub, sess Session, checker Checker) *fakeConn {
	t.Helper()
	conn := newFakeConn(4096)
	if !h.Reserve() {
		t.Fatal("hub full")
	}
	go h.Serve(conn, sess, "token", checker)
	if f, _ := conn.next(t, 2*time.Second); f.Schema != SchemaStatus {
		t.Fatalf("first frame %s", f.Schema)
	}
	if f, _ := conn.next(t, 2*time.Second); f.Schema != SchemaSnapshot {
		t.Fatalf("second frame %s", f.Schema)
	}
	return conn
}

// subscribe sends a subscription and returns the status and snapshot
// that answer it.
func subscribe(t testing.TB, conn *fakeConn, raw []byte) (StatusBody, SnapshotBody) {
	t.Helper()
	conn.in <- raw
	sf, _ := conn.until(t, SchemaStatus, 2*time.Second)
	nf, _ := conn.until(t, SchemaSnapshot, 2*time.Second)
	return statusOf(t, sf), snapshotOf(t, nf)
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func readExample(t testing.TB, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "lab", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func listExamples(t testing.TB, rel string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join("testdata", "lab", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, rel+"/"+e.Name())
		}
	}
	return out
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

// jsonNames lists the JSON member names of v's type, walked through
// structs (embedded ones flattened), pointers, slices and map values,
// each prefixed by its path.
func jsonNames(prefix string, v any) []string {
	return walkNames(prefix, reflect.TypeOf(v), map[reflect.Type]bool{})
}

func walkNames(prefix string, t reflect.Type, seen map[reflect.Type]bool) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return nil
	}
	seen[t] = true
	defer delete(seen, t)
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		if f.Anonymous && name == "" {
			out = append(out, walkNames(prefix, f.Type, seen)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, prefix+"."+name)
		out = append(out, walkNames(prefix+"."+name, f.Type, seen)...)
	}
	return out
}
