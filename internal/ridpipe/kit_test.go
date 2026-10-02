package ridpipe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// The test kit: a simulated receiver that encodes its frames with
// uspace-core odid.Encode (never a hand-written byte), a recording
// publisher, and a pipeline built around them.

// recorder is a bus.Publisher that keeps every message.
type recorder struct {
	mu   sync.Mutex
	msgs []published
	err  error
	// identErr fails ident.v1 publishes only.
	identErr error
}

type published struct {
	subject string
	data    []byte
}

func (r *recorder) Publish(subject string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.identErr != nil && strings.HasPrefix(subject, "ident.v1.") {
		return r.identErr
	}
	r.msgs = append(r.msgs, published{subject, append([]byte(nil), data...)})
	return nil
}

// tracks are the trk.v1 messages published so far, in order.
func (r *recorder) tracks(t *testing.T) []track.Message {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []track.Message
	for _, m := range r.msgs {
		if !strings.HasPrefix(m.subject, "trk.v1.") {
			continue
		}
		var tm track.Message
		dec := json.NewDecoder(bytes.NewReader(m.data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&tm); err != nil {
			t.Fatalf("%s: %v", m.subject, err)
		}
		if err := tm.Validate(); err != nil {
			t.Fatalf("published an invalid track: %v", err)
		}
		if want, err := track.SubjectOf(&tm); err != nil || want != m.subject {
			t.Fatalf("published on %s, want %s (%v)", m.subject, want, err)
		}
		out = append(out, tm)
	}
	return out
}

// idents are the ident.v1 messages published so far, in order.
func (r *recorder) idents(t *testing.T) []track.IdentChange {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []track.IdentChange
	for _, m := range r.msgs {
		if !strings.HasPrefix(m.subject, "ident.v1.") {
			continue
		}
		var c track.IdentChange
		if err := json.Unmarshal(m.data, &c); err != nil {
			t.Fatal(err)
		}
		if m.subject != "ident.v1."+c.Body.TrackID {
			t.Fatalf("ident change for %s on %s", c.Body.TrackID, m.subject)
		}
		out = append(out, c)
	}
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.msgs = nil
	r.mu.Unlock()
}

// constGeoid is a geoid.Undulator with one undulation everywhere (a
// stand-in for WP-11's grid; the subtraction is core's).
type constGeoid struct{ n float64 }

func (g constGeoid) UndulationM(core.LatLon) (float64, error) { return g.n, nil }

// failingGeoid answers every position with an error.
type failingGeoid struct{}

func (failingGeoid) UndulationM(core.LatLon) (float64, error) {
	return 0, &core.FieldError{Field: "position", Reason: "outside the grid"}
}

func f64(v float64) *float64 { return &v }

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// Positions of the simulated aircraft: Tbilisi, inside Georgia's cells.
const (
	baseLatDeg = 41.7151
	baseLonDeg = 44.8271
)

// loc is an airborne Location at lat, lon with a geodetic and a
// pressure altitude of good accuracy, a velocity and no timestamp.
func loc(lat, lon float64) odid.Location {
	return odid.Location{
		Status: odid.StatusAirborne, LatDeg: f64(lat), LonDeg: f64(lon), AltHAEM: f64(520), AltBaroM: f64(507.5),
		VertAccuracy: 4, SpeedHorizontalMS: f64(10), DirectionDeg: f64(90), SpeedVerticalMS: f64(1.5),
	}
}

// frame encodes msgs as one message, or as a pack when there are
// several (odid.Encode, odid.EncodePack).
func frame(t testing.TB, msgs ...odid.Message) []byte {
	t.Helper()
	if len(msgs) == 1 {
		b, err := odid.Encode(msgs[0])
		if err != nil {
			t.Fatalf("encode %T: %v", msgs[0], err)
		}
		return b[:]
	}
	b, err := odid.EncodePack(msgs)
	if err != nil {
		t.Fatalf("encode pack: %v", err)
	}
	return b
}

// rxRow is one observation heard by receiver rx from transmitter tx at
// heard on the receiver's clock (nil: the receiver sent no rx_ts).
func rxRow(rx, tx string, payload []byte, heard *time.Time) Row {
	sum := sha256.Sum256(payload)
	id := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%v|%x", rx, tx, heard, sum))
	r := Row{
		FrameID: hex.EncodeToString(id[:16]), ReceiverID: rx, Transmitter: tx, ReceiverTS: heard,
		Payload: payload, PayloadSHA256: sum[:], Nonce: "n",
	}
	if len(payload) > 0 {
		mt := int(payload[0] >> 4)
		r.MsgType = &mt
	}
	return r
}

// batchOf is a batch of rx received by this system at ingest.
func batchOf(rx string, ingest time.Time, backlog bool, rows ...Row) *Batch {
	for i := range rows {
		rows[i].IngestTS = ingest
		rows[i].Backlog = backlog
	}
	return &Batch{ID: fmt.Sprintf("%s:%d", rx, ingest.UnixNano()), ReceiverID: rx, IngestTS: ingest, Backlog: backlog, Rows: rows}
}

func at(t time.Time) *time.Time { return &t }

// quiet is a limiter on a discarded logger.
func quiet() *logging.Limiter { return logging.NewLimiter(logging.Discard(), time.Minute, 0, nil) }

// pipe is a pipeline publishing to a recorder.
func pipe(s Settings, d Deps) (*Pipeline, *recorder) {
	rec := &recorder{}
	if d.Publisher == nil {
		d.Publisher = rec
	}
	if d.Limiter == nil {
		d.Limiter = quiet()
	}
	return New(s, d), rec
}

// observe hands b to p and fails the test on an error.
func observe(t testing.TB, p *Pipeline, b *Batch) {
	t.Helper()
	if err := p.Observe(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

// fixedProjection is a registry projection source answering one read.
type fixedProjection struct{ l registry.Loaded }

func (f fixedProjection) LoadProjection(context.Context) (registry.Loaded, error) { return f.l, nil }

// loadedRegistry is WP-3's ProjectionReader after one good read of ops
// and uas: the lookup a running rid-ingest resolves against.
func loadedRegistry(t testing.TB, ops []identify.OperatorFacts, uas []identify.UASFacts) func() identify.Lookup {
	t.Helper()
	r := &registry.ProjectionReader{Source: fixedProjection{registry.Loaded{Operators: ops, UAS: uas, Version: 1}}}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r.Lookup
}

// logBuffer is a JSON logger whose lines a test reads back.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), `"msg":"`+msg+`"`)
}

func (l *logBuffer) logger() *slog.Logger { return slog.New(slog.NewJSONHandler(l, nil)) }
