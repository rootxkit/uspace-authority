// Package dpviews is the set of areas the F3411 Display Provider shows
// (WP-14), as it travels between the processes: the oversight areas api
// holds (POST /v1/dp/views, persisted in dp_views and published to KV
// bucket dp_oversight under key "views" after every commit and
// republished periodically), and the console viewports picture-ws
// reports (KV bucket dp_views, one key per picture-ws instance, with a
// bucket TTL so an idle console stops polling). dp-poller reads both.
// The package holds the shapes, their bounds (E-10) and the KV
// operations; nothing here decides what is displayed.
package dpviews

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
)

// Buckets and keys.
const (
	OversightBucket = "dp_oversight"
	OversightKey    = "views"
	ConsoleBucket   = "dp_views"
	// ConsoleKeyPrefix prefixes a picture-ws instance's key.
	ConsoleKeyPrefix = "console."
)

// Bounds (E-10).
const (
	// MaxOversight bounds the oversight areas.
	MaxOversight = 256
	// MaxConsoleBoxes bounds the viewports one picture-ws reports.
	MaxConsoleBoxes = 64
	// OversightValueBytes and ConsoleValueBytes bound the KV values.
	OversightValueBytes = 64 << 10
	ConsoleValueBytes   = 16 << 10
	// ConsoleTTL is how long a reported viewport is displayed without
	// being reported again: an idle console stops polling.
	ConsoleTTL = 60 * time.Second
	// ConsoleEvery is how often picture-ws reports, well inside the TTL.
	ConsoleEvery = 15 * time.Second
)

// BBox is [west, south, east, north] in WGS84 degrees, the order of the
// console's viewport (console/subscribe/v1).
type BBox [4]float64

// Check refuses a box that is not a usable view: non-finite, outside
// WGS84, empty, or crossing the antimeridian (west >= east).
func (b BBox) Check() error {
	for _, v := range b {
		if !core.IsFinite(v) {
			return core.Fieldf("bbox", "not a finite number")
		}
	}
	w, s, e, n := b[0], b[1], b[2], b[3]
	switch {
	case s < -90 || n > 90:
		return core.Fieldf("bbox", "latitudes must be in [-90, 90]")
	case w < -180 || e > 180:
		return core.Fieldf("bbox", "longitudes must be in [-180, 180]")
	case s >= n:
		return core.Fieldf("bbox", "south must be below north")
	case w >= e:
		return core.Fieldf("bbox", "west must be below east (an area never crosses the antimeridian)")
	}
	return nil
}

// Area is one oversight area.
type Area struct {
	ID    int64  `json:"id"`
	Label string `json:"label"`
	BBox  BBox   `json:"bbox"`
}

// Oversight is the KV value of the oversight areas. Version is the
// database's: a writer never replaces a stored value of a higher
// version (two api replicas never move it backwards).
type Oversight struct {
	Version int64  `json:"version"`
	Areas   []Area `json:"areas"`
}

// Console is the KV value of one picture-ws instance's viewports.
type Console struct {
	Instance string    `json:"instance"`
	At       time.Time `json:"at"`
	BBoxes   []BBox    `json:"bboxes"`
}

// ErrMalformed is a value that is not one of these shapes.
var ErrMalformed = errors.New("dp views value malformed")

// DecodeOversight reads an Oversight value, bounded; a bad area is
// refused with the whole value (the reader keeps what it holds).
func DecodeOversight(raw []byte) (Oversight, error) {
	if len(raw) > OversightValueBytes {
		return Oversight{}, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var o Oversight
	if err := json.Unmarshal(raw, &o); err != nil {
		return Oversight{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(o.Areas) > MaxOversight {
		return Oversight{}, fmt.Errorf("%w: %d areas, at most %d", ErrMalformed, len(o.Areas), MaxOversight)
	}
	for i, a := range o.Areas {
		if err := a.BBox.Check(); err != nil {
			return Oversight{}, fmt.Errorf("%w: areas[%d]: %w", ErrMalformed, i, err)
		}
	}
	return o, nil
}

// DecodeConsole reads a Console value, bounded.
func DecodeConsole(raw []byte) (Console, error) {
	if len(raw) > ConsoleValueBytes {
		return Console{}, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var c Console
	if err := json.Unmarshal(raw, &c); err != nil {
		return Console{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(c.BBoxes) > MaxConsoleBoxes {
		return Console{}, fmt.Errorf("%w: %d boxes, at most %d", ErrMalformed, len(c.BBoxes), MaxConsoleBoxes)
	}
	for i, b := range c.BBoxes {
		if err := b.Check(); err != nil {
			return Console{}, fmt.Errorf("%w: bboxes[%d]: %w", ErrMalformed, i, err)
		}
	}
	return c, nil
}

// OversightBucketConfig is the oversight bucket: no TTL, the areas stay
// until api replaces them.
func OversightBucketConfig(name string) jetstream.KeyValueConfig {
	if name == "" {
		name = OversightBucket
	}
	return jetstream.KeyValueConfig{
		Bucket: name, Description: "Display Provider oversight areas (POST /v1/dp/views): one key, every area",
		History: 8, MaxValueSize: OversightValueBytes, MaxBytes: -1, Storage: jetstream.FileStorage, Replicas: 1,
	}
}

// ConsoleBucketConfig is the console viewports bucket: every value lives
// ConsoleTTL unless reported again.
func ConsoleBucketConfig(name string) jetstream.KeyValueConfig {
	if name == "" {
		name = ConsoleBucket
	}
	return jetstream.KeyValueConfig{
		Bucket: name, Description: "console viewports picture-ws reports for the Display Provider, one key per instance, expiring",
		History: 1, MaxValueSize: ConsoleValueBytes, MaxBytes: -1, TTL: ConsoleTTL, Storage: jetstream.MemoryStorage, Replicas: 1,
	}
}

var keyToken = regexp.MustCompile(`[^-_=a-zA-Z0-9]`)

// ConsoleKey is the key of a picture-ws instance (KV key characters
// only).
func ConsoleKey(instance string) string {
	s := keyToken.ReplaceAllString(instance, "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return ConsoleKeyPrefix + s
}

// PutOversight stores o unless the bucket holds a higher version, with
// compare-and-set so two writers never interleave (at most attempts
// tries). It reports whether o was stored.
func PutOversight(ctx context.Context, kv jetstream.KeyValue, o Oversight, attempts int) (bool, error) {
	data, err := json.Marshal(o)
	if err != nil {
		return false, err
	}
	if len(data) > OversightValueBytes {
		return false, fmt.Errorf("oversight areas are %d bytes, at most %d", len(data), OversightValueBytes)
	}
	var last error
	for range max(1, attempts) {
		e, err := kv.Get(ctx, OversightKey)
		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound):
			if _, last = kv.Create(ctx, OversightKey, data); last == nil {
				return true, nil
			}
			continue
		case err != nil:
			return false, err
		}
		if held, err := DecodeOversight(e.Value()); err == nil && held.Version > o.Version {
			return false, nil
		}
		if _, last = kv.Update(ctx, OversightKey, data, e.Revision()); last == nil {
			return true, nil
		}
	}
	return false, last
}

// Boxes is every box of the values, oversight first.
func Boxes(o Oversight, consoles []Console) []BBox {
	out := make([]BBox, 0, len(o.Areas))
	for _, a := range o.Areas {
		out = append(out, a.BBox)
	}
	for _, c := range consoles {
		out = append(out, c.BBoxes...)
	}
	return out
}

// Round snaps a console box outwards to 1e-4 degrees (about 10 m), so
// small pans of a viewport do not make new tiles every report.
func Round(b BBox) BBox {
	const q = 1e4
	return BBox{math.Floor(b[0]*q) / q, math.Floor(b[1]*q) / q, math.Ceil(b[2]*q) / q, math.Ceil(b[3]*q) / q}
}
