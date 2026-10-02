package zonesvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/projector"
)

// ProjectedZone is one row of proj_zones.
type ProjectedZone struct {
	Dataset     Dataset
	Identifier  string
	ZoneVersion int
	Feature     json.RawMessage
	ValidFrom   time.Time
	ValidTo     time.Time
	Type        string
	BBox        BBox
}

// key is the row's key as DeleteProjectedZonesExcept compares it.
func (z *ProjectedZone) key() string {
	return string(z.Dataset) + "/" + z.Identifier + "/" + strconv.Itoa(z.ZoneVersion)
}

// Projection is where the zones projection is written: proj_zones in the
// telemetry database (D2), or a fake in tests.
type Projection interface {
	// Replace makes the projection hold exactly rows, in one telemetry
	// transaction, and returns how many other rows it deleted.
	Replace(ctx context.Context, rows []ProjectedZone, at time.Time, zonesVersion int64) (int64, error)
}

// TSProjection is Projection on the telemetry database, as
// authority_ts_projector.
type TSProjection struct {
	P *ts.Projector
}

// Replace implements Projection.
func (p TSProjection) Replace(ctx context.Context, rows []ProjectedZone, at time.Time, zonesVersion int64) (int64, error) {
	tx, err := p.P.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	params := projector.UpsertProjectedZonesParams{ProjectedAt: at, ZonesVersion: zonesVersion}
	keys := make([]string, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		params.Datasets = append(params.Datasets, string(r.Dataset))
		params.Identifiers = append(params.Identifiers, r.Identifier)
		params.ZoneVersions = append(params.ZoneVersions, int32(r.ZoneVersion))
		params.Features = append(params.Features, string(r.Feature))
		params.ValidFroms = append(params.ValidFroms, r.ValidFrom)
		params.ValidTos = append(params.ValidTos, r.ValidTo)
		params.Types = append(params.Types, r.Type)
		params.MinLats = append(params.MinLats, r.BBox.MinLatDeg)
		params.MinLons = append(params.MinLons, r.BBox.MinLonDeg)
		params.MaxLats = append(params.MaxLats, r.BBox.MaxLatDeg)
		params.MaxLons = append(params.MaxLons, r.BBox.MaxLonDeg)
		keys = append(keys, r.key())
	}
	if len(rows) > 0 {
		if _, err := tx.Q.UpsertProjectedZones(ctx, params); err != nil {
			return 0, err
		}
	}
	deleted, err := tx.Q.DeleteProjectedZonesExcept(ctx, keys)
	if err != nil {
		return 0, err
	}
	return deleted, tx.Commit(ctx)
}

// projectedRows are the projection rows of the stored versions; each
// feature is parsed again for its box.
func projectedRows(vs []Version) ([]ProjectedZone, error) {
	out := make([]ProjectedZone, 0, len(vs))
	for i := range vs {
		v := &vs[i]
		fc, probs := ed318.Parse(wrapFeature(v.Feature), ed318.Limits{})
		if probs != nil {
			return nil, fmt.Errorf("zone %s version %d does not parse: %w", v.Identifier, v.ZoneVersion, probs)
		}
		out = append(out, ProjectedZone{
			Dataset: v.Dataset, Identifier: v.Identifier, ZoneVersion: v.ZoneVersion, Feature: v.Feature,
			ValidFrom: v.ValidFrom, ValidTo: v.ValidTo, Type: v.Type, BBox: featureBBox(&fc.Features[0]),
		})
	}
	return out, nil
}

// Publisher announces a new zones version after a publication:
// zones.v1.changed and KV zones_version (docs/PLAN.md §6). Readers that
// miss it catch up on their periodic re-read.
type Publisher interface {
	PublishZonesVersion(ctx context.Context, version int64) error
}

// NopPublisher publishes nowhere.
type NopPublisher struct{}

// PublishZonesVersion does nothing.
func (NopPublisher) PublishZonesVersion(context.Context, int64) error { return nil }

// VersionKey is the key of the zones version in KV zones_version.
const VersionKey = "current"

// BusPublisher announces on the bus: the version in KV zones_version
// (key VersionKey) and a push on zones.v1.changed. Each call is bounded
// by Timeout.
type BusPublisher struct {
	NC      *nats.Conn
	JS      jetstream.JetStream
	Bucket  jetstream.KeyValueConfig
	Timeout time.Duration
}

// NewBusPublisher binds the zones_version bucket of the topology.
func NewBusPublisher(bp *bus.Process, timeout time.Duration) *BusPublisher {
	cfg, _ := bp.Topology.Bucket(bus.BucketZonesVersion)
	return &BusPublisher{NC: bp.NC, JS: bp.JS, Bucket: cfg, Timeout: timeout}
}

// versionMessage is the KV value and the push body.
type versionMessage struct {
	ZonesVersion int64 `json:"zones_version"`
}

// PublishZonesVersion implements Publisher.
func (p *BusPublisher) PublishZonesVersion(ctx context.Context, version int64) error {
	body, err := json.Marshal(versionMessage{ZonesVersion: version})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	kv, err := bus.OpenBucket(ctx, p.JS, p.Bucket)
	if err != nil {
		return err
	}
	if _, err := kv.Put(ctx, VersionKey, body); err != nil {
		return fmt.Errorf("zones_version: %w", err)
	}
	return p.NC.Publish(bus.SubjectZonesChanged, body)
}
