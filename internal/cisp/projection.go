package cisp

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/projector"
)

// RestrictionRow is one row of proj_restrictions.
type RestrictionRow struct {
	Identifier       string
	Feature          []byte
	State            string
	StartsAt         time.Time
	EndsAt           time.Time
	ANSPRef          string
	USpaceAirspaceID string
}

// restrictionStates are the states proj_restrictions admits besides
// unknown (the CISP's CisRestriction.state).
var restrictionStates = map[string]bool{"planned": true, "active": true, "ended": true, "cancelled": true}

// RestrictionRows are the projection rows of a restrictions version: every
// feature as served, with the state and window of its CISP block (a
// state this build does not know is projected as unknown, never dropped).
func RestrictionRows(v *Version) []RestrictionRow {
	out := make([]RestrictionRow, 0, len(v.Features))
	for i := range v.Features {
		f := &v.Features[i]
		r := RestrictionRow{Identifier: f.Identifier, Feature: f.Raw, State: "unknown"}
		if b := f.Restriction; b != nil {
			if restrictionStates[string(b.State)] {
				r.State = string(b.State)
			}
			r.StartsAt, r.EndsAt, r.ANSPRef, r.USpaceAirspaceID = b.StartsAt, b.EndsAt, b.AnspRef, b.UspaceAirspaceId
		}
		out = append(out, r)
	}
	return out
}

// ErrProjectionNewer is returned when the projection already holds a
// newer CIS version than the one written (another replica got there
// first); nothing was written.
var ErrProjectionNewer = errors.New("the restrictions projection holds a newer version")

// Projector writes the restrictions projection the detectors read.
type Projector interface {
	ProjectRestrictions(ctx context.Context, version int64, etag string, rows []RestrictionRow, at time.Time) error
}

// TSProjector is Projector on the telemetry database, as
// authority_ts_projector: one transaction under the projection's lock,
// refusing a version older than the state row's, replacing every row
// and the state row.
type TSProjector struct {
	P *ts.Projector
}

// ProjectRestrictions implements Projector.
func (p TSProjector) ProjectRestrictions(ctx context.Context, version int64, etag string, rows []RestrictionRow, at time.Time) error {
	tx, err := p.P.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Q.LockRestrictionsProjection(ctx); err != nil {
		return err
	}
	held, err := tx.Q.RestrictionsProjectionVersion(ctx)
	if err != nil {
		return err
	}
	if held > version {
		return ErrProjectionNewer
	}
	if _, err := tx.Q.DeleteAllRestrictions(ctx); err != nil {
		return err
	}
	if len(rows) > 0 {
		params := projector.InsertRestrictionsParams{CisVersion: version, ProjectedAt: at}
		for i := range rows {
			r := &rows[i]
			params.Identifiers = append(params.Identifiers, r.Identifier)
			params.Features = append(params.Features, string(r.Feature))
			params.States = append(params.States, r.State)
			params.Starts = append(params.Starts, r.StartsAt)
			params.Ends = append(params.Ends, r.EndsAt)
			params.AnspRefs = append(params.AnspRefs, r.ANSPRef)
			params.AirspaceIds = append(params.AirspaceIds, r.USpaceAirspaceID)
		}
		if _, err := tx.Q.InsertRestrictions(ctx, params); err != nil {
			return err
		}
	}
	if err := tx.Q.UpsertRestrictionsState(ctx, projector.UpsertRestrictionsStateParams{
		CisVersion: version, Etag: etag, ProjectedAt: at,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Announcer announces a cached version on cis.v1.<dataset> (docs/PLAN.md
// §6): detect re-reads proj_restrictions at once (Z-12), picture-ws
// shows the version.
type Announcer interface {
	Announce(ctx context.Context, c *Cached) error
}

// CacheSchema names the body of a cis.v1.<dataset> message
// (schemas/cache/cis/v1.json, owned here: NATS never crosses a system).
const CacheSchema = "cache/cis/v1"

// CacheMessage is the body of a cis.v1.<dataset> message.
type CacheMessage struct {
	Dataset      string     `json:"dataset"`
	CISVersion   int64      `json:"cis_version"`
	ETag         string     `json:"etag"`
	CISUpdatedAt *time.Time `json:"cis_updated_at,omitempty"`
	FeatureCount int        `json:"feature_count"`
	FetchedAt    time.Time  `json:"fetched_at"`
}

// BusAnnouncer writes the announcement to the CIS stream; each write is
// bounded by Timeout.
type BusAnnouncer struct {
	JS       jetstream.JetStream
	Producer string
	Timeout  time.Duration
	Now      func() time.Time
}

// Announce implements Announcer.
func (b *BusAnnouncer) Announce(ctx context.Context, c *Cached) error {
	subject, err := bus.Subjects.Cis(string(c.Dataset))
	if err != nil {
		return err
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	env := bus.SystemEnvelope(CacheSchema, b.Producer, now, CacheMessage{
		Dataset: string(c.Dataset), CISVersion: c.Version, ETag: c.ETag, CISUpdatedAt: c.UpdatedAt,
		FeatureCount: c.FeatureCount, FetchedAt: c.FetchedAt.UTC(),
	})
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, err = bus.PublishJS(ctx, b.JS, subject, env)
	return err
}
