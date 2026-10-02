package zonesvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
)

// Counters of the zone service (status line and /metrics, E-09).
const (
	CounterRefused               = "zones_change_refused"          // a write, import, approval or publication refused
	CounterProjectionWriteFailed = "zones_projection_write_failed" // a publication rolled back because its projection write failed
	CounterProjectionAhead       = "zones_projection_ahead"        // the projection committed, the relational commit failed; a repair was requested
	CounterAnnounceFailed        = "zones_announce_failed"         // a publication committed, its push failed; readers catch up on their re-read
	CounterReprojected           = "zones_reprojected"             // full re-projections written
	CounterReprojectFailed       = "zones_reproject_failed"        // a full re-projection failed; it is retried
	CounterReprojectRetried      = "zones_reproject_retried"       // a failed re-projection retried before the periodic run
	CounterReprojectSkipped      = "zones_reproject_skipped"       // another replica held the job lock
	CounterProjectionDeleted     = "zones_projection_rows_deleted" // projection rows the relational state no longer holds, deleted
	CounterPublished             = "zones_published"               // publications written to the outbox
	CounterExported              = "zones_exported"                // exports answered
	CounterDaylightUnavailable   = "zones_daylight_unavailable"    // an applicability question refused: no daylight source
)

// Advisory locks. LockProjection is held by every publication and by the
// full re-projection from its relational read to its projection commit,
// so a publication waits for a running re-projection and is never
// overwritten by its older read (G-08). LockReprojectJob keeps two api
// replicas from running the job at once.
const (
	LockProjection   = "zones_projection"
	LockReprojectJob = "zones_reprojection_job"
)

// Problem slugs of this package.
const (
	SlugProjection      = "projection_unavailable"
	SlugNothing         = "nothing_to_publish"
	SlugFilterConflict  = "filter_conflict"
	SlugDatasetTooLarge = "dataset_too_large"
)

// ErrProjection marks a publication rolled back because its projection
// write failed.
var ErrProjection = errors.New("zones projection not written")

// MaxPageSize bounds a list page.
const MaxPageSize = 500

// Event and entity types (internal/audit catalogue).
const (
	entityZone   = "zone"
	entityUSpace = "uspace_airspace"
)

// Meta is the collection metadata of every export and publication:
// ed318.Metadata's names (issued, provider), never the spec's
// creationDateTime / updateDateTime / originator (M15).
type Meta struct {
	ProviderName string
	ProviderLang string
}

// Service authors, stores, exports and publishes zones and U-space
// airspaces (api only).
type Service struct {
	Store      Store
	Projection Projection
	Publisher  Publisher
	// Daylight resolves daylight events for applicability answers;
	// nil is ground.Daylight (core's ed318.NOAADaylight).
	Daylight ed318.Daylight
	Meta     Meta
	Counters *core.Counters
	Logger   *slog.Logger

	repairOnce sync.Once
	repair     chan struct{}
}

func (s *Service) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Service) daylight() ed318.Daylight {
	if s.Daylight == nil {
		return ground.Daylight()
	}
	return s.Daylight
}

func (s *Service) repairs() chan struct{} {
	s.repairOnce.Do(func() { s.repair = make(chan struct{}, 1) })
	return s.repair
}

// RequestRepair asks the job loop for a full re-projection now.
func (s *Service) RequestRepair() {
	select {
	case s.repairs() <- struct{}{}:
	default:
	}
}

// refused counts a refusal (a problem below 500) and passes err on.
func (s *Service) refused(err error) error {
	if err != nil && httpx.ProblemFromError(err).Status < http.StatusInternalServerError {
		s.count(CounterRefused)
	}
	return err
}

// validation is the 400 of a refused document: every field error, and
// truncated when more were found than the problem holds.
func validation(detail string, errs []*core.FieldError, more int) error {
	p := httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", detail, errs...)
	if more > 0 {
		p.Truncated = true
	}
	return &httpx.ProblemError{Problem: p}
}

func conflict(detail string, fe *core.FieldError) error {
	return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, detail, fe)
}

func notFound(ds Dataset, identifier string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such "+entityOf(ds),
		core.Fieldf("identifier", "%s %q does not exist", entityOf(ds), identifier))
}

func entityOf(ds Dataset) string {
	if ds == DatasetUSpace {
		return entityUSpace
	}
	return entityZone
}

// projectionRefusal is the 503 of a publication whose projection write
// failed. The detail names the cause without echoing the driver's text.
func projectionRefusal(err error) error {
	reason := "the telemetry database could not be reached"
	if state := store.SQLState(err); state != "" {
		reason = "the telemetry database refused the write (SQLSTATE " + state + ")"
		if c := store.Constraint(err); c != "" {
			reason += " on " + c
		}
	}
	return errors.Join(ErrProjection, httpx.Refuse(http.StatusServiceUnavailable, SlugProjection,
		"the zones projection could not be written, so the publication was rolled back: "+reason))
}

// DraftInput is one authored version as the API receives it.
type DraftInput struct {
	// Identifier is the path's identifier of a replacement; empty for a
	// creation.
	Identifier  string
	Feature     []byte
	ValidFrom   *time.Time
	ValidTo     *time.Time
	Designation *Designation
}

// prepare validates in and returns the draft to store. For a U-space
// airspace the designation's Art. 3(4) block is written into the
// feature first, and the feature is validated with it.
func prepare(ds Dataset, in *DraftInput) (*Draft, error) {
	fromField, toField := "valid_from", "valid_to"
	if ds == DatasetUSpace {
		fromField, toField = "designated_from", "designated_to"
	}
	errs := checkPeriod(fromField, toField, in.ValidFrom, in.ValidTo)
	feature := in.Feature
	if len(feature) > MaxDocumentBytes {
		errs = append(errs, core.Fieldf("feature", "is %d bytes; at most %d", len(feature), MaxDocumentBytes))
		return nil, validation("", errs, 0)
	}
	if ds == DatasetUSpace {
		if in.Designation == nil {
			return nil, validation("", append(errs, core.Fieldf("designation", "required")), 0)
		}
		fc, probs := ed318.Parse(wrapFeature(feature), ed318.Limits{})
		self := ""
		if probs == nil && len(fc.Features) == 1 {
			self = fc.Features[0].Properties.Identifier
		}
		errs = append(errs, checkDesignation(in.Designation, self, "designation")...)
		if len(errs) > 0 {
			return nil, validation("", errs, 0)
		}
		var more int
		var ferrs []*core.FieldError
		if feature, ferrs, more = withRequirements(feature, in.Designation); len(ferrs) > 0 {
			return nil, validation("", ferrs, more)
		}
		// withRequirements returns the whole collection; take its feature.
		feats, err := splitFeatures(feature)
		if err != nil || len(feats) != 1 {
			return nil, fmt.Errorf("the feature with its requirements block does not read back (%d features): %w", len(feats), err)
		}
		feature = feats[0]
	}
	cs, ferrs, more := checkDocument(wrapFeature(feature), ds, singleFeature)
	if len(cs) != 1 && len(ferrs) == 0 {
		ferrs = append(ferrs, core.Fieldf("feature", "must be one ED-318 feature"))
	}
	errs = append(errs, ferrs...)
	if len(errs) > 0 {
		return nil, validation("", errs, more)
	}
	c := cs[0]
	if in.Identifier != "" && c.identifier != in.Identifier {
		return nil, validation("", []*core.FieldError{core.Fieldf("feature.properties.identifier",
			"%q is not the path's identifier %q", c.identifier, in.Identifier)}, 0)
	}
	return &Draft{
		Dataset: ds, Identifier: c.identifier, Feature: c.feature, Columns: c.columns,
		ValidFrom: in.ValidFrom.UTC(), ValidTo: in.ValidTo.UTC(), Designation: in.Designation,
	}, nil
}

// splitFeatures is the features of an ED-318 collection as raw JSON.
func splitFeatures(doc []byte) ([]json.RawMessage, error) {
	var w struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(doc, &w); err != nil {
		return nil, err
	}
	return w.Features, nil
}

// How insertNext treats an identifier.
type insertMode int

const (
	modeCreate  insertMode = iota // a new identifier only
	modeReplace                   // an existing identifier only
	modeAny                       // either (an import)
)

// insertNext stores d as the identifier's next version inside tx: the
// identifier must not belong to the other dataset; modeCreate refuses
// an identifier that exists and modeReplace one that does not. The
// older unpublished versions are superseded.
func insertNext(ctx context.Context, tx Tx, d *Draft, mode insertMode, by string) (Version, *core.FieldError, error) {
	latest, err := tx.LatestForUpdate(ctx, d.Identifier)
	next := 1
	switch {
	case errors.Is(err, ErrNotFound):
		if mode == modeReplace {
			return Version{}, nil, notFound(d.Dataset, d.Identifier)
		}
	case err != nil:
		return Version{}, nil, err
	case latest.Dataset != d.Dataset:
		return Version{}, core.Fieldf("feature.properties.identifier", "%q is a %s; identifiers are unique across zones and U-space airspaces",
			d.Identifier, entityOf(latest.Dataset)), nil
	case mode == modeCreate:
		return Version{}, core.Fieldf("feature.properties.identifier", "%q exists (version %d); author a new version with PUT",
			d.Identifier, latest.ZoneVersion), nil
	default:
		next = latest.ZoneVersion + 1
	}
	if err := tx.SupersedeUnpublished(ctx, d.Identifier); err != nil {
		return Version{}, nil, err
	}
	v, err := tx.Insert(ctx, d, next, by)
	if errors.Is(err, ErrDuplicate) {
		return Version{}, core.Fieldf("feature.properties.identifier", "%q was written by another change meanwhile; retry", d.Identifier), nil
	}
	return v, nil, err
}

func draftedEvent(ds Dataset) string {
	if ds == DatasetUSpace {
		return audit.EventUSpaceDrafted
	}
	return audit.EventZoneDrafted
}

// Draft authors a version: a new identifier when create, else the next
// version of in.Identifier.
func (s *Service) Draft(ctx context.Context, ds Dataset, in DraftInput, create bool, actor audit.Actor) (Version, error) {
	d, err := prepare(ds, &in)
	if err != nil {
		return Version{}, s.refused(err)
	}
	var out Version
	err = s.Store.InTx(ctx, func(tx Tx) error {
		mode := modeReplace
		if create {
			mode = modeCreate
		}
		v, fe, err := insertNext(ctx, tx, d, mode, actor.ID)
		if err != nil {
			return err
		}
		if fe != nil {
			return conflict("the identifier cannot take this version", fe)
		}
		out = v
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: entityOf(ds), EntityID: v.Identifier, EventType: draftedEvent(ds),
			Payload: map[string]any{"zone_version": v.ZoneVersion, "type": v.Type, "valid_from": v.ValidFrom, "valid_to": v.ValidTo,
				"extensions": v.WGS84Fields},
		})
	})
	if err != nil {
		return Version{}, s.refused(err)
	}
	return out, nil
}

// ImportInput is one import as the API receives it.
type ImportInput struct {
	Body      []byte
	ValidFrom *time.Time
	ValidTo   *time.Time
	Lang      string
	// Source names where the file came from in the event ("file",
	// "airspace.gov.ge").
	Source string
}

// Import reads an ED-318 or ED-269 file and stores one draft per zone,
// all or nothing (LESSONS Z-02).
func (s *Service) Import(ctx context.Context, in ImportInput, actor audit.Actor) (Format, []Version, error) {
	im, errs, more := readImport(in.Body, in.Lang, DatasetZones)
	if len(errs) > 0 {
		return "", nil, s.refused(validation("the file was refused whole; nothing was imported", errs, more))
	}
	from, to := in.ValidFrom, in.ValidTo
	if from == nil {
		from = im.metaFrom
	}
	if to == nil {
		to = im.metaTo
	}
	if errs := checkPeriod("valid_from", "valid_to", from, to); len(errs) > 0 {
		return "", nil, s.refused(validation("the import names no period of validity", errs, 0))
	}
	var out []Version
	err := s.Store.InTx(ctx, func(tx Tx) error {
		var errs []*core.FieldError
		for i := range im.features {
			c := &im.features[i]
			d := &Draft{Dataset: DatasetZones, Identifier: c.identifier, Feature: c.feature, Columns: c.columns,
				ValidFrom: from.UTC(), ValidTo: to.UTC()}
			v, fe, err := insertNext(ctx, tx, d, modeAny, actor.ID)
			if err != nil {
				return err
			}
			if fe != nil {
				errs = append(errs, core.Fieldf(fmt.Sprintf("features[%d].properties.identifier", i), "%s", fe.Reason))
				continue
			}
			out = append(out, v)
		}
		if len(errs) > 0 {
			capped, more := capErrors(errs)
			return validation("the file was refused whole; nothing was imported", capped, more)
		}
		ids := make([]string, 0, len(out))
		for i := range out {
			ids = append(ids, fmt.Sprintf("%s@%d", out[i].Identifier, out[i].ZoneVersion))
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: entityZone, EntityID: "import", EventType: audit.EventZonesImported,
			Payload: map[string]any{"format": im.format, "source": in.Source, "zones": len(out), "versions": ids,
				"valid_from": from.UTC(), "valid_to": to.UTC()},
		})
	})
	if err != nil {
		return "", nil, s.refused(err)
	}
	return im.format, out, nil
}

func approvedEvent(ds Dataset) string {
	if ds == DatasetUSpace {
		return audit.EventUSpaceDesignated
	}
	return audit.EventZoneApproved
}

// Approve approves (designates, for a U-space airspace) the newest
// version of identifier, which must be zoneVersion and a draft.
func (s *Service) Approve(ctx context.Context, ds Dataset, identifier string, zoneVersion int, actor audit.Actor) (Version, error) {
	var out Version
	err := s.Store.InTx(ctx, func(tx Tx) error {
		latest, err := tx.LatestForUpdate(ctx, identifier)
		switch {
		case errors.Is(err, ErrNotFound) || err == nil && latest.Dataset != ds:
			return notFound(ds, identifier)
		case err != nil:
			return err
		case latest.ZoneVersion != zoneVersion:
			return conflict("only the newest version is approved", core.Fieldf("zone_version", "%d is not the newest version (%d)", zoneVersion, latest.ZoneVersion))
		case latest.State != StateDraft:
			return conflict("only a draft is approved", core.Fieldf("zone_version", "version %d is %s, not a draft", zoneVersion, latest.State))
		}
		if out, err = tx.Approve(ctx, identifier, zoneVersion, actor.ID); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: entityOf(ds), EntityID: identifier, EventType: approvedEvent(ds),
			Payload: map[string]any{"zone_version": zoneVersion},
		})
	})
	if err != nil {
		return Version{}, s.refused(err)
	}
	return out, nil
}

func publishedEvent(ds Dataset) string {
	if ds == DatasetUSpace {
		return audit.EventUSpacePublished
	}
	return audit.EventZonesPublished
}

func (s *Service) metadata(at time.Time) ed318.Metadata {
	m := ed318.Metadata{Issued: &ed318.DateTime{Time: at.UTC()}}
	if s.Meta.ProviderName != "" {
		name := s.Meta.ProviderName
		lang := s.Meta.ProviderLang
		if lang == "" {
			lang = DefaultLang
		}
		m.Provider = []ed318.Text{{Text: &name, Lang: lang}}
	}
	return m
}

func featuresOf(vs []Version) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(vs))
	for i := range vs {
		out = append(out, vs[i].Feature)
	}
	return out
}

// checkAdjacent refuses a U-space publication whose airspaces name an
// adjacent airspace that is not in it (cis/uspace_requirements/v1).
func checkAdjacent(set []Version) error {
	ids := make(map[string]bool, len(set))
	for i := range set {
		ids[set[i].Identifier] = true
	}
	for i := range set {
		adj, err := adjacentOf(set[i].Feature)
		if err != nil {
			return err
		}
		for k, a := range adj {
			if !ids[a] {
				return conflict("an adjacent U-space airspace is not in this publication",
					core.Fieldf(fmt.Sprintf("%s.designation.adjacent_ids[%d]", set[i].Identifier, k), "%q is not a U-space airspace in force", a))
			}
		}
	}
	return nil
}

// Publish publishes every approved version of ds (spec 02 F1): in one
// transaction under LockProjection, the versions become published under
// a new zones version and supersede their identifiers' older published
// versions; the full set in force now is exported into the outbox row
// (pending, unsigned until WP-6); the projection is rewritten in the
// telemetry database before the relational commit, so a failed
// projection write rolls the publication back (503
// projection_unavailable) and a failed relational commit after it is
// counted and repaired at once. Then the version is announced.
func (s *Service) Publish(ctx context.Context, ds Dataset, actor audit.Actor) (Published, error) {
	var out Published
	var projected bool
	err := s.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, LockProjection); err != nil {
			return err
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		version, err := tx.NextZonesVersion(ctx)
		if err != nil {
			return err
		}
		published, err := tx.PublishApproved(ctx, ds, version, actor.ID)
		if err != nil {
			return err
		}
		if len(published) == 0 {
			return httpx.Refuse(http.StatusConflict, SlugNothing, "no "+entityOf(ds)+" version is approved")
		}
		for i := range published {
			if err := tx.SupersedeOlderPublished(ctx, published[i].Identifier, published[i].ZoneVersion); err != nil {
				return err
			}
		}
		set, err := tx.InForce(ctx, ds, now)
		if err != nil {
			return err
		}
		if ds == DatasetUSpace {
			if err := checkAdjacent(set); err != nil {
				return err
			}
		}
		payload, n, err := buildExport(featuresOf(set), s.metadata(now), ExportAll, now, nil)
		if err != nil {
			return err
		}
		if len(payload) > MaxDocumentBytes {
			return httpx.Refuse(http.StatusConflict, SlugDatasetTooLarge,
				fmt.Sprintf("the %s dataset is %d bytes; a publication is at most %d (what the CISP's ED-318 parser accepts)", ds, len(payload), MaxDocumentBytes))
		}
		sum := sha256.Sum256(payload)
		pub, err := tx.EnqueuePublication(ctx, PublicationInput{
			Dataset: ds, Version: version, Payload: payload, PayloadHash: hex.EncodeToString(sum[:]), FeatureCount: n, By: actor.ID,
		})
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(published))
		for i := range published {
			ids = append(ids, fmt.Sprintf("%s@%d", published[i].Identifier, published[i].ZoneVersion))
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: entityOf(ds), EntityID: string(ds), EventType: publishedEvent(ds),
			Payload: map[string]any{"zones_version": version, "published": ids, "publication_id": pub.ID,
				"payload_hash": pub.PayloadHash, "feature_count": n},
		}); err != nil {
			return err
		}
		rows, err := tx.Projectable(ctx, now)
		if err != nil {
			return err
		}
		if err := s.writeProjection(ctx, rows, now, version); err != nil {
			s.count(CounterProjectionWriteFailed)
			logging.Error(ctx, s.logger(), "zones publication rolled back: the projection was not written", err,
				slog.Int64("zones_version", version))
			return projectionRefusal(err)
		}
		projected = true
		out = Published{Dataset: ds, ZonesVersion: version, Versions: published, Publication: pub}
		return nil
	})
	if err != nil {
		if projected {
			s.count(CounterProjectionAhead)
			logging.Error(ctx, s.logger(), "zones publication not committed after its projection was; re-projecting now", err,
				slog.Int64("zones_version", out.ZonesVersion))
			s.RequestRepair()
		}
		return Published{}, s.refused(err)
	}
	s.count(CounterPublished)
	s.announce(ctx, out.ZonesVersion)
	return out, nil
}

// writeProjection replaces the projection with rows.
func (s *Service) writeProjection(ctx context.Context, vs []Version, at time.Time, version int64) error {
	rows, err := projectedRows(vs)
	if err != nil {
		return err
	}
	deleted, err := s.Projection.Replace(ctx, rows, at, version)
	if err != nil {
		return err
	}
	if deleted > 0 && s.Counters != nil {
		s.Counters.Add(CounterProjectionDeleted, uint64(deleted))
	}
	return nil
}

func (s *Service) announce(ctx context.Context, version int64) {
	pub := s.Publisher
	if pub == nil {
		pub = NopPublisher{}
	}
	if err := pub.PublishZonesVersion(ctx, version); err != nil {
		s.count(CounterAnnounceFailed)
		logging.Error(ctx, s.logger(), "zones publication committed but not announced; readers apply it on their next re-read", err,
			slog.Int64("zones_version", version))
	}
}

// ExportInput selects an export.
type ExportInput struct {
	At        *time.Time
	AppliesAt *time.Time
}

// Export writes the geo-zones in force as an ED-318 collection (see
// ExportMode), recording the export.
func (s *Service) Export(ctx context.Context, in ExportInput, actor audit.Actor) ([]byte, error) {
	if in.At != nil && in.AppliesAt != nil {
		return nil, s.refused(httpx.Refuse(http.StatusBadRequest, SlugFilterConflict, "at filters and applies_at annotates; give one",
			core.Fieldf("applies_at", "cannot be combined with at")))
	}
	var out []byte
	err := s.Store.InTx(ctx, func(tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		instant, mode := now, ExportAll
		switch {
		case in.At != nil:
			instant, mode = *in.At, ExportFilter
		case in.AppliesAt != nil:
			instant, mode = *in.AppliesAt, ExportAnnotate
		}
		set, err := tx.InForce(ctx, DatasetZones, instant)
		if err != nil {
			return err
		}
		var n int
		if out, n, err = buildExport(featuresOf(set), s.metadata(now), mode, instant, s.daylight()); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: entityZone, EntityID: string(DatasetZones), EventType: audit.EventZonesExported,
			Payload: map[string]any{"at": in.At, "applies_at": in.AppliesAt, "instant": instant.UTC(), "features": n},
		})
	})
	if err != nil {
		return nil, s.refused(err)
	}
	s.count(CounterExported)
	return out, nil
}

// Get is the newest version of identifier in ds.
func (s *Service) Get(ctx context.Context, ds Dataset, identifier string) (Version, error) {
	v, err := s.Store.Latest(ctx, identifier)
	if errors.Is(err, ErrNotFound) || err == nil && v.Dataset != ds {
		return Version{}, notFound(ds, identifier)
	}
	return v, err
}

// List is one page of the newest version of each identifier of ds.
func (s *Service) List(ctx context.Context, f ListFilter) ([]Version, error) {
	if f.State != "" && !ValidState(f.State) {
		return nil, core.Fieldf("state", "must be draft, approved, published or superseded")
	}
	if f.Limit < 1 || f.Limit > MaxPageSize {
		f.Limit = 100
	}
	return s.Store.List(ctx, f)
}

// Versions is one page of identifier's history, newest first, below
// before (0: from the newest).
func (s *Service) Versions(ctx context.Context, ds Dataset, identifier string, before, limit int) ([]Version, error) {
	if _, err := s.Get(ctx, ds, identifier); err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxPageSize {
		limit = 100
	}
	if before < 1 {
		before = 1 << 30
	}
	return s.Store.Versions(ctx, identifier, before, limit)
}

// ApplicabilityAnswer says whether a version of a geo-zone applies at
// an instant.
type ApplicabilityAnswer struct {
	Identifier  string
	ZoneVersion int
	At          time.Time
	Answer      Applicability
	Reason      string
}

// Applies answers whether the newest version of identifier (or
// zoneVersion when not 0) applies at at, through ed318.Applies. A
// question that needs a daylight event while none can be resolved is
// refused 503 daylight_unavailable, never guessed.
func (s *Service) Applies(ctx context.Context, identifier string, zoneVersion int, at time.Time) (ApplicabilityAnswer, error) {
	v, err := s.Get(ctx, DatasetZones, identifier)
	if err != nil {
		return ApplicabilityAnswer{}, err
	}
	if zoneVersion > 0 && zoneVersion != v.ZoneVersion {
		if v, err = s.Store.Version(ctx, identifier, zoneVersion); errors.Is(err, ErrNotFound) {
			return ApplicabilityAnswer{}, httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such version",
				core.Fieldf("zone_version", "%s has no version %d", identifier, zoneVersion))
		} else if err != nil {
			return ApplicabilityAnswer{}, err
		}
	}
	fc, err := collect([]json.RawMessage{v.Feature})
	if err != nil {
		return ApplicabilityAnswer{}, err
	}
	a, err := applicabilityOf(&fc.Features[0], at, s.daylight())
	out := ApplicabilityAnswer{Identifier: v.Identifier, ZoneVersion: v.ZoneVersion, At: at, Answer: a}
	if err != nil {
		if errors.Is(err, ErrDaylightUnavailable) {
			s.count(CounterDaylightUnavailable)
			return ApplicabilityAnswer{}, httpx.Refuse(http.StatusServiceUnavailable, SlugDaylight,
				"this zone's schedule uses daylight events and no sunrise and sunset source is available; the answer is not guessed",
				core.Fieldf("feature.properties.limitedApplicability", "%v", err))
		}
		out.Reason = err.Error()
	}
	return out, nil
}
