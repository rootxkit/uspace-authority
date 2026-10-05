package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// The ANSP's degraded direct delivery (spec 02 F2 failure rule,
// cross-plan M4, M5): while the CISP does not hold a restriction's
// version, the ANSP posts the cis/change/v1 record, signed with its own
// key, to /v1/cis/notifications. The record's version member is the
// restriction's ansp_version, not a CIS dataset version, and its
// pull_url is the ANSP's GET /v1/restrictions/{id}/direct, which serves
// the version as restriction/direct/v1 signed with the ANSP's key in
// X-JWS-Signature. The subscriber pulls it, verifies it with the ANSP's
// publisher keys (CIS_ANSP_PUBLISHER_JWKS_URL), and lays it over the
// CISP's restrictions version in proj_restrictions until the CISP holds
// that version or a newer one. The overlay is stored
// (cis_direct_restrictions), so a restart keeps it.

// DirectSchema names the body of the ANSP's GET
// /v1/restrictions/{id}/direct.
const DirectSchema = "restriction/direct/v1"

// HeaderDirectSignature carries the ANSP's detached JWS over that body.
const HeaderDirectSignature = "X-JWS-Signature"

// Bounds and defaults of the direct path (E-10).
const (
	// MaxDirectBytes bounds the pulled body: one restriction and its
	// feature.
	MaxDirectBytes = 256 << 10
	// DefaultDirectMax bounds the restrictions held from the direct
	// path, and the pulls waiting (CIS_DIRECT_MAX).
	DefaultDirectMax = 500
	// DefaultDirectKeep is how long a direct restriction that is over
	// (ended, cancelled, or past its ends_at) is kept, and how long a
	// pull is retried (CIS_DIRECT_KEEP_S; pending GCAA: the spec names
	// no figure, 24 h is spec 02 F3's notification retry window).
	DefaultDirectKeep = 24 * time.Hour
	// DefaultDirectTimeout bounds one pull.
	DefaultDirectTimeout = 10 * time.Second
	// directRetryEvery is how often failed pulls are tried again and
	// the overlay is pruned.
	directRetryEvery = 10 * time.Second
)

// Counters of the direct path.
const (
	CounterDirectQueued     = "cis_direct_queued"
	CounterDirectFull       = "cis_direct_full"
	CounterDirectPulls      = "cis_direct_pulls"
	CounterDirectPullFailed = "cis_direct_pull_failed"
	CounterDirectRefused    = "cis_direct_refused"
	CounterDirectApplied    = "cis_direct_applied"
	CounterDirectReplays    = "cis_direct_replays"
	CounterDirectSuperseded = "cis_direct_superseded_by_cisp"
	CounterDirectExpired    = "cis_direct_expired"
	CounterDirectStoreFail  = "cis_direct_store_failed"
)

// DirectHint is what a verified ANSP notification says: the restriction
// (the JWS sub), its ansp_version (the record's version member), the
// identifiers it names, and the pull_url the receiver's guard accepted.
type DirectHint struct {
	RestrictionID string
	AnspVersion   int64
	FeatureIDs    []string
	PullURL       string
	Issuer        string
	Reason        string
	At            time.Time

	attempts int
	lastErr  string
}

// DirectRestriction is restriction/direct/v1 (uspace-ansp
// api/openapi.yaml DirectRestriction): the version member is
// ansp_version (M4).
type DirectRestriction struct {
	Schema           string          `json:"schema"`
	ID               string          `json:"id"`
	AnspRef          string          `json:"ansp_ref"`
	AnspVersion      int64           `json:"ansp_version"`
	Identifier       string          `json:"identifier"`
	UspaceAirspaceID string          `json:"uspace_airspace_id"`
	State            string          `json:"state"`
	StartsAt         time.Time       `json:"starts_at"`
	EndsAt           time.Time       `json:"ends_at"`
	ChangedAt        time.Time       `json:"changed_at"`
	Feature          json.RawMessage `json:"feature"`
}

// DirectStored is one row of cis_direct_restrictions.
type DirectStored struct {
	Identifier    string
	RestrictionID string
	AnspRef       string
	AnspVersion   int64
	State         string
	Body          []byte
	Signature     string
	Issuer        string
	// AgeS is the time since it was stored, on the database clock (read
	// back only).
	AgeS float64
}

// DirectStore keeps the direct restrictions across a restart.
type DirectStore interface {
	// SaveDirect stores d unless a version at or above it is stored for
	// its identifier; stored says whether it was written.
	SaveDirect(ctx context.Context, d DirectStored) (stored bool, err error)
	// LoadDirect returns at most maxRows stored rows.
	LoadDirect(ctx context.Context, maxRows int) ([]DirectStored, error)
	// DeleteDirect deletes identifier's row when its version is at or
	// below anspVersion.
	DeleteDirect(ctx context.Context, identifier string, anspVersion int64) error
}

// DirectConfig configures the direct path of a Subscriber.
type DirectConfig struct {
	// Client pulls the ANSP's pull_url: no credential (the route is
	// public; the signature is what is trusted), never the CISP's
	// client. Nil is a client bounded by DefaultDirectTimeout.
	Client *http.Client
	Store  DirectStore
	// Max is CIS_DIRECT_MAX; Keep CIS_DIRECT_KEEP_S.
	Max  int
	Keep time.Duration
}

// directHeld is a direct restriction laid over the CISP's version.
type directHeld struct {
	d      DirectRestriction
	body   []byte
	sig    string
	issuer string
	// since is when it arrived, on this process's clock.
	since time.Time
	row   RestrictionRow
}

func (s *Subscriber) directMax() int {
	if s.cfg.Direct.Max > 0 {
		return s.cfg.Direct.Max
	}
	return DefaultDirectMax
}

func (s *Subscriber) directKeep() time.Duration {
	if s.cfg.Direct.Keep > 0 {
		return s.cfg.Direct.Keep
	}
	return DefaultDirectKeep
}

// TriggerDirect queues the pull of a direct notification; it never
// blocks. The newest version of a restriction wins. It returns false,
// counted, when DirectMax pulls are already waiting: the receiver then
// answers 503 and the ANSP retries.
func (s *Subscriber) TriggerDirect(h DirectHint) bool {
	s.mu.Lock()
	p := s.directPending[h.RestrictionID]
	switch {
	case p != nil && h.AnspVersion <= p.AnspVersion:
	case p == nil && len(s.directPending) >= s.directMax():
		s.mu.Unlock()
		s.cfg.Counters.Inc(CounterDirectFull)
		return false
	default:
		hc := h
		s.directPending[h.RestrictionID] = &hc
	}
	s.mu.Unlock()
	s.cfg.Counters.Inc(CounterDirectQueued)
	select {
	case s.directKick <- struct{}{}:
	default:
	}
	return true
}

// directWorker pulls the queued direct notifications, retries the ones
// that failed and prunes the overlay, until ctx ends.
func (s *Subscriber) directWorker(ctx context.Context) {
	t := time.NewTicker(directRetryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.directKick:
		case <-t.C:
			s.pruneDirect(ctx)
		}
		s.drainDirect(ctx)
	}
}

// drainDirect tries every pending pull once.
func (s *Subscriber) drainDirect(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.directPending))
	for id := range s.directPending {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		p := s.directPending[id]
		var h DirectHint
		if p != nil {
			h = *p
		}
		s.mu.Unlock()
		if p == nil {
			continue
		}
		err := s.ApplyDirect(ctx, h)
		s.mu.Lock()
		cur := s.directPending[id]
		switch {
		case cur == nil || cur.AnspVersion > h.AnspVersion:
			// A newer notification came meanwhile: it is pulled next.
		case err == nil || errors.Is(err, errDirectPermanent):
			delete(s.directPending, id)
		case s.cfg.Now().Sub(h.At) > s.directKeep():
			delete(s.directPending, id)
			s.cfg.Counters.Inc(CounterDirectExpired)
			s.cfg.Logger.Error("a direct restriction could not be pulled within the keep period; given up",
				slog.String("restriction_id", id), slog.Int64("ansp_version", h.AnspVersion), slog.String("error", short(err.Error())))
		default:
			cur.attempts++
			cur.lastErr = short(err.Error())
		}
		s.mu.Unlock()
	}
}

// errDirectPermanent marks a pull that no retry changes (a 404, a body
// that is not the version named): counted, logged, dropped.
var errDirectPermanent = errors.New("permanent")

// ApplyDirect pulls h's pull_url, verifies the ANSP's signature over
// the body, checks it is the restriction and version h names, stores it
// and lays it over the CISP's restrictions version in the projection.
// A version at or below the one held for the restriction, from either
// path, is a replay (counted, nothing pulled). The pull runs without the
// restrictions lock (a CISP pull is not held behind the ANSP's answer);
// the checks run again under it before anything is stored.
func (s *Subscriber) ApplyDirect(ctx context.Context, h DirectHint) error {
	log := s.cfg.Logger.With(slog.String("restriction_id", h.RestrictionID), slog.Int64("ansp_version", h.AnspVersion),
		slog.String("issuer", h.Issuer))
	if held := s.heldAnspVersion(h.FeatureIDs); held >= h.AnspVersion {
		s.cfg.Counters.Inc(CounterDirectReplays)
		log.Info("direct restriction at or below the version held; nothing pulled", slog.Int64("held", held))
		return nil
	}
	s.cfg.Counters.Inc(CounterDirectPulls)
	body, sig, err := s.pullDirect(ctx, h.PullURL)
	if err != nil {
		s.cfg.Counters.Inc(CounterDirectPullFailed)
		log.Warn("direct restriction not pulled; retried", slog.String("error", short(err.Error())))
		return err
	}
	if s.cfg.Publishers == nil {
		s.cfg.Counters.Inc(CounterDirectRefused)
		log.Error("direct restriction not applied: no publisher keys are configured")
		return errors.New("no publisher keys are configured")
	}
	if _, err := s.cfg.Publishers.Verify(ctx, PublisherANSP, sig, body); err != nil {
		// Keys not fetched yet and a signature that does not verify read
		// alike: retried until the keep period ends.
		s.cfg.Counters.Inc(CounterDirectRefused)
		log.Error("direct restriction not applied: the ANSP's signature does not verify", slog.String("error", short(err.Error())))
		return err
	}
	held, err := s.buildDirect(h, body, sig)
	if err != nil {
		s.cfg.Counters.Inc(CounterDirectRefused)
		log.Error("direct restriction refused", slog.String("error", short(err.Error())))
		return fmt.Errorf("%w: %w", errDirectPermanent, err)
	}
	d := held.d
	lock := s.locks[DatasetRestrictions]
	lock.Lock()
	defer lock.Unlock()
	if prev := s.heldAnspVersion([]string{d.Identifier}); prev >= d.AnspVersion && s.baseAnspVersion(d.Identifier) < prev {
		s.cfg.Counters.Inc(CounterDirectReplays)
		log.Info("a direct restriction at or above this version was applied meanwhile", slog.Int64("held", prev))
		return nil
	}
	if base := s.baseAnspVersion(d.Identifier); base >= d.AnspVersion {
		s.cfg.Counters.Inc(CounterDirectSuperseded)
		log.Info("the CISP holds this restriction version or a newer one; the direct one is not applied")
		return nil
	}
	if ds := s.cfg.Direct.Store; ds != nil {
		if _, err := ds.SaveDirect(ctx, DirectStored{Identifier: d.Identifier, RestrictionID: d.ID, AnspRef: d.AnspRef,
			AnspVersion: d.AnspVersion, State: d.State, Body: body, Signature: sig, Issuer: h.Issuer}); err != nil {
			// Applied anyway: the restriction is in force now; a restart
			// before the CISP holds it loses it, which is said.
			s.cfg.Counters.Inc(CounterDirectStoreFail)
			log.Error("direct restriction not stored; applied from memory, lost at a restart until the CISP holds it",
				slog.String("error", short(err.Error())))
		}
	}
	s.mu.Lock()
	s.direct[d.Identifier] = held
	s.mu.Unlock()
	s.cfg.Counters.Inc(CounterDirectApplied)
	log.Info("direct restriction applied over the CISP's version", slog.String("identifier", d.Identifier),
		slog.String("state", d.State), slog.String("reason", h.Reason))
	s.reproject(ctx)
	return nil
}

// pullDirect reads raw (no credential), bounded.
func (s *Subscriber) pullDirect(ctx context.Context, raw string) ([]byte, string, error) {
	client := s.cfg.Direct.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultDirectTimeout}
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultDirectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the pull_url is not a request: %w", errDirectPermanent, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDirectBytes+1))
	if err != nil {
		return nil, "", err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, "", fmt.Errorf("%w: the ANSP answered 404", errDirectPermanent)
	case resp.StatusCode != http.StatusOK:
		return nil, "", fmt.Errorf("the ANSP answered %d", resp.StatusCode)
	case len(body) > MaxDirectBytes:
		return nil, "", fmt.Errorf("%w: the body is longer than %d bytes", errDirectPermanent, MaxDirectBytes)
	}
	sig := resp.Header.Get(HeaderDirectSignature)
	if sig == "" {
		return nil, "", fmt.Errorf("no %s", HeaderDirectSignature)
	}
	return body, sig, nil
}

// buildDirect reads a verified body and checks it is what h names: the
// restriction (sub), an identifier the record listed, a version at least
// the record's, a known state, and a feature that parses as ED-318
// under the same identifier.
func (s *Subscriber) buildDirect(h DirectHint, body []byte, sig string) (*directHeld, error) {
	d, err := parseDirect(body)
	if err != nil {
		return nil, err
	}
	switch {
	case d.ID != h.RestrictionID:
		return nil, fmt.Errorf("the body is restriction %q, the notification names %q", short(d.ID), short(h.RestrictionID))
	case !slices.Contains(h.FeatureIDs, d.Identifier):
		return nil, fmt.Errorf("identifier %q is not among the notification's feature_ids", short(d.Identifier))
	case d.AnspVersion < h.AnspVersion:
		return nil, fmt.Errorf("ansp_version %d is below the notification's %d", d.AnspVersion, h.AnspVersion)
	}
	row, err := directRow(d)
	if err != nil {
		return nil, err
	}
	return &directHeld{d: d, body: body, sig: sig, issuer: h.Issuer, since: s.cfg.Now(), row: row}, nil
}

// parseDirect reads restriction/direct/v1. Members it does not know are
// ignored (additive within v1); the ones it needs are checked.
func parseDirect(body []byte) (DirectRestriction, error) {
	var d DirectRestriction
	if err := json.Unmarshal(body, &d); err != nil {
		return d, fmt.Errorf("not a %s body", DirectSchema)
	}
	switch {
	case d.Schema != DirectSchema:
		return d, fmt.Errorf("schema %q, want %s", short(d.Schema), DirectSchema)
	case d.ID == "" || d.AnspRef == "" || d.Identifier == "" || d.AnspVersion < 1 || len(d.Feature) == 0:
		return d, errors.New("id, ansp_ref, identifier, ansp_version or feature is missing")
	case !restrictionStates[d.State]:
		return d, fmt.Errorf("state %q is not a restriction state", short(d.State))
	}
	return d, nil
}

// directRow is the projection row of d: its feature as the ANSP signed
// it (ed318.Parse must read it, as the detectors do), its state and
// window.
func directRow(d DirectRestriction) (RestrictionRow, error) {
	doc := make([]byte, 0, len(d.Feature)+48)
	doc = append(doc, `{"type":"FeatureCollection","features":[`...)
	doc = append(doc, d.Feature...)
	doc = append(doc, "]}"...)
	fc, probs := ed318.Parse(doc, ed318.Limits{})
	if probs != nil {
		return RestrictionRow{}, fmt.Errorf("the feature does not parse: %s", short(probs.Error()))
	}
	if len(fc.Features) != 1 || fc.Features[0].Properties.Identifier != d.Identifier {
		return RestrictionRow{}, fmt.Errorf("the feature is not restriction %q", short(d.Identifier))
	}
	return RestrictionRow{Identifier: d.Identifier, Feature: d.Feature, State: d.State, StartsAt: d.StartsAt, EndsAt: d.EndsAt,
		ANSPRef: d.AnspRef, USpaceAirspaceID: d.UspaceAirspaceID}, nil
}

// baseRestriction is the CISP's block of id in the restrictions version
// held, or nil.
func (s *Subscriber) baseRestriction(id string) *cispclient.CisRestriction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.st[DatasetRestrictions].cur; cur != nil {
		for i := range cur.Features {
			if f := &cur.Features[i]; f.Identifier == id {
				return f.Restriction
			}
		}
	}
	return nil
}

// baseAnspVersion is the ansp_version of id in the CISP's restrictions
// version held (0 when absent).
func (s *Subscriber) baseAnspVersion(id string) int64 {
	if r := s.baseRestriction(id); r != nil {
		return r.AnspVersion
	}
	return 0
}

// heldAnspVersion is the highest ansp_version held for any of ids, from
// the CISP's version or the direct path (0 when none).
func (s *Subscriber) heldAnspVersion(ids []string) int64 {
	var best int64
	for _, id := range ids {
		best = max(best, s.baseAnspVersion(id))
		s.mu.Lock()
		if h := s.direct[id]; h != nil {
			best = max(best, h.d.AnspVersion)
		}
		s.mu.Unlock()
	}
	return best
}

// mergedRows are the projection rows of the CISP's restrictions version
// v (nil: none) with the direct restrictions laid over them: a direct
// restriction replaces the CISP's row of the same identifier while its
// ansp_version is higher, and is added when the CISP has none.
func (s *Subscriber) mergedRows(v *Version) []RestrictionRow {
	var base []RestrictionRow
	versions := map[string]int64{}
	if v != nil {
		base = RestrictionRows(v)
		for i := range v.Features {
			if r := v.Features[i].Restriction; r != nil {
				versions[v.Features[i].Identifier] = r.AnspVersion
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RestrictionRow, 0, len(base)+len(s.direct))
	seen := map[string]bool{}
	for i := range base {
		id := base[i].Identifier
		if h := s.direct[id]; h != nil && versions[id] < h.d.AnspVersion {
			continue
		}
		seen[id] = true
		out = append(out, base[i])
	}
	ids := make([]string, 0, len(s.direct))
	for id := range s.direct {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, s.direct[id].row)
	}
	return out
}

// reproject writes the projection again after the direct overlay
// changed and announces it, so the detectors re-read it at once (Z-12).
// The CISP's version, and its age, are unchanged. The caller holds the
// restrictions lock.
func (s *Subscriber) reproject(ctx context.Context) {
	s.mu.Lock()
	st := s.st[DatasetRestrictions]
	cur, kid, fetched, checked := st.cur, st.kid, st.fetchedAt, st.checkedAt
	s.mu.Unlock()
	s.project(ctx, cur)
	c := &Cached{Dataset: DatasetRestrictions, ETag: ETagOf(DatasetRestrictions, 0), FetchedAt: fetched, CheckedAt: checked, PublisherKID: kid}
	if cur != nil {
		c.Version, c.ETag, c.UpdatedAt, c.FeatureCount = cur.Number, cur.ETag, cur.UpdatedAt, cur.FeatureCount()
	}
	s.announce(ctx, c)
}

// pruneDirect drops the direct restrictions the CISP now holds at the
// same version or a newer one, and the ones over for longer than the
// keep period, and projects again when it dropped any.
func (s *Subscriber) pruneDirect(ctx context.Context) {
	lock := s.locks[DatasetRestrictions]
	lock.Lock()
	defer lock.Unlock()
	if s.dropDirect(ctx) {
		s.reproject(ctx)
	}
}

// dropDirect is pruneDirect's drop (deleting the rows from the store);
// true when it dropped any. The caller holds the restrictions lock.
func (s *Subscriber) dropDirect(ctx context.Context) bool {
	now := s.cfg.Now()
	keep := s.directKeep()
	type gone struct {
		id      string
		version int64
		why     string
	}
	s.mu.Lock()
	ids := make([]string, 0, len(s.direct))
	for id := range s.direct {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	var drop []gone
	for _, id := range ids {
		base := s.baseAnspVersion(id)
		s.mu.Lock()
		h := s.direct[id]
		s.mu.Unlock()
		if h == nil {
			continue
		}
		over := h.d.State == "ended" || h.d.State == "cancelled"
		switch {
		case base >= h.d.AnspVersion:
			drop = append(drop, gone{id, h.d.AnspVersion, "superseded"})
		case over && now.Sub(h.since) > keep:
			drop = append(drop, gone{id, h.d.AnspVersion, "kept long enough after its end"})
		case !over && !h.d.EndsAt.IsZero() && now.Sub(h.d.EndsAt) > keep:
			drop = append(drop, gone{id, h.d.AnspVersion, "kept long enough after its ends_at"})
		}
	}
	s.mu.Lock()
	for _, g := range drop {
		delete(s.direct, g.id)
	}
	s.mu.Unlock()
	for _, g := range drop {
		if g.why == "superseded" {
			s.cfg.Counters.Inc(CounterDirectSuperseded)
		} else {
			s.cfg.Counters.Inc(CounterDirectExpired)
		}
		s.cfg.Logger.Info("direct restriction dropped: "+g.why, slog.String("identifier", g.id), slog.Int64("ansp_version", g.version))
		if ds := s.cfg.Direct.Store; ds != nil {
			if err := ds.DeleteDirect(ctx, g.id, g.version); err != nil {
				s.cfg.Counters.Inc(CounterDirectStoreFail)
				s.cfg.Logger.Warn("dropped direct restriction not deleted from the store; it is dropped again at the next start",
					slog.String("identifier", g.id), slog.String("error", short(err.Error())))
			}
		}
	}
	return len(drop) > 0
}

// warmDirect loads the stored direct restrictions (Warm): each is built
// again from its stored body, which was verified when it arrived.
func (s *Subscriber) warmDirect(ctx context.Context) {
	ds := s.cfg.Direct.Store
	if ds == nil {
		return
	}
	rows, err := ds.LoadDirect(ctx, s.directMax())
	if err != nil {
		s.cfg.Counters.Inc(CounterDirectStoreFail)
		s.cfg.Logger.Error("the direct restrictions could not be read from the database", slog.String("error", short(err.Error())))
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range rows {
		r := &rows[i]
		d, err := parseDirect(r.Body)
		var row RestrictionRow
		if err == nil {
			row, err = directRow(d)
		}
		if err != nil {
			s.cfg.Logger.Error("a stored direct restriction no longer builds", slog.String("identifier", r.Identifier),
				slog.String("error", short(err.Error())))
			continue
		}
		age := time.Duration(max(0, r.AgeS) * float64(time.Second))
		s.direct[d.Identifier] = &directHeld{d: d, body: r.Body, sig: r.Signature, issuer: r.Issuer, since: now.Add(-age), row: row}
	}
}

// DirectState is one restriction of the direct path for the console and
// the status line: pending (notified, not applied yet) or applied (in
// the projection, the CISP not holding it yet).
type DirectState struct {
	Identifier    string
	RestrictionID string
	AnspVersion   int64
	State         string
	Pending       bool
	LastError     string
}

// Direct is the direct path's restrictions, pending ones first.
func (s *Subscriber) Direct() []DirectState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DirectState, 0, len(s.directPending)+len(s.direct))
	for id, p := range s.directPending {
		out = append(out, DirectState{RestrictionID: id, AnspVersion: p.AnspVersion, Pending: true, LastError: p.lastErr})
	}
	for id, h := range s.direct {
		out = append(out, DirectState{Identifier: id, RestrictionID: h.d.ID, AnspVersion: h.d.AnspVersion, State: h.d.State})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pending != out[j].Pending {
			return out[i].Pending
		}
		return out[i].RestrictionID < out[j].RestrictionID
	})
	return out
}

// SaveDirect implements DirectStore (cis_direct_restrictions, migration
// 00026).
func (s PG) SaveDirect(ctx context.Context, d DirectStored) (bool, error) {
	n, err := s.DB.Queries().UpsertCISDirect(ctx, gen.UpsertCISDirectParams{
		Identifier: d.Identifier, RestrictionID: d.RestrictionID, AnspRef: d.AnspRef, AnspVersion: d.AnspVersion,
		State: d.State, Body: d.Body, Signature: d.Signature, Issuer: d.Issuer,
	})
	return n == 1, err
}

// LoadDirect implements DirectStore.
func (s PG) LoadDirect(ctx context.Context, maxRows int) ([]DirectStored, error) {
	rows, err := s.DB.Queries().LoadCISDirect(ctx, int32(min(maxRows, 1<<30)))
	if err != nil {
		return nil, err
	}
	out := make([]DirectStored, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, DirectStored{Identifier: r.Identifier, RestrictionID: r.RestrictionID, AnspRef: r.AnspRef,
			AnspVersion: r.AnspVersion, State: r.State, Body: r.Body, Signature: r.Signature, Issuer: r.Issuer, AgeS: r.AgeS})
	}
	return out, nil
}

// DeleteDirect implements DirectStore.
func (s PG) DeleteDirect(ctx context.Context, identifier string, anspVersion int64) error {
	_, err := s.DB.Queries().DeleteCISDirect(ctx, gen.DeleteCISDirectParams{Identifier: identifier, AnspVersion: anspVersion})
	return err
}

var _ DirectStore = PG{}
