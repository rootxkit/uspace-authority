package detectsvc

import (
	"context"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// naCase is one aircraft inside one U-space airspace, judged for
// no_authorisation (WP-26; spec 04 §3.3, Art. 6(4)).
type naCase struct {
	// presence is the monitor's key of the aircraft's presence in the
	// airspace (zone:<country>:<identifier>:<aircraft>), key the
	// violation's (no_authorisation:<country>:<identifier>:<aircraft>).
	presence, key, aircraft string
	ref                     zoneRef
	// unmatchedSinceS is when the outcomes started saying no intent
	// matches (wall clock), unmatchedAtS the captured_at of the first of
	// them; matchedSinceS when an open violation's aircraft started
	// matching. Zero when not running.
	unmatchedSinceS, unmatchedAtS, matchedSinceS float64
	// last is the outcome of the last tick, nil when none stood (the DSS
	// unavailable, the aircraft not checked yet): the case is suspended.
	last *intents.Outcome
	ov   *open
}

// noAuthKey is the violation key of a presence key.
func noAuthKey(presence string) string {
	return string(violation.KindNoAuthorisation) + ":" + strings.TrimPrefix(presence, alerting.KindZone+":")
}

// openCase starts the case of an aircraft's presence in a U-space
// airspace, if it is not already held.
func (w *Worker) openCase(presence, id string, ref zoneRef) {
	if _, ok := w.noAuth[presence]; ok {
		return
	}
	w.noAuth[presence] = &naCase{presence: presence, key: noAuthKey(presence), aircraft: id, ref: ref}
	if w.in.Authorisations() == nil {
		w.Counters.Inc(CounterNoAuthNotJudged)
		w.errorf("detect_no_authorisation_not_judged", "an aircraft is inside a U-space airspace and this detector has no DSS: no_authorisation is not judged",
			slog.String("drone_id", id), slog.String("zone_id", ref.country+"/"+ref.id))
	}
}

// closeCase ends the case of presence: its open violation, if any,
// clears with reason (the presence's own, or reconfigured), and the
// board forgets an aircraft no longer in any U-space airspace.
func (w *Worker) closeCase(presence, reason string, atS float64) {
	c, ok := w.noAuth[presence]
	if !ok {
		return
	}
	delete(w.noAuth, presence)
	if c.ov != nil {
		var clearing map[string]any
		if reason == string(alerting.ClearResolved) {
			clearing = map[string]any{"left_uspace": true}
		}
		w.closeViolation(c.ov, reason, atS, c.ov.body.Detail, clearing)
	}
	if b := w.in.Authorisations(); b != nil && len(w.uspace[c.aircraft]) == 0 {
		b.Forget(c.aircraft)
	}
}

// afterRebuildNoAuth closes the cases whose presence the rebuilt monitor
// no longer raises: stale when the aircraft's samples are gone, else
// reconfigured (the airspace withdrawn), as the other violations.
func (w *Worker) afterRebuildNoAuth(wallS float64) {
	for _, k := range slices.Sorted(maps.Keys(w.noAuth)) {
		c := w.noAuth[k]
		if _, still := w.uspace[c.aircraft][k]; still {
			continue
		}
		reason := violation.ClearReasonReconfigured
		if _, held := w.excerpts.LastOf(c.aircraft); !held {
			reason = string(alerting.ClearStale)
		}
		if c.ov != nil && reason == violation.ClearReasonReconfigured {
			w.Counters.Inc(CounterClearedReconfigured)
		}
		w.closeCase(k, reason, wallS)
	}
}

// wantIntents asks the board for the intents at a live sample of an
// aircraft inside U-space airspace. The height asked is the track's
// height above the ellipsoid (alt_wgs84_m) from a geodetic or network
// source; with none the position is asked without one (vertical not
// checked: the 120 m rule is then never lifted).
func (w *Worker) wantIntents(m *track.Message, at time.Time) {
	b := w.in.Authorisations()
	id := m.Body.TrackID
	keys := w.uspace[id]
	if b == nil || len(keys) == 0 {
		return
	}
	first := slices.Min(slices.Collect(maps.Keys(keys)))
	c := w.noAuth[first]
	if c == nil || c.ref.zone == nil {
		return
	}
	var hae *float64
	if a := m.Body.AltWGS84M; a != nil && core.IsFinite(*a) && (m.Body.AltSource == core.AltGeodetic || m.Body.AltSource == core.AltNetwork) {
		v := *a
		hae = &v
	}
	b.Want(intents.Query{TrackID: id, ZoneKey: intents.ZoneKeyOf(c.ref.zone.Country, c.ref.zone.Identifier),
		Pos: core.LatLon{LatDeg: m.Body.Position.Lat, LonDeg: m.Body.Position.Lng}, AltHAEM: hae, At: at})
}

// noAuthDetail is a no_authorisation's detail: the airspace, the grace,
// the DSS's state, what the last outcome considered and why each intent
// failed, and what it says of identity (IdentityNotExposed).
func (w *Worker) noAuthDetail(c *naCase, b *intents.Board) map[string]any {
	d := map[string]any{
		"zone_id": c.ref.country + "/" + c.ref.id, "grace_s": w.thresholds.NoAuthorisationGraceS, "identity": intents.IdentityNotExposed,
	}
	if b != nil {
		st, _ := b.State()
		d["dss_state"] = string(st)
	}
	if c.unmatchedAtS > 0 {
		d["unmatched_since"] = stampS(c.unmatchedAtS)
	}
	if c.last != nil {
		d["vertical_checked"] = c.last.VerticalChecked
		d["candidates"] = slices.Clone(c.last.Candidates)
		d["candidates_truncated"] = c.last.Truncated
		d["checked_at"] = stampS(seconds(c.last.CheckedAt))
	} else {
		d["candidates"] = []intents.Candidate{}
		d["suspended"] = true
	}
	return d
}

// judgeNoAuth runs every tick over the cases: with no outcome standing
// the case is suspended (its grace restarts, nothing is raised or
// cleared on a match: E-02, never "clear" because the DSS is away); an
// unmatched outcome for longer than the policy's grace raises
// no_authorisation; a match for longer than clear_after_s clears it
// resolved (hysteresis). Leaving the airspace clears it with the
// presence (noteUSpaceCleared).
func (w *Worker) judgeNoAuth(wallS float64) {
	b := w.in.Authorisations()
	if b == nil || len(w.noAuth) == 0 {
		return
	}
	grace, clearAfter := w.thresholds.NoAuthorisationGraceS, w.thresholds.ClearAfterS
	for _, k := range slices.Sorted(maps.Keys(w.noAuth)) {
		c := w.noAuth[k]
		o, ok := b.Outcome(c.aircraft)
		switch {
		case !ok:
			c.last, c.unmatchedSinceS, c.unmatchedAtS, c.matchedSinceS = nil, 0, 0, 0
		case o.Matched:
			c.last, c.unmatchedSinceS, c.unmatchedAtS = &o, 0, 0
			if c.ov == nil {
				continue
			}
			if c.matchedSinceS == 0 {
				c.matchedSinceS = wallS
			}
			if wallS-c.matchedSinceS >= clearAfter {
				clearing := map[string]any{"matched_intent": *o.Match, "off_nominal": o.OffNominal, "identity": intents.IdentityNotExposed}
				w.closeViolation(c.ov, string(alerting.ClearResolved), seconds(o.At), w.noAuthDetail(c, b), clearing)
				c.ov, c.matchedSinceS = nil, 0
			}
		default:
			c.last, c.matchedSinceS = &o, 0
			if c.unmatchedSinceS == 0 {
				c.unmatchedSinceS, c.unmatchedAtS = wallS, seconds(o.At)
			}
			if c.ov == nil && wallS-c.unmatchedSinceS >= grace {
				w.raiseNoAuth(c, b, seconds(o.At))
			}
		}
	}
}

// raiseNoAuth publishes the raise of c at the captured_at of its last
// outcome.
func (w *Worker) raiseNoAuth(c *naCase, b *intents.Board, atS float64) {
	sev := w.thresholds.NoAuthorisationSeverity
	if sev == "" {
		sev = policy.DefaultNoAuthorisationSeverity
	}
	body := w.bodyFor(violation.KindNoAuthorisation, c.key, c.aircraft, c.ref, sev, w.noAuthDetail(c, b), c.unmatchedAtS, atS)
	c.ov = &open{body: body, excerptUpToS: atS - w.set.ExcerptWindowS}
	w.enqueue(c.ov, violation.StateRaised, atS)
	w.Counters.Inc(CounterRaised)
}

// republishNoAuth republishes every open no_authorisation with its
// current detail and the samples since (C-08), within ctx, after the
// other violations and only while the outbox is empty.
func (w *Worker) republishNoAuth(ctx context.Context) {
	keys := make([]string, 0, len(w.noAuth))
	for k, c := range w.noAuth {
		if c.ov != nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	if len(w.outbox) > 0 || ctx.Err() != nil {
		w.Counters.Add(CounterRepublishDeferred, uint64(len(keys)))
		return
	}
	slices.Sort(keys)
	b := w.in.Authorisations()
	for i, k := range keys {
		c := w.noAuth[k]
		if ctx.Err() != nil {
			w.Counters.Add(CounterRepublishDeferred, uint64(len(keys)-i))
			return
		}
		c.ov.body.Detail = w.noAuthDetail(c, b)
		c.ov.body.PolicyVersion = w.policyVer
		c.ov.body.InUSpace = true
		if c.last != nil {
			c.ov.body.CapturedAt = stampS(seconds(c.last.At))
		}
		upTo := c.ov.excerptUpToS
		m := w.message(c.ov, violation.StateUpdated, math.Inf(1))
		pctx, cancel := context.WithTimeout(ctx, w.publishTimeout())
		err := w.pub.PublishViolation(pctx, m)
		cancel()
		if err != nil {
			c.ov.excerptUpToS = upTo
			w.Counters.Inc(CounterRepublishFailed)
			w.warn("detect_republish_failed", "active violations not republished to ALRT; retried next tick",
				slog.String("error", err.Error()), slog.Int("active", len(keys)))
			w.Counters.Add(CounterRepublishDeferred, uint64(len(keys)-i-1))
			return
		}
		w.Counters.Inc(CounterRepublished)
	}
}

// heightLifted reports whether the 120 m rule is lifted for aircraft id:
// the policy says skip_when_authorised, the aircraft is inside a U-space
// airspace, and its last outcome matched an intent with its height
// checked (spec 01 §7: the authorised volume caps it). Unmatched and
// unknown aircraft are still judged against 120 m.
func (w *Worker) heightLifted(id string) bool {
	if w.thresholds.HeightLimitInUspace != policy.HeightSkipWhenAuthorised {
		return false
	}
	for k := range w.uspace[id] {
		if c := w.noAuth[k]; c != nil && c.last != nil && c.last.Matched && c.last.VerticalChecked {
			return true
		}
	}
	return false
}

// gateHeight applies heightLifted every tick to the height conditions
// the monitor holds: an open height_120m of an aircraft now lifted
// clears authorised and is held; a held one whose aircraft lost its
// match is raised at once; a held key the monitor no longer holds goes.
func (w *Worker) gateHeight() {
	active := map[string]bool{}
	for _, a := range w.mon.Active() {
		if kind, _ := parseKey(a.Key); kind != alerting.KindHeight {
			continue
		}
		active[a.Key] = true
		id := aircraftOf(&a)
		lifted := w.heightLifted(id)
		if ov, isOpen := w.open[a.Key]; isOpen && lifted {
			w.closeViolation(ov, violation.ClearReasonAuthorised, w.wallS(), ov.body.Detail, map[string]any{"authorised": true})
			delete(w.open, a.Key)
			w.heldHeight[a.Key] = true
			w.Counters.Inc(CounterHeightLifted)
			continue
		}
		if w.heldHeight[a.Key] && !lifted {
			delete(w.heldHeight, a.Key)
			w.Counters.Inc(CounterHeightRestored)
			w.raised(&a)
		}
	}
	for k := range w.heldHeight {
		if !active[k] {
			delete(w.heldHeight, k)
		}
	}
}

// openNoAuth is the number of open no_authorisation violations.
func (w *Worker) openNoAuth() int {
	n := 0
	for _, c := range w.noAuth {
		if c.ov != nil {
			n++
		}
	}
	return n
}

// noAuthStats are the cases' numbers for the status line (WP-26).
type noAuthStats struct {
	cases, open, unknown, matched, grace, heightLifted int
}

func (w *Worker) noAuthStats() noAuthStats {
	s := noAuthStats{cases: len(w.noAuth), heightLifted: len(w.heldHeight)}
	for _, c := range w.noAuth {
		switch {
		case c.ov != nil:
			s.open++
		case c.last == nil:
			s.unknown++
		case c.last.Matched:
			s.matched++
		case c.unmatchedSinceS > 0:
			s.grace++
		}
	}
	return s
}
