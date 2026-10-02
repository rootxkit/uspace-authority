package detectsvc

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/f3411"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/vectors"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The knowledge vectors alert_lifecycle.json and zones_vertical.json run
// through this repository's adapters (CLAUDE.md, RunOwned): each input
// is written as the trk.v1 message rid-ingest publishes, mapped by
// ToTrack, judged by the worker's uspace-core monitor (built by
// ConfigFor from a policy with the case's thresholds), and its output is
// the violation/v1 messages the worker publishes, compared with the
// case's expected raises and clears through the kind mapping of plan D5.
// Nothing is judged here.
//
// What the authority's adapter cannot express, said rather than
// skipped: conflicts (plan D5) are never judged here (SkipConflicts), so
// a case's conflict raises and clears are expected as nothing, and the
// counters of a case that expects conflicts, which rest on alert holders
// the authority never has, are not compared; an aircraft whose
// identification the vector leaves null carries "registered" (every
// authority track carries one), which raises no identification alert,
// as the vector expects of none.

const tolDetail = 0.1/2 + 1e-9

// vSource maps the vectors' source names onto this system's sources
// (one name, one source type, both in tracks and in switches).
var vSource = map[string]track.Source{"relay": track.SourceOperatorWS, "remote_id": track.SourceDirectRID}

func vSourceOf(t *testing.T, name string) track.Source {
	t.Helper()
	s, ok := vSource[name]
	if !ok {
		t.Fatalf("source %q has no mapping", name)
	}
	return s
}

type vAircraft struct {
	ID                  string               `json:"id"`
	NorthM              *float64             `json:"north_m"`
	EastM               *float64             `json:"east_m"`
	LatDeg              float64              `json:"lat_deg"`
	LonDeg              float64              `json:"lon_deg"`
	AltAMSLM            *float64             `json:"alt_amsl_m"`
	VN                  float64              `json:"vn"`
	VE                  float64              `json:"ve"`
	VD                  float64              `json:"vd"`
	Flying              *bool                `json:"flying"`
	CapturedAtS         *float64             `json:"captured_at_s"`
	RxAtS               *float64             `json:"rx_at_s"`
	StationClockOffsetS *float64             `json:"station_clock_offset_s"`
	Backlog             bool                 `json:"backlog"`
	Source              *string              `json:"source"`
	Station             *string              `json:"station"`
	AltSource           *string              `json:"alt_source"`
	Identification      *core.Identification `json:"identification"`
	Transmitter         *string              `json:"transmitter"`
	Identified          *bool                `json:"identified"`
}

type vStep struct {
	TS         float64    `json:"t_s"`
	Op         string     `json:"op"`
	Aircraft   *vAircraft `json:"aircraft"`
	SourceType string     `json:"source_type"`
	InstanceID *string    `json:"instance_id"`
	Enabled    *bool      `json:"enabled"`
}

type vConfig struct {
	ClearAfterS      *float64          `json:"clear_after_s"`
	StaleAfterS      *float64          `json:"stale_after_s"`
	NeighbourMaxAgeS *float64          `json:"neighbour_max_age_s"`
	LiveMaxAgeS      *float64          `json:"live_max_age_s"`
	MaxAircraft      *int              `json:"max_aircraft"`
	MaxSourceShare   *float64          `json:"max_source_share"`
	Zones            []json.RawMessage `json:"zones"`
}

type vAlert struct {
	Kind     string         `json:"kind"`
	Severity string         `json:"severity"`
	Aircraft []string       `json:"aircraft"`
	Detail   map[string]any `json:"detail"`
	Reason   string         `json:"reason"`
}

type vStepExp struct {
	Raised  []vAlert `json:"raised"`
	Cleared []vAlert `json:"cleared"`
}

type vExpected struct {
	PerStep     []vStepExp        `json:"per_step"`
	ActiveAfter []vAlert          `json:"active_after"`
	Counters    map[string]uint64 `json:"counters"`
}

// stampOf is a time in seconds as an envelope stamp.
func stampOf(s float64) time.Time {
	sec, frac := math.Modf(s)
	return time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC()
}

// messageOf writes a vector aircraft as the trk.v1 message rid-ingest
// would publish, with the description's defaults (captured at t_s,
// received when captured, flying, 550 m AMSL geodetic, source relay).
func messageOf(t *testing.T, a *vAircraft, tS float64) *track.Message {
	t.Helper()
	captured := tS
	if a.CapturedAtS != nil {
		captured = *a.CapturedAtS
	}
	rx := captured
	if a.RxAtS != nil {
		rx = *a.RxAtS
	}
	src := captured
	if a.StationClockOffsetS != nil {
		src += *a.StationClockOffsetS
	}
	alt := 550.0
	if a.AltAMSLM != nil {
		alt = *a.AltAMSLM
	}
	status := f3411.Airborne
	if a.Flying != nil && !*a.Flying {
		status = f3411.Ground
	}
	altSrc := core.AltGeodetic
	if a.AltSource != nil {
		altSrc = core.AltSource(*a.AltSource)
	}
	source := track.SourceOperatorWS
	if a.Source != nil {
		source = vSourceOf(t, *a.Source)
	}
	inst := "station"
	if a.Station != nil {
		inst = *a.Station
	}
	ident := core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched, Basis: core.BasisAsBroadcast}
	if a.Identification != nil {
		ident = *a.Identification
		if ident.Basis == "" {
			ident.Basis = core.BasisAsBroadcast
		}
	}
	body := track.Body{TrackID: a.ID, Trust: core.TrustBroadcast, Source: source, SourceInstance: inst,
		Position: track.Position{Lat: a.LatDeg, Lng: a.LonDeg}, AltSource: altSrc, Status: &status, Identification: ident}
	if altSrc == core.AltPressure {
		body.AltPressureM = &alt
	} else {
		body.AltAMSLM = &alt
	}
	ts := stampOf(src)
	m, err := track.New("authority/rid-ingest", core.Times{TS: &ts, RxTS: stampOf(rx), CapturedAt: stampOf(captured),
		Source: core.TimeBroadcast, Backlog: a.Backlog}, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

// violationKind is the vector's alert kind as the authority publishes it.
var violationKind = map[string]violation.Kind{
	"zone": violation.KindZoneIncursion, "height": violation.KindHeight120m, "identification": violation.KindUnregistered,
	"identification_mismatch": violation.KindIdentificationMismatch,
}

func expectedViolations(as []vAlert) []vAlert {
	var out []vAlert
	for _, a := range as {
		k, ok := violationKind[a.Kind]
		if !ok {
			continue // a conflict: the authority raises none (plan D5)
		}
		a.Kind = string(k)
		out = append(out, a)
	}
	return out
}

func published(ms []*violation.Message) (raised, cleared []vAlert) {
	for _, m := range ms {
		a := vAlert{Kind: string(m.Body.Kind), Severity: string(m.Body.Severity), Aircraft: []string{m.Body.TrackRef}, Detail: m.Body.Detail}
		switch m.Body.State {
		case violation.StateRaised:
			raised = append(raised, a)
		case violation.StateUpdated:
			// A severity change is raised again under the same key (C-07);
			// the worker publishes it as an update of the open
			raised = append(raised, a)
		case violation.StateCleared:
			a.Reason = *m.Body.ClearReason
			cleared = append(cleared, a)
		}
	}
	return raised, cleared
}

func detailEqual(got, want any) bool {
	switch w := want.(type) {
	case float64:
		g, ok := got.(float64)
		return ok && math.Abs(g-w) <= tolDetail
	case []any:
		g, ok := got.([]string)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range g {
			if s, ok := w[i].(string); !ok || s != g[i] {
				return false
			}
		}
		return true
	case nil:
		return got == nil
	}
	return got == want
}

func alertEqual(got, want vAlert) bool {
	if got.Kind != want.Kind || got.Severity != want.Severity || got.Reason != want.Reason ||
		!slices.Equal(got.Aircraft, want.Aircraft) || len(got.Detail) != len(want.Detail) {
		return false
	}
	for k, w := range want.Detail {
		if g, ok := got.Detail[k]; !ok || !detailEqual(g, w) {
			return false
		}
	}
	return true
}

func compareSets(t *testing.T, what string, got, want []vAlert) {
	t.Helper()
	used := make([]bool, len(got))
	var missing []vAlert
	for _, w := range want {
		found := false
		for i, g := range got {
			if !used[i] && alertEqual(g, w) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			missing = append(missing, w)
		}
	}
	var extra []vAlert
	for i := range got {
		if !used[i] {
			extra = append(extra, got[i])
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf("%s: missing %+v unexpected %+v", what, missing, extra)
	}
}

// vSwitches accumulates the switch_source steps into published states.
type vSwitches struct{ st coresources.State }

func (s *vSwitches) apply(t *testing.T, typ string, instance *string, enabled bool) coresources.State {
	t.Helper()
	s.st.Epoch = "vectors"
	s.st.Version++
	name := string(vSourceOf(t, typ))
	for i, c := range s.st.Controls {
		if c.SourceType == name && ((c.InstanceID == nil && instance == nil) || (c.InstanceID != nil && instance != nil && *c.InstanceID == *instance)) {
			s.st.Controls[i].Enabled = enabled
			return s.clone()
		}
	}
	s.st.Controls = append(s.st.Controls, coresources.Control{SourceType: name, InstanceID: instance, Enabled: enabled})
	return s.clone()
}

func (s *vSwitches) clone() coresources.State {
	out := s.st
	out.Controls = slices.Clone(s.st.Controls)
	return out
}

func TestVectorsAlertLifecycleThroughTheDetector(t *testing.T) {
	f := vectors.Load(t, "alert_lifecycle.json")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			Config vConfig `json:"config"`
			Steps  []vStep `json:"steps"`
		}
		var exp vExpected
		c.Decode(t, &in, &exp)
		r := newRigAt(t, stampOf(0), func(s *Settings) {
			if in.Config.MaxAircraft != nil {
				s.MaxAircraft = *in.Config.MaxAircraft
			}
		})
		r.in.setPolicy(1, func(p *policy.Thresholds) {
			if v := in.Config.ClearAfterS; v != nil {
				p.ClearAfterS = *v
			}
			if v := in.Config.StaleAfterS; v != nil {
				p.StaleAfterS = *v
			}
			if v := in.Config.LiveMaxAgeS; v != nil {
				p.LiveMaxAgeS = *v
			}
		})
		var zs []*zones.Zone
		for i, raw := range in.Config.Zones {
			gz, problems := ed269.ParseZone(raw, ed269.Limits{})
			if problems != nil {
				t.Fatalf("zones[%d]: %v", i, problems)
			}
			z, err := zones.FromED269(gz)
			if err != nil {
				t.Fatal(err)
			}
			zs = append(zs, z)
		}
		r.in.setZones(zs...)
		r.clk.set(stampOf(0))
		r.w.maybeRebuild()
		r.pub.take()
		conflicts := false
		var sw vSwitches
		for i, s := range in.Steps {
			r.clk.set(stampOf(s.TS))
			switch s.Op {
			case "observe":
				if !r.w.Observe(messageOf(t, s.Aircraft, s.TS)) {
					t.Fatalf("step %d not observed", i)
				}
			case "tick":
				r.w.handle(r.w.mon.Tick(r.w.wallS()))
			case "switch_source":
				r.in.setSources(sw.apply(t, s.SourceType, s.InstanceID, *s.Enabled))
				r.w.SwitchSources(t.Context())
			default:
				t.Fatalf("step %d: op %q", i, s.Op)
			}
			raised, cleared := published(r.pub.take())
			wantR, wantC := expectedViolations(exp.PerStep[i].Raised), expectedViolations(exp.PerStep[i].Cleared)
			conflicts = conflicts || len(wantR) != len(exp.PerStep[i].Raised) || len(wantC) != len(exp.PerStep[i].Cleared)
			compareSets(t, fmt.Sprintf("step %d raised", i), raised, wantR)
			compareSets(t, fmt.Sprintf("step %d cleared", i), cleared, wantC)
		}
		var active []vAlert
		for _, a := range r.w.mon.Active() {
			if k, ok := violationKind[a.Kind]; ok {
				active = append(active, vAlert{Kind: string(k), Severity: string(a.Severity), Aircraft: a.Aircraft, Detail: a.Detail})
			}
		}
		compareSets(t, "active_after", active, expectedViolations(exp.ActiveAfter))
		if len(expectedViolations(exp.ActiveAfter)) != len(exp.ActiveAfter) || conflicts {
			return
		}
		r.w.fold()
		for name, want := range exp.Counters {
			if got := r.w.MonitorCounters.Get(name); got != want {
				t.Errorf("counter %s = %d, want %d", name, got, want)
			}
		}
	})
}

type zvInput struct {
	Zone     json.RawMessage `json:"zone"`
	Aircraft struct {
		AltAMSLM  *float64 `json:"alt_amsl_m"`
		AltSource string   `json:"alt_source"`
	} `json:"aircraft"`
	Terrain              json.RawMessage `json:"terrain"`
	GeoidUndulationM     *float64        `json:"geoid_undulation_m"`
	MaxHeightAGLM        *float64        `json:"max_height_agl_m"`
	PressureUncertaintyM float64         `json:"pressure_uncertainty_m"`
	ConditionalSeverity  string          `json:"conditional_severity"`
	ZoneType             *string         `json:"zone_type"`
}

type zvExpected struct {
	Raised []struct {
		Kind     string          `json:"kind"`
		Severity string          `json:"severity"`
		Aircraft []string        `json:"aircraft"`
		Detail   json.RawMessage `json:"detail"`
	} `json:"raised"`
	Counters map[string]uint64 `json:"counters"`
	Reasons  []string          `json:"reasons"`
}

func envOfVector(t *testing.T, in zvInput) zones.Env {
	t.Helper()
	env := zones.Env{UndulationM: in.GeoidUndulationM}
	var word string
	if err := json.Unmarshal(in.Terrain, &word); err == nil {
		switch word {
		case "none":
			env.Ground = zones.GroundNotConfigured
		case "unknown here":
			env.Ground = zones.GroundUnknown
		default:
			t.Fatalf("terrain %q", word)
		}
		return env
	}
	var known struct {
		GroundM *float64 `json:"ground_m"`
	}
	vectors.Unmarshal(t, in.Terrain, &known)
	env.Ground, env.GroundM = zones.GroundKnown, *known.GroundM
	return env
}

// zones_vertical.json: one aircraft inside the zone (or none, for the
// height limit) judged once. The height limit of a case without one is
// set out of reach (the authority always judges its own, from policy),
// and a USPACE zone raises presence, never a violation (in_uspace).
func TestVectorsZonesVerticalThroughTheDetector(t *testing.T) {
	f := vectors.Load(t, "zones_vertical.json")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in zvInput
		var exp zvExpected
		c.Decode(t, &in, &exp)
		r := newRigAt(t, stampOf(0), nil)
		r.in.setPolicy(1, func(p *policy.Thresholds) {
			p.PressureUncertaintyM = in.PressureUncertaintyM
			p.ZoneConditionalSeverity = core.Severity(in.ConditionalSeverity)
			p.HeightLimitAGLM = 1e9
			if in.MaxHeightAGLM != nil {
				p.HeightLimitAGLM = *in.MaxHeightAGLM
			}
		})
		env := envOfVector(t, in)
		r.in.env = func(core.LatLon) zones.Env { return env }
		pos := core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}
		uspace := false
		if string(in.Zone) != "null" && len(in.Zone) > 0 {
			gz, problems := ed269.ParseZone(in.Zone, ed269.Limits{})
			if problems != nil {
				t.Fatal(problems)
			}
			z, err := zones.FromED269(gz)
			if err != nil {
				t.Fatal(err)
			}
			if in.ZoneType != nil {
				z.Type, z.Restriction = core.ZoneType(*in.ZoneType), ""
				uspace = z.Type == core.ZoneUSpace
			}
			r.in.setZones(z)
		}
		a := &vAircraft{ID: "A", LatDeg: pos.LatDeg, LonDeg: pos.LonDeg, AltAMSLM: in.Aircraft.AltAMSLM, AltSource: &in.Aircraft.AltSource}
		if in.Aircraft.AltAMSLM == nil {
			none := string(core.AltNone)
			a.AltSource = &none
		}
		r.clk.set(stampOf(0))
		r.w.Observe(messageOf(t, a, 0))
		raised, _ := published(r.pub.take())
		var want []vAlert
		for _, e := range exp.Raised {
			var d map[string]any
			vectors.Unmarshal(t, e.Detail, &d)
			k := violationKind[e.Kind]
			if uspace && e.Kind == "zone" {
				continue // presence in U-space: recorded, not a violation
			}
			want = append(want, vAlert{Kind: string(k), Severity: e.Severity, Aircraft: e.Aircraft, Detail: d})
		}
		compareSets(t, "raised", raised, want)
		if uspace && len(exp.Raised) > 0 && r.w.Counters.Get(CounterUSpacePresence) != 1 {
			t.Errorf("U-space presence not recorded: %v", r.w.Counters.Snapshot())
		}
		r.w.fold()
		for name, want := range exp.Counters {
			if got := r.w.MonitorCounters.Get(name); got != want {
				t.Errorf("counter %s = %d, want %d", name, got, want)
			}
		}
	})
}
