package dp

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// The conformance hook (docs/PLAN.md Q-A7): the InterUSS Remote ID
// observation interface uss_qualifier calls on a Display Provider, at
// the commit api/clients/SOURCE records
// (api/clients/interuss-observation/observation.yaml: GET
// {base}/display_data?view= and GET {base}/display_data/{id}), with
// base /v1/dp/observations. Scope dp.observe, issued to lab-01 only
// (WP-2 table B). Not a product endpoint.
const (
	ObservationBase       = "/v1/dp/observations"
	PatternDisplayData    = "GET " + ObservationBase + "/display_data"
	PatternDisplayDetails = "GET " + ObservationBase + "/display_data/{id}"
	// ScopeObserve is the hook's scope.
	ScopeObserve = "dp.observe"
)

// Counters of the hook.
const (
	CounterObserveServed      = "observations_served"
	CounterObserveNoToken     = "observations_refused_no_token"
	CounterObserveBadToken    = "observations_refused_token"
	CounterObserveUnavailable = "observations_refused_verifier_unavailable"
	CounterObserveScope       = "observations_refused_scope"
	CounterObserveBadView     = "observations_refused_view"
)

// The observation interface's shapes, member names from the pinned
// observation.yaml and commons.yaml (TestObservationShapesFollowThePinnedContract).

// ObsPosition is observation.yaml Position.
type ObsPosition struct {
	Lat    float64    `json:"lat"`
	Lng    float64    `json:"lng"`
	Alt    *float64   `json:"alt,omitempty"`
	Height *ObsHeight `json:"height,omitempty"`
}

// ObsHeight is commons.yaml RIDHeight.
type ObsHeight struct {
	Distance  float64 `json:"distance"`
	Reference string  `json:"reference"`
}

// ObsCurrentState is observation.yaml CurrentState.
type ObsCurrentState struct {
	Timestamp         string   `json:"timestamp,omitempty"`
	OperationalStatus string   `json:"operational_status,omitempty"`
	Track             *float64 `json:"track,omitempty"`
	Speed             *float64 `json:"speed,omitempty"`
	VerticalSpeed     *float64 `json:"vertical_speed,omitempty"`
}

// ObsFlight is observation.yaml Flight.
type ObsFlight struct {
	ID                 string           `json:"id"`
	CurrentState       *ObsCurrentState `json:"current_state,omitempty"`
	MostRecentPosition *ObsPosition     `json:"most_recent_position,omitempty"`
}

// ObsCluster is observation.yaml Cluster.
type ObsCluster struct {
	Corners         [2]ObsPosition `json:"corners"`
	AreaSqm         float64        `json:"area_sqm"`
	NumberOfFlights int            `json:"number_of_flights"`
}

// ObsDisplayData is observation.yaml GetDisplayDataResponse.
type ObsDisplayData struct {
	Flights  []ObsFlight  `json:"flights"`
	Clusters []ObsCluster `json:"clusters"`
}

// ObsLatLng is commons.yaml LatLngPoint.
type ObsLatLng struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

// ObsOperator is observation.yaml Operator.
type ObsOperator struct {
	ID       string     `json:"id,omitempty"`
	Location *ObsLatLng `json:"location,omitempty"`
}

// ObsUAS is observation.yaml UAS.
type ObsUAS struct {
	ID string `json:"id,omitempty"`
}

// ObsDetails is observation.yaml GetDetailsResponse.
type ObsDetails struct {
	Operator *ObsOperator `json:"operator,omitempty"`
	UAS      *ObsUAS      `json:"uas,omitempty"`
}

// Observations serves the hook from the flights the Display Provider
// shows: those whose last state was received within MaxAge (60 s,
// timeplace's MaxAgeS) and lies in the view. A view wider than the
// F3411 details diagonal (NetDetailsMaxDisplayAreaDiagonalKm, 2 km) is
// answered with clusters, never with flights: the view is cut into a
// 2 x 2 grid (each cell at least NetMinClusterSizePercent of the view)
// and every cell holding a flight is one cluster.
type Observations struct {
	Verifier Verifier
	Memory   *Memory
	MaxAge   time.Duration
	Counters *core.Counters
	Now      func() time.Time
}

func (o *Observations) inc(name string) {
	if o.Counters != nil {
		o.Counters.Inc(name)
	}
}

func (o *Observations) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func problem(r *http.Request) func(http.ResponseWriter, int, string) {
	return func(w http.ResponseWriter, status int, detail string) {
		slug := httpx.SlugUnauthn
		switch status {
		case http.StatusForbidden:
			slug = httpx.SlugForbidden
		case http.StatusServiceUnavailable:
			slug = "unavailable"
		}
		httpx.NewProblem(status, slug, "", detail).Write(w, r)
	}
}

// Mount registers the two routes on mux.
func (o *Observations) Mount(mux *http.ServeMux) {
	mux.HandleFunc(PatternDisplayData, o.displayData)
	mux.HandleFunc(PatternDisplayDetails, o.details)
}

func (o *Observations) admit(w http.ResponseWriter, r *http.Request) bool {
	_, ok := authenticate(w, r, o.Verifier, ScopeObserve, o.inc,
		[4]string{CounterObserveNoToken, CounterObserveBadToken, CounterObserveUnavailable, CounterObserveScope}, problem(r))
	return ok
}

func (o *Observations) recent() []FlightView {
	maxAge := o.MaxAge
	if maxAge <= 0 {
		maxAge = f3411.NetMaxNearRealTimeDataPeriodSeconds * time.Second
	}
	return o.Memory.Snapshot(o.now().Add(-maxAge))
}

func (o *Observations) displayData(w http.ResponseWriter, r *http.Request) {
	if !o.admit(w, r) {
		return
	}
	view, err := ParseView(r.URL.Query().Get("view"), "view")
	if err != nil {
		o.inc(CounterObserveBadView)
		var fe *core.FieldError
		if !errors.As(err, &fe) {
			fe = &core.FieldError{Field: "view", Reason: err.Error()}
		}
		httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "", "", fe).Write(w, r)
		return
	}
	o.inc(CounterObserveServed)
	writeJSON(w, DisplayData(view, o.recent()))
}

// DisplayData is the observation of view: flights for a view within
// the details diagonal, clusters for a wider one.
func DisplayData(view Box, flights []FlightView) ObsDisplayData {
	out := ObsDisplayData{Flights: []ObsFlight{}, Clusters: []ObsCluster{}}
	var in []FlightView
	for _, f := range flights {
		p := f.Mapped.Message.Body.Position
		if Contains(view, core.LatLon{LatDeg: p.Lat, LonDeg: p.Lng}) {
			in = append(in, f)
		}
	}
	if DiagonalKM(view) <= f3411.NetDetailsMaxDisplayAreaDiagonalKm {
		for _, f := range in {
			out.Flights = append(out.Flights, obsFlight(f))
		}
		return out
	}
	// Each flight counts in one cell (a flight on an inner edge goes
	// north and east), in Split4's order.
	cells := Tile{Box: view}.Split4()
	midLat, midLon := (view.MinLat+view.MaxLat)/2, (view.MinLon+view.MaxLon)/2
	var counts [4]int
	for _, f := range in {
		p := f.Mapped.Message.Body.Position
		i := 0
		if p.Lat >= midLat {
			i += 2
		}
		if p.Lng >= midLon {
			i++
		}
		counts[i]++
	}
	for i, c := range cells {
		n := counts[i]
		if n == 0 {
			continue
		}
		north, east := geodesy.LocalOffsetAboutMidLatM(core.LatLon{LatDeg: c.Box.MinLat, LonDeg: c.Box.MinLon},
			core.LatLon{LatDeg: c.Box.MaxLat, LonDeg: c.Box.MaxLon})
		out.Clusters = append(out.Clusters, ObsCluster{
			Corners:         [2]ObsPosition{{Lat: c.Box.MinLat, Lng: c.Box.MinLon}, {Lat: c.Box.MaxLat, Lng: c.Box.MaxLon}},
			AreaSqm:         math.Abs(north * east),
			NumberOfFlights: n,
		})
	}
	return out
}

func obsFlight(f FlightView) ObsFlight {
	b := &f.Mapped.Message.Body
	pos := &ObsPosition{Lat: b.Position.Lat, Lng: b.Position.Lng, Alt: b.AltWGS84M}
	if b.HeightM != nil && b.HeightRef != nil {
		pos.Height = &ObsHeight{Distance: *b.HeightM, Reference: string(*b.HeightRef)}
	}
	st := &ObsCurrentState{Track: b.TrackDeg, Speed: b.SpeedMS, VerticalSpeed: b.VSpeedMS}
	if ts := f.Mapped.Message.TS; ts != nil {
		st.Timestamp = *ts
	}
	if b.Status != nil {
		st.OperationalStatus = string(*b.Status)
	}
	return ObsFlight{ID: b.TrackID, CurrentState: st, MostRecentPosition: pos}
}

func (o *Observations) details(w http.ResponseWriter, r *http.Request) {
	if !o.admit(w, r) {
		return
	}
	id := r.PathValue("id")
	for _, f := range o.recent() {
		if f.Mapped.Message.Body.TrackID != id {
			continue
		}
		o.inc(CounterObserveServed)
		writeJSON(w, Details(f.Details))
		return
	}
	httpx.NewProblem(http.StatusNotFound, httpx.SlugNotFound, "", "no such flight").Write(w, r)
}

// Details is the observation of a flight's details: the operator id's
// public part only (the secret part of an EU registration number never
// leaves, regnum.PublicPart), the operator location and the serial.
func Details(d *f3411.RIDFlightDetails) ObsDetails {
	var out ObsDetails
	if d == nil {
		return out
	}
	if id := OperatorIDOf(d); id != nil || d.OperatorLocation != nil {
		op := &ObsOperator{}
		if id != nil {
			op.ID = regnum.PublicPart(*id)
		}
		if l := d.OperatorLocation; l != nil {
			op.Location = &ObsLatLng{Lat: l.Position.Lat, Lng: l.Position.Lng}
		}
		out.Operator = op
	}
	if sn := SerialOf(d); sn != nil {
		out.UAS = &ObsUAS{ID: *sn}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
