package dp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/timeplace"
)

func shownFlight(t *testing.T, mem *Memory, id string, la, lo float64, d *f3411.RIDFlightDetails, now time.Time) string {
	t.Helper()
	f := flight(id, state(now, la, lo))
	resp := now
	m, ok := Map(&Input{USSID: "ussp-lab-01", Flight: &f, Details: d, ResponseTS: &resp, RxTS: now}, MapDeps{Network: timeplace.DefaultNetworkPolicy()})
	if !ok {
		t.Fatal("not mapped")
	}
	k := FlightKey{USSID: "ussp-lab-01", FlightID: id}
	mem.Fresh(k, f.CurrentState, now)
	if d != nil {
		mem.SetDetailsRaw(k, d, nil, now)
	}
	mem.Published(k, m, "isa-1")
	return m.Message.Body.TrackID
}

// Q-A7: a view within the details diagonal shows flights; a wider one
// shows clusters only, each cell at least 15 % of the view
// (NetMinClusterSizePercent); a flight outside the view is not shown.
func TestDisplayDataFlightsOrClusters(t *testing.T) {
	now := time.Now()
	mem := NewMemory(100, nil)
	id := shownFlight(t, mem, "fl-1", baseLatDeg, baseLonDeg, nil, now)
	shownFlight(t, mem, "fl-far", baseLatDeg+1, baseLonDeg, nil, now)
	small := DisplayData(box2km, mem.Snapshot(now.Add(-time.Minute)))
	if len(small.Flights) != 1 || small.Flights[0].ID != id || len(small.Clusters) != 0 {
		t.Fatalf("small view %+v", small)
	}
	if p := small.Flights[0].MostRecentPosition; p == nil || p.Lat != baseLatDeg || *p.Alt != 600 {
		t.Fatalf("position %+v", p)
	}
	wide := DisplayData(box7km, mem.Snapshot(now.Add(-time.Minute)))
	if len(wide.Flights) != 0 || len(wide.Clusters) != 1 || wide.Clusters[0].NumberOfFlights != 1 {
		t.Fatalf("wide view %+v", wide)
	}
	viewArea := (box7km.MaxLat - box7km.MinLat) * (box7km.MaxLon - box7km.MinLon)
	c := wide.Clusters[0].Corners
	if cellArea := (c[1].Lat - c[0].Lat) * (c[1].Lng - c[0].Lng); cellArea < viewArea*f3411.NetMinClusterSizePercent/100 {
		t.Fatalf("cluster %.9f of a view of %.9f", cellArea, viewArea)
	}
}

// The hook admits a token granting dp.observe only; details show the
// operator id's public part, never the secret suffix.
func TestObservationHookAdmissionAndDetails(t *testing.T) {
	k := newIssuerKit(t)
	now := time.Now()
	mem := NewMemory(100, nil)
	d := details("fl-1", ctaSerial, "GEOabcd1234efgh-x9z")
	d.OperatorLocation = &f3411.OperatorLocation{Position: f3411.LatLngPoint{Lat: 41.7, Lng: 44.8}}
	id := shownFlight(t, mem, "fl-1", baseLatDeg, baseLonDeg, d, now)
	cnt := &core.Counters{}
	o := &Observations{Verifier: k.v, Memory: mem, Counters: cnt}
	mux := http.NewServeMux()
	o.Mount(mux)
	get := func(path, tok string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	view := ObservationBase + "/display_data?view=" + ViewParam(box2km)
	if code, _ := get(view, ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := get(view, k.token(t, "lab-01", ownHost, "rid.display_provider")); code != 403 {
		t.Fatalf("wrong scope: %d", code)
	}
	if code, _ := get(ObservationBase+"/display_data?view=1,2,3", k.token(t, "lab-01", ownHost, ScopeObserve)); code != 400 {
		t.Fatalf("bad view: %d", code)
	}
	code, body := get(view, k.token(t, "lab-01", ownHost, ScopeObserve))
	if code != 200 || !strings.Contains(body, id) {
		t.Fatalf("observed: %d %s", code, body)
	}
	code, body = get(ObservationBase+"/display_data/"+id, k.token(t, "lab-01", ownHost, ScopeObserve))
	if code != 200 || !strings.Contains(body, `"id":"GEOabcd1234efgh"`) || strings.Contains(body, "x9z") || !strings.Contains(body, ctaSerial) {
		t.Fatalf("details: %d %s", code, body)
	}
	if code, _ := get(ObservationBase+"/display_data/nobody", k.token(t, "lab-01", ownHost, ScopeObserve)); code != 404 {
		t.Fatalf("unknown flight: %d", code)
	}
	s := cnt.Snapshot()
	if s[CounterObserveNoToken] != 1 || s[CounterObserveScope] != 1 || s[CounterObserveBadView] != 1 || s[CounterObserveServed] != 2 {
		t.Fatalf("counters %v", s)
	}
}

// yamlProps reads the property names of components.schemas.<name> from
// the pinned observation interface (indentation-based; the file is the
// interface InterUSS publishes at the pinned commit).
func yamlProps(t *testing.T, file, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	start := slices.Index(lines, "    "+name+":")
	if start < 0 {
		t.Fatalf("no schema %s in %s", name, file)
	}
	prop := regexp.MustCompile(`^        ([a-z_]+):$`)
	var out []string
	in := false
	for _, l := range lines[start+1:] {
		if strings.HasPrefix(l, "    ") && !strings.HasPrefix(l, "     ") {
			break // the next schema
		}
		if l == "      properties:" {
			in = true
			continue
		}
		if in && strings.HasPrefix(l, "      ") && !strings.HasPrefix(l, "       ") {
			in = false
		}
		if m := prop.FindStringSubmatch(l); in && m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func jsonNames(v any) []string {
	var out []string
	t := reflect.TypeOf(v)
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		out = append(out, name)
	}
	return out
}

// E-03: every member the hook writes is a property of the pinned
// interface's schema of the same name (never written from memory).
func TestObservationShapesFollowThePinnedContract(t *testing.T) {
	const obs, commons = "../../api/clients/interuss-observation/observation.yaml", "../../api/clients/interuss-observation/commons.yaml"
	for _, c := range []struct {
		file, schema string
		v            any
	}{
		{obs, "GetDisplayDataResponse", ObsDisplayData{}}, {obs, "Flight", ObsFlight{}}, {obs, "CurrentState", ObsCurrentState{}},
		{obs, "Position", ObsPosition{}}, {obs, "Cluster", ObsCluster{}}, {obs, "GetDetailsResponse", ObsDetails{}},
		{obs, "Operator", ObsOperator{}}, {obs, "UAS", ObsUAS{}}, {commons, "RIDHeight", ObsHeight{}}, {commons, "LatLngPoint", ObsLatLng{}},
	} {
		props := yamlProps(t, c.file, c.schema)
		if len(props) == 0 {
			t.Fatalf("%s: no properties read", c.schema)
		}
		for _, n := range jsonNames(c.v) {
			if !slices.Contains(props, n) {
				t.Errorf("%s.%s is not in the pinned %s (%v)", c.schema, n, c.schema, props)
			}
		}
	}
	// The response is JSON the shape reads back.
	raw, _ := json.Marshal(DisplayData(box2km, nil))
	if string(raw) != `{"flights":[],"clusters":[]}` {
		t.Fatalf("%s", raw)
	}
}
