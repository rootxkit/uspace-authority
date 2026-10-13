package zonesvc

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/outline"
)

// outlineServer mounts GET /v1/outlines/circle behind the contract's
// roles, with no store: the operation reads none.
func outlineServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	identify := func(r *http.Request) (apiserver.Identity, error) {
		id, ok := testIdentities[r.Header.Get("X-Test-As")]
		if !ok {
			return apiserver.Identity{}, apiserver.ErrNoSession
		}
		return id, nil
	}
	h := Handler{}
	apiserver.Mount(mux, apiserver.Server{ZonesHandler: h, USpaceHandler: h}, apiserver.Options{
		Middlewares:  []apiserver.Middleware{apiserver.Authorize(identify, apiserver.DefaultRules())},
		Admit:        apiserver.Admission(identify, apiserver.DefaultRules()),
		Keep:         apiserver.PathPrefix("/v1/outlines"),
		BodyCounters: &core.Counters{},
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Presence: an author (inspector, admin) gets the circle drawn, closed.
func TestCircleOutlineDrawsForAnAuthor(t *testing.T) {
	srv := outlineServer(t)
	for _, as := range []string{"inspector", "admin"} {
		code, ct, b := call(t, srv, as, http.MethodGet, "/v1/outlines/circle?lat=41.715&lng=44.8&radius_m=1500", "", nil)
		if code != http.StatusOK || !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s: %d %s", as, code, b)
		}
		var got struct {
			Outline struct {
				Type        string         `json:"type"`
				Coordinates [][][2]float64 `json:"coordinates"`
			} `json:"outline"`
			Vertices int `json:"vertices"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		ring := got.Outline.Coordinates
		if got.Outline.Type != "Polygon" || got.Vertices != outline.Vertices || len(ring) != 1 || len(ring[0]) != outline.Vertices+1 || ring[0][0] != ring[0][outline.Vertices] {
			t.Fatalf("%s: %s", as, b)
		}
		if ring[0][0] != [2]float64{44.8, 41.72850525} {
			t.Fatalf("%s: first vertex %v", as, ring[0][0])
		}
	}
}

// Absence: a viewer is not an author, no session is 401, and each bound
// is a 400 naming its field.
func TestCircleOutlineRefuses(t *testing.T) {
	srv := outlineServer(t)
	if code, _, b := call(t, srv, "viewer", http.MethodGet, "/v1/outlines/circle?lat=41.7&lng=44.8&radius_m=1500", "", nil); code != http.StatusForbidden {
		t.Fatalf("viewer: %d %s", code, b)
	}
	if code, _, b := call(t, srv, "nobody", http.MethodGet, "/v1/outlines/circle?lat=41.7&lng=44.8&radius_m=1500", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no session: %d %s", code, b)
	}
	for q, field := range map[string]string{
		"lat=41.7&lng=44.8&radius_m=0":                                     "radius_m",
		"lat=41.7&lng=44.8&radius_m=" + strconv.Itoa(outline.MaxRadiusM+1): "radius_m",
		"lat=89.5&lng=44.8&radius_m=1500":                                  "lat",
		"lat=41.7&lng=181&radius_m=1500":                                   "lng",
	} {
		code, _, b := call(t, srv, "inspector", http.MethodGet, "/v1/outlines/circle?"+q, "", nil)
		if code != http.StatusBadRequest || !strings.Contains(string(b), `"field":"`+field+`"`) {
			t.Errorf("%s: %d %s", q, code, b)
		}
	}
}

// The editor's ring bound (web/src/zones/editor/outline.ts
// MAX_RING_VERTICES) is the vertices of the largest ring ed318.Parse
// takes, whose last position repeats the first: a ring at the bound is
// accepted, one past it refused (E-01).
func TestEditorRingBoundIsCoresParseBound(t *testing.T) {
	src, err := os.ReadFile("../../web/src/zones/editor/outline.ts")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`export const MAX_RING_VERTICES = (\d+);`).FindSubmatch(src)
	if m == nil {
		t.Fatal("MAX_RING_VERTICES not found in web/src/zones/editor/outline.ts")
	}
	n, _ := strconv.Atoi(string(m[1]))
	if want := ed269.DefaultLimits.MaxRingVertices - 1; n != want {
		t.Fatalf("MAX_RING_VERTICES %d, core takes %d vertices", n, want)
	}
	ring := func(vertices int) string {
		pts := make([]string, 0, vertices+1)
		for i := range vertices {
			// A convex fan of distinct positions around (44.8, 41.7).
			a := 2 * math.Pi * float64(i) / float64(vertices)
			pts = append(pts, fmt.Sprintf("[%.9f,%.9f]", 44.8+0.1*math.Cos(a), 41.7+0.1*math.Sin(a)))
		}
		pts = append(pts, pts[0])
		return `{"type":"FeatureCollection","features":[{"type":"Feature","properties":{"identifier":"TST001","country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["AIR_TRAFFIC"],"zoneAuthority":[{"name":[{"text":"A","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]},"geometry":{"type":"Polygon","coordinates":[[` + strings.Join(pts, ",") + `]],"layer":{"upper":120,"upperReference":"AGL","lower":0,"lowerReference":"AGL","uom":"m"}}}]}`
	}
	if _, probs := ed318.Parse([]byte(ring(n)), ed318.Limits{}); probs != nil && strings.Contains(probs.Error(), "per ring") {
		t.Fatalf("a ring of %d vertices is refused: %v", n, probs)
	}
	if _, probs := ed318.Parse([]byte(ring(n+1)), ed318.Limits{}); probs == nil || !strings.Contains(probs.Error(), "per ring") {
		t.Fatalf("a ring of %d vertices is not refused for its size: %v", n+1, probs)
	}
}
