package picture

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

// FuzzParseSubscribe: whatever a console sends, ParseSubscribe never
// panics, refuses with a *core.FieldError naming a member, and what it
// accepts is a box in range with layers of the closed enumeration that
// parses back to the same subscription.
func FuzzParseSubscribe(f *testing.F) {
	for _, seed := range []string{
		string(subscribeFrameOf(44.80, 41.70, 44.85, 41.73)),
		string(subscribeFrameOf(179.9, -1, -179.9, 1, LayerTracks)),
		string(subscribeFrameOf(-180, -90, 180, 90, LayerAlerts, LayerZones)),
		`{"schema":"console/subscribe/v1","msg_id":null,"body":{"bbox":[1,2,3,4],"layers":[]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,50,3,40],"layers":[]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3,4],"layers":["tracks","tracks"]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1e999,2,3,4],"layers":[]}}`,
		`{"schema":"console/subscribe/v1","body":null}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3,4],"layers":[]}} {}`,
		"", "null", "[]", "{", "\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		box, layers, err := ParseSubscribe(raw)
		if err != nil {
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field == "" {
				t.Fatalf("refusal %v is not a *core.FieldError naming a member", err)
			}
			if layers != nil {
				t.Fatalf("refused with layers %v", layers)
			}
			return
		}
		for _, v := range []float64{box.MinLat, box.MaxLat, box.MinLon, box.MaxLon} {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("accepted a box with %v", v)
			}
		}
		if box.MinLat < -90 || box.MaxLat > 90 || box.MinLat > box.MaxLat || box.MinLon < -180 || box.MinLon > 180 ||
			box.MaxLon < -180 || box.MaxLon > 180 {
			t.Fatalf("accepted a box out of range: %+v", box)
		}
		var names []string
		for l, on := range layers {
			switch l {
			case LayerTracks, LayerManned, LayerAlerts, LayerZones:
			default:
				t.Fatalf("accepted layer %q", l)
			}
			if !on {
				t.Fatalf("layer %q listed as off", l)
			}
			names = append(names, l)
		}
		if names == nil {
			names = []string{}
		}
		again, err := json.Marshal(map[string]any{"schema": SchemaSubscribe, "body": map[string]any{
			"bbox": []float64{box.MinLon, box.MinLat, box.MaxLon, box.MaxLat}, "layers": names,
		}})
		if err != nil {
			t.Fatal(err)
		}
		box2, layers2, err := ParseSubscribe(again)
		if err != nil || box2 != box || len(layers2) != len(layers) {
			t.Fatalf("an accepted subscription does not parse back: %+v %v %v", box2, layers2, err)
		}
	})
}

// FuzzParseBBox: any four numbers, and any other count, are either a box
// in range whose corners are the numbers given, or a refusal naming the
// field; nothing panics.
func FuzzParseBBox(f *testing.F) {
	f.Add(44.80, 41.70, 44.85, 41.73, 4)
	f.Add(179.9, -1.0, -179.9, 1.0, 4)
	f.Add(-180.0, -90.0, 180.0, 90.0, 4)
	f.Add(1.0, 50.0, 3.0, 40.0, 4)
	f.Add(math.NaN(), 0.0, 0.0, 0.0, 4)
	f.Add(math.Inf(1), 0.0, 0.0, 0.0, 4)
	f.Add(0.0, 0.0, 0.0, 0.0, 3)
	f.Add(0.0, 0.0, 0.0, 0.0, 5)
	f.Fuzz(func(t *testing.T, w, s, e, n float64, count int) {
		v := []float64{w, s, e, n}
		switch {
		case count < 0:
			v = nil
		case count < 4:
			v = v[:count%4]
		case count > 4:
			v = append(v, make([]float64, min(count-4, 8))...)
		}
		box, err := ParseBBox(v, "bbox")
		ok := len(v) == 4
		for _, x := range v {
			ok = ok && !math.IsNaN(x) && !math.IsInf(x, 0)
		}
		ok = ok && w >= -180 && w <= 180 && e >= -180 && e <= 180 && s >= -90 && s <= 90 && n >= -90 && n <= 90 && s <= n
		if err != nil {
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != "bbox" {
				t.Fatalf("refusal %v does not name the field", err)
			}
			if ok {
				t.Fatalf("refused a valid box %v: %v", v, err)
			}
			return
		}
		if !ok {
			t.Fatalf("accepted %v", v)
		}
		if box.MinLon != w || box.MinLat != s || box.MaxLon != e || box.MaxLat != n {
			t.Fatalf("box %+v is not [%v %v %v %v]", box, w, s, e, n)
		}
	})
}
