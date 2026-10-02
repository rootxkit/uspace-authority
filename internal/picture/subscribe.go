package picture

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-authority/internal/cell"
)

// subscribeFrame is console/subscribe/v1 as it arrives.
type subscribeFrame struct {
	Schema string          `json:"schema"`
	MsgID  *string         `json:"msg_id"`
	Body   json.RawMessage `json:"body"`
}

type subscribeBody struct {
	BBox   []float64 `json:"bbox"`
	Layers []string  `json:"layers"`
}

// ParseSubscribe reads one console/subscribe/v1 frame (uspace-lab
// schemas/common/console/subscribe/v1): the schema name, a body with a
// bbox of four numbers [west, south, east, north] in range (west > east
// crosses the antimeridian, south <= north) and unique layers of the
// closed enumeration. The msg_id is ignored: nothing a console sends is
// a time or an anchor. Every refusal is a *core.FieldError naming the
// member; nothing here panics on any input.
func ParseSubscribe(raw []byte) (geodesy.BBox, map[string]bool, error) {
	var f subscribeFrame
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&f); err != nil {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "frame", Reason: "not a JSON object"}
	}
	if dec.More() {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "frame", Reason: "trailing data after the frame"}
	}
	if f.Schema != SchemaSubscribe {
		return geodesy.BBox{}, nil, core.Fieldf("schema", "%q: the only frame a console sends is %s", truncate(f.Schema, 64), SchemaSubscribe)
	}
	if len(f.Body) == 0 || string(f.Body) == "null" {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	var b subscribeBody
	if err := json.Unmarshal(f.Body, &b); err != nil {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "body", Reason: "bbox must be four numbers and layers an array of names"}
	}
	if b.BBox == nil {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "body.bbox", Reason: "required"}
	}
	if b.Layers == nil {
		return geodesy.BBox{}, nil, &core.FieldError{Field: "body.layers", Reason: "required"}
	}
	box, err := ParseBBox(b.BBox, "body.bbox")
	if err != nil {
		return geodesy.BBox{}, nil, err
	}
	layers := make(map[string]bool, len(b.Layers))
	for i, l := range b.Layers {
		switch l {
		case LayerTracks, LayerManned, LayerAlerts, LayerZones:
		default:
			return geodesy.BBox{}, nil, core.Fieldf("body.layers", "item %d %q is not tracks, manned, alerts or zones", i, truncate(l, 32))
		}
		if layers[l] {
			return geodesy.BBox{}, nil, core.Fieldf("body.layers", "%q is listed twice", l)
		}
		layers[l] = true
	}
	return box, layers, nil
}

// ParseBBox reads [west, south, east, north] in WGS84 degrees.
func ParseBBox(v []float64, field string) (geodesy.BBox, error) {
	if len(v) != 4 {
		return geodesy.BBox{}, core.Fieldf(field, "four numbers [west, south, east, north], got %d", len(v))
	}
	for _, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return geodesy.BBox{}, &core.FieldError{Field: field, Reason: "not a finite number"}
		}
	}
	w, s, e, n := v[0], v[1], v[2], v[3]
	switch {
	case w < -180 || w > 180 || e < -180 || e > 180:
		return geodesy.BBox{}, core.Fieldf(field, "longitudes must be in [-180, 180]")
	case s < -90 || s > 90 || n < -90 || n > 90:
		return geodesy.BBox{}, core.Fieldf(field, "latitudes must be in [-90, 90]")
	case s > n:
		return geodesy.BBox{}, core.Fieldf(field, "south %v is north of north %v", s, n)
	}
	return geodesy.BBox{MinLat: s, MinLon: w, MaxLat: n, MaxLon: e}, nil
}

// ViewportCells is the cell set of box: the c5 cover plus one ring of
// neighbours, at most maxCells (internal/cell.Viewport; a larger one is
// a *core.FieldError naming "bbox", E-10).
func ViewportCells(box geodesy.BBox, maxCells int) (map[cell.ID]struct{}, error) {
	ids, err := cell.Viewport(box, maxCells)
	if err != nil {
		return nil, err
	}
	out := make(map[cell.ID]struct{}, len(ids))
	for _, c := range ids {
		out[c] = struct{}{}
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
