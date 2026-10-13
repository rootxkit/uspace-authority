package zonesvc

import (
	"context"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/outline"
)

// GetCircleOutline answers GET /v1/outlines/circle: the circle drawn for
// the zone editors' map (internal/outline; docs/PLAN.md section 14 Q55).
// Pure: it reads no store, writes and audits nothing, and a centre or
// radius out of bounds is a 400 naming the field before anything is
// computed (httpx.ProblemFromError).
func (h Handler) GetCircleOutline(_ context.Context, req gen.GetCircleOutlineRequestObject) (gen.GetCircleOutlineResponseObject, error) {
	ring, err := outline.Circle(core.LatLon{LatDeg: req.Params.Lat, LonDeg: req.Params.Lng}, req.Params.RadiusM)
	if err != nil {
		return nil, err
	}
	coords := make([][]float64, len(ring))
	for i, p := range ring {
		coords[i] = []float64{p[0], p[1]}
	}
	var out gen.CircleOutline
	out.Outline.Type = gen.CircleOutlineOutlineTypePolygon
	out.Outline.Coordinates = [][][]float64{coords}
	out.Vertices = outline.Vertices
	return gen.GetCircleOutline200JSONResponse(out), nil
}
