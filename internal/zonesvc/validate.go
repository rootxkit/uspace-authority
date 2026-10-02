package zonesvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// MaxDocumentBytes bounds one write or import (E-10): what uspace-core
// ed318.Parse and ed269.Parse accept by default (ed269.DefaultLimits).
var MaxDocumentBytes = ed269.DefaultLimits.MaxBytes

// reservedIdentifiers are path segments of /v1/zones and /v1/uspace that
// an identifier would shadow.
var reservedIdentifiers = map[string]bool{"export": true, "import": true, "publish": true}

// checked is one feature accepted by every check, with what is stored.
type checked struct {
	dataset    Dataset
	identifier string
	feature    json.RawMessage
	parsed     ed318.Feature
	columns    Columns
}

// rewriter maps a path of the wrapped document onto the caller's.
type rewriter func(string) string

// singleFeature rewrites the paths of a one-feature document onto the
// request's `feature` member.
func singleFeature(p string) string {
	switch {
	case p == "$" || p == "features" || p == "features[0]":
		return "feature"
	case strings.HasPrefix(p, "features[0]."):
		return "feature." + strings.TrimPrefix(p, "features[0].")
	}
	return p
}

// identity keeps the document's paths (an import names features[i]).
func identity(p string) string { return p }

// problemErrors turns parse problems into field errors, rewritten, with
// the count of those beyond the cap.
func problemErrors(p *ed269.Problems, rw rewriter) ([]*core.FieldError, int) {
	out := make([]*core.FieldError, 0, len(p.List))
	for _, pr := range p.List {
		out = append(out, &core.FieldError{Field: rw(pr.Field), Reason: pr.Reason})
	}
	return out, p.Truncated
}

// fieldOf names err's field under prefix, rewriting the one-feature
// document path "features[0]" that ToZones and FromED269 report.
func fieldOf(err error, prefix string) *core.FieldError {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		f := fe.Field
		switch {
		case f == "features[0]":
			f = prefix
		case strings.HasPrefix(f, "features[0]."):
			f = prefix + "." + strings.TrimPrefix(f, "features[0].")
		}
		return &core.FieldError{Field: f, Reason: fe.Reason}
	}
	return &core.FieldError{Field: prefix, Reason: err.Error()}
}

// asField is err's field error as reported, or one naming fallback.
func asField(err error, fallback string) *core.FieldError {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return &core.FieldError{Field: fe.Field, Reason: fe.Reason}
	}
	return &core.FieldError{Field: fallback, Reason: err.Error()}
}

// wrapFeature makes a one-feature ED-318 collection of raw.
func wrapFeature(raw []byte) []byte {
	b := make([]byte, 0, len(raw)+48)
	b = append(b, `{"type":"FeatureCollection","features":[`...)
	b = append(b, raw...)
	return append(b, "]}"...)
}

// checkDocument validates a whole ED-318 document whose every feature
// belongs to ds: uspace-core ed318.Parse (never repairing it, 06 T9),
// the dataset's type, an identifier that is not a path segment, and
// ed318.ToZones (every ring through geodesy.ValidRing, every limit
// judgeable, the applicability evaluable: Z-04, Z-06, Z-07). It returns
// every feature with its exact exported bytes and derived columns, or
// every problem (capped, with the count beyond).
func checkDocument(raw []byte, ds Dataset, rw rewriter) ([]checked, []*core.FieldError, int) {
	fc, probs := ed318.Parse(raw, ed318.Limits{})
	if probs != nil {
		errs, more := problemErrors(probs, rw)
		return nil, errs, more
	}
	return checkCollection(fc, ds, rw)
}

// checkCollection is checkDocument on a parsed collection.
func checkCollection(fc *ed318.FeatureCollection, ds Dataset, rw rewriter) ([]checked, []*core.FieldError, int) {
	exported, err := ed318.Export(fc)
	if err != nil {
		return nil, []*core.FieldError{fieldOf(err, rw("$"))}, 0
	}
	var w struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(exported, &w); err != nil || len(w.Features) != len(fc.Features) {
		return nil, []*core.FieldError{{Field: rw("$"), Reason: "the exported collection could not be read back"}}, 0
	}
	var errs []*core.FieldError
	out := make([]checked, 0, len(fc.Features))
	for i := range fc.Features {
		path := rw(fmt.Sprintf("features[%d]", i))
		c, fes := checkFeature(&fc.Features[i], w.Features[i], ds, path)
		errs = append(errs, fes...)
		if len(fes) == 0 {
			out = append(out, c)
		}
	}
	if len(errs) > 0 {
		capped, more := capErrors(errs)
		return nil, capped, more
	}
	return out, nil, 0
}

// capErrors keeps the first MaxProblems errors and counts the rest.
func capErrors(errs []*core.FieldError) ([]*core.FieldError, int) {
	limit := ed269.DefaultLimits.MaxProblems
	if len(errs) > limit {
		return errs[:limit], len(errs) - limit
	}
	return errs, 0
}

// datasetOf is the dataset a feature's type belongs to: USPACE is a
// U-space airspace, every other type a geo-zone.
func datasetOf(f *ed318.Feature) Dataset {
	if f.Properties.Type == core.ZoneUSpace {
		return DatasetUSpace
	}
	return DatasetZones
}

// checkFeature checks one feature of ds; an empty ds takes the
// feature's own (datasetOf).
func checkFeature(f *ed318.Feature, raw json.RawMessage, ds Dataset, path string) (checked, []*core.FieldError) {
	var errs []*core.FieldError
	p := &f.Properties
	if ds == "" {
		ds = datasetOf(f)
	}
	switch {
	case ds == DatasetZones && p.Type == core.ZoneUSpace:
		errs = append(errs, core.Fieldf(path+".properties.type", "USPACE is a U-space airspace: author it under /v1/uspace"))
	case ds == DatasetUSpace && p.Type != core.ZoneUSpace:
		errs = append(errs, core.Fieldf(path+".properties.type", "%q is not USPACE: a geo-zone is authored under /v1/zones", string(p.Type)))
	}
	if reservedIdentifiers[p.Identifier] {
		errs = append(errs, core.Fieldf(path+".properties.identifier", "%q is a path segment of the API; choose another identifier", p.Identifier))
	}
	one := &ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{*f}}
	if _, err := ed318.ToZones(one, structuralDaylight{}); err != nil {
		errs = append(errs, fieldOf(err, path))
	}
	if len(errs) > 0 {
		return checked{}, errs
	}
	cols, err := columnsOf(f, raw)
	if err != nil {
		return checked{}, []*core.FieldError{fieldOf(err, path)}
	}
	return checked{dataset: ds, identifier: p.Identifier, feature: raw, parsed: *f, columns: cols}, nil
}

// structuralDaylight lets ed318.ToZones run its structural checks on a
// schedule with daylight events (end dates present, at most
// MaxEventDays, windows well formed) when a zone is written. Its times
// are fixed hours of the day and the zones it yields are discarded:
// nothing is judged with them. Judgement and the applicability answers
// use the ground package's Daylight (NoDaylight until WP-11).
type structuralDaylight struct{}

// Event implements ed318.Daylight.
func (structuralDaylight) Event(name string, day time.Time, _ core.LatLon) (time.Time, error) {
	hour := map[string]int{ed318.EventBMCT: 5, ed318.EventSR: 6, ed318.EventSS: 18, ed318.EventEECT: 19}
	h, ok := hour[name]
	if !ok {
		return time.Time{}, fmt.Errorf("unknown daylight event %q", name)
	}
	return time.Date(day.Year(), day.Month(), day.Day(), h, 0, 0, 0, time.UTC), nil
}

// rawProperties are the members stored as JSON columns, taken from the
// exported feature so that each column is exactly the published value.
type rawProperties struct {
	Properties struct {
		Name                 json.RawMessage `json:"name"`
		OtherReasonInfo      json.RawMessage `json:"otherReasonInfo"`
		Message              json.RawMessage `json:"message"`
		LimitedApplicability json.RawMessage `json:"limitedApplicability"`
		ZoneAuthority        json.RawMessage `json:"zoneAuthority"`
		DataSource           json.RawMessage `json:"dataSource"`
		ExtendedProperties   json.RawMessage `json:"extendedProperties"`
	} `json:"properties"`
}

func nilIfEmpty(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return nil
	}
	return r
}

// geoJSONGeometry is a plain GeoJSON geometry for PostGIS: no layer, no
// extent (a circle part of a collection is its centre point).
type geoJSONGeometry struct {
	Type        string            `json:"type"`
	Coordinates any               `json:"coordinates,omitempty"`
	Geometries  []geoJSONGeometry `json:"geometries,omitempty"`
}

func plainGeometry(g *ed318.Geometry) geoJSONGeometry {
	switch g.Type {
	case ed318.GeometryPolygon:
		rings := make([][][2]float64, 0, len(g.Rings))
		for _, r := range g.Rings {
			ring := make([][2]float64, 0, len(r))
			for _, p := range r {
				ring = append(ring, [2]float64{p.LonDeg, p.LatDeg})
			}
			rings = append(rings, ring)
		}
		return geoJSONGeometry{Type: "Polygon", Coordinates: rings}
	case ed318.GeometryPoint:
		return geoJSONGeometry{Type: "Point", Coordinates: [2]float64{g.Center.LonDeg, g.Center.LatDeg}}
	}
	out := geoJSONGeometry{Type: "GeometryCollection", Geometries: []geoJSONGeometry{}}
	for i := range g.Geometries {
		out.Geometries = append(out.Geometries, plainGeometry(&g.Geometries[i]))
	}
	return out
}

// layerColumn is one part's vertical extent as the layers column holds
// it: metres in its reference, with the radius of a circle part.
type layerColumn struct {
	Part         int      `json:"part"`
	GeometryType string   `json:"geometry_type"`
	LowerM       *float64 `json:"lower_m,omitempty"`
	LowerRef     string   `json:"lower_ref,omitempty"`
	UpperM       *float64 `json:"upper_m,omitempty"`
	UpperRef     string   `json:"upper_ref,omitempty"`
	RadiusM      *float64 `json:"radius_m,omitempty"`
}

// layerExtra is one part's limits as published, unit included
// (ed318_extra: the original unit of every converted limit).
type layerExtra struct {
	Part  int      `json:"part"`
	Uom   string   `json:"uom"`
	Lower *float64 `json:"lower,omitempty"`
	Upper *float64 `json:"upper,omitempty"`
}

// parts are the geometry's parts with the layer that applies to each
// and the path of that layer.
func parts(g *ed318.Geometry) ([]ed318.Geometry, []string) {
	if g.Type != ed318.GeometryCollection {
		return []ed318.Geometry{*g}, []string{"geometry.layer"}
	}
	out := make([]ed318.Geometry, 0, len(g.Geometries))
	paths := make([]string, 0, len(g.Geometries))
	for i := range g.Geometries {
		m := g.Geometries[i]
		lp := fmt.Sprintf("geometry.geometries[%d].layer", i)
		if m.Layer == nil {
			m.Layer = g.Layer
			lp = "geometry.layer"
		}
		out = append(out, m)
		paths = append(paths, lp)
	}
	return out, paths
}

func columnsOf(f *ed318.Feature, raw json.RawMessage) (Columns, error) {
	var rp rawProperties
	if err := json.Unmarshal(raw, &rp); err != nil {
		return Columns{}, core.Fieldf("feature", "could not be read back: %v", err)
	}
	p := &f.Properties
	c := Columns{
		Country: p.Country, Type: string(p.Type), Variant: p.Variant, Reason: append([]string{}, p.Reason...),
		Name: nilIfEmpty(rp.Properties.Name), OtherReasonInfo: nilIfEmpty(rp.Properties.OtherReasonInfo),
		RestrictionConditions: p.RestrictionConditions, Region: p.Region, RegulationExemption: p.RegulationExemption,
		Message: nilIfEmpty(rp.Properties.Message), GeometryType: f.Geometry.Type,
		Limited: nilIfEmpty(rp.Properties.LimitedApplicability), ZoneAuthority: nilIfEmpty(rp.Properties.ZoneAuthority),
		DataSource: nilIfEmpty(rp.Properties.DataSource), Extended: nilIfEmpty(rp.Properties.ExtendedProperties),
		WGS84Fields: []string{},
	}
	if c.ZoneAuthority == nil {
		return Columns{}, core.Fieldf("feature.properties.zoneAuthority", "required")
	}
	if f.Geometry.Type == ed318.GeometryPoint {
		lon, lat, r := f.Geometry.Center.LonDeg, f.Geometry.Center.LatDeg, *f.Geometry.RadiusM
		c.CenterLonDeg, c.CenterLatDeg, c.RadiusM = &lon, &lat, &r
	} else {
		b, err := json.Marshal(plainGeometry(&f.Geometry))
		if err != nil {
			return Columns{}, err
		}
		s := string(b)
		c.GeometryGeoJSON = &s
	}
	ps, layerPaths := parts(&f.Geometry)
	layers := make([]layerColumn, 0, len(ps))
	extras := make([]layerExtra, 0, len(ps))
	seen := map[string]bool{}
	for k := range ps {
		g := &ps[k]
		lc := layerColumn{Part: k, GeometryType: g.Type, RadiusM: g.RadiusM}
		if l := g.Layer; l != nil {
			lc.LowerM, lc.LowerRef, lc.UpperM, lc.UpperRef = l.LowerM(), string(l.LowerReference), l.UpperM(), string(l.UpperReference)
			uom := ed318.UomMetres
			if l.Uom != nil {
				uom = *l.Uom
			}
			extras = append(extras, layerExtra{Part: k, Uom: uom, Lower: l.Lower, Upper: l.Upper})
			for _, w := range []struct {
				ref    core.VerticalRef
				member string
			}{{l.LowerReference, "lowerReference"}, {l.UpperReference, "upperReference"}} {
				field := layerPaths[k] + "." + w.member
				if w.ref == core.RefWGS84 && !seen[field] {
					seen[field] = true
					c.WGS84Fields = append(c.WGS84Fields, field)
				}
			}
		}
		layers = append(layers, lc)
	}
	if len(ps) == 1 {
		l := layers[0]
		c.LowerM, c.UpperM = l.LowerM, l.UpperM
		c.LowerRef, c.UpperRef = optional(l.LowerRef), optional(l.UpperRef)
	}
	var err error
	if c.Layers, err = json.Marshal(layers); err != nil {
		return Columns{}, err
	}
	if c.ED318Extra, err = json.Marshal(map[string]any{"layers": extras}); err != nil {
		return Columns{}, err
	}
	return c, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// checkPeriod refuses a version without a period of validity (2019/947
// Art. 15(3)) or with one that ends before it starts.
func checkPeriod(fromField, toField string, from, to *time.Time) []*core.FieldError {
	var errs []*core.FieldError
	if from == nil || from.IsZero() {
		errs = append(errs, core.Fieldf(fromField, "required: a zone has a period of validity (2019/947 Art. 15(3))"))
	}
	if to == nil || to.IsZero() {
		errs = append(errs, core.Fieldf(toField, "required: a zone has a period of validity (2019/947 Art. 15(3))"))
	}
	if len(errs) == 0 && !to.After(*from) {
		errs = append(errs, core.Fieldf(toField, "must be after %s", fromField))
	}
	return errs
}
