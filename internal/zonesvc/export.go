package zonesvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geodesy"
)

// ApplicabilityKey is the extendedProperties member an export annotates
// with Applies, NotApplicable or Unknown (M17, the CISP's name).
const ApplicabilityKey = "cis_applicability"

// ErrDaylightUnavailable is the error of NoDaylight.
var ErrDaylightUnavailable = errors.New("daylight events cannot be resolved: no sunrise and sunset source is available")

// SlugDaylight is the problem slug of a question that needs a daylight
// event while none can be resolved.
const SlugDaylight = "daylight_unavailable"

// NoDaylight is a daylight source that is not available: it refuses
// every event, naming it, so a zone scheduled by daylight is reported as
// not evaluated, never guessed (ed318.Applies then answers "not
// evaluated"). The source the service and the reader use is
// ground.Daylight (core's ed318.NOAADaylight, WP-11); NoDaylight is what
// a caller sets to take it away.
type NoDaylight struct{}

// Event implements ed318.Daylight.
func (NoDaylight) Event(name string, _ time.Time, _ core.LatLon) (time.Time, error) {
	return time.Time{}, fmt.Errorf("%s: %w", name, ErrDaylightUnavailable)
}

// maxExportBytes bounds the collection an export reads back. A
// publication is held to MaxDocumentBytes (what the CISP's parser
// accepts); a console export may be larger.
const maxExportBytes = 64 << 20

// collect parses the stored features as one ED-318 collection. Every
// feature was accepted when it was written; a failure here is a store
// that holds something else, an internal error naming the problem.
func collect(features []json.RawMessage) (*ed318.FeatureCollection, error) {
	n := 64
	for _, f := range features {
		n += len(f) + 1
	}
	doc := make([]byte, 0, n)
	doc = append(doc, `{"type":"FeatureCollection","features":[`...)
	for i, f := range features {
		if i > 0 {
			doc = append(doc, ',')
		}
		doc = append(doc, f...)
	}
	doc = append(doc, "]}"...)
	fc, probs := ed318.Parse(doc, ed318.Limits{MaxBytes: maxExportBytes})
	if probs != nil {
		return nil, fmt.Errorf("stored zones do not parse as one ED-318 collection: %w", probs)
	}
	return fc, nil
}

// featureCentre is where a feature's applicability is evaluated: the
// centre of its bounding box.
func featureCentre(f *ed318.Feature) core.LatLon {
	lat, lon := featureBBox(f).Centre()
	return core.LatLon{LatDeg: lat, LonDeg: lon}
}

// featureBBox is the union of the uspace-core geodesy boxes of the
// feature's parts (ed318.Parse refuses a shape across the antimeridian,
// so a plain union is the box).
func featureBBox(f *ed318.Feature) BBox {
	ps, _ := parts(&f.Geometry)
	var b BBox
	for i := range ps {
		var gb geodesy.BBox
		switch g := &ps[i]; g.Type {
		case ed318.GeometryPolygon:
			poly := geodesy.Polygon{Rings: make([]geodesy.Ring, 0, len(g.Rings))}
			for _, r := range g.Rings {
				poly.Rings = append(poly.Rings, geodesy.Ring(r))
			}
			gb = poly.BBox()
		case ed318.GeometryPoint:
			if g.Center == nil || g.RadiusM == nil {
				continue
			}
			gb = geodesy.Circle{Center: *g.Center, RadiusM: *g.RadiusM}.BBox()
		}
		if i == 0 {
			b = BBox{MinLatDeg: gb.MinLat, MinLonDeg: gb.MinLon, MaxLatDeg: gb.MaxLat, MaxLonDeg: gb.MaxLon}
			continue
		}
		b.MinLatDeg, b.MinLonDeg = min(b.MinLatDeg, gb.MinLat), min(b.MinLonDeg, gb.MinLon)
		b.MaxLatDeg, b.MaxLonDeg = max(b.MaxLatDeg, gb.MaxLat), max(b.MaxLonDeg, gb.MaxLon)
	}
	return b
}

// FieldLimitedApplicability is where a feature's applicability lives,
// and so where its period of validity is published.
const FieldLimitedApplicability = "properties.limitedApplicability"

// withinValidity bounds f's applicability by its version's period of
// validity (valid_from to valid_to, both included; 2019/947 Art. 15(3)),
// the only form in which an ED-318 feature carries it: ED-318 has no
// other per-zone validity member, and the collection's metadata
// validFrom and validTo belong to the dataset, not to a zone (spec 02
// F1; 03 §1 geo_zones). A feature without limitedApplicability is given
// the one TimePeriod {startDateTime: valid_from, endDateTime:
// valid_to}; each TimePeriod of one with limitedApplicability has its
// startDateTime and endDateTime clipped to the period, its schedule
// kept, and is dropped when nothing of it is left. Without this a
// published zone carries no end, and every consumer (the CISP, a USSP,
// the public map) shows it in force for ever.
//
// A feature none of whose periods meets its period of validity never
// applies; ED-318 cannot say that (no limitedApplicability means
// "always"), so it is an error naming the field, never an empty list.
func withinValidity(f *ed318.Feature, from, to time.Time) error {
	from, to = from.UTC(), to.UTC()
	tps := f.Properties.LimitedApplicability
	if len(tps) == 0 {
		f.Properties.LimitedApplicability = []ed318.TimePeriod{{StartDateTime: &ed318.DateTime{Time: from}, EndDateTime: &ed318.DateTime{Time: to}}}
		return nil
	}
	out := make([]ed318.TimePeriod, 0, len(tps))
	for _, tp := range tps {
		if tp.StartDateTime == nil || tp.StartDateTime.Time.Before(from) {
			tp.StartDateTime = &ed318.DateTime{Time: from}
		}
		if tp.EndDateTime == nil || tp.EndDateTime.Time.After(to) {
			tp.EndDateTime = &ed318.DateTime{Time: to}
		}
		if tp.StartDateTime.Time.Before(tp.EndDateTime.Time) {
			out = append(out, tp)
		}
	}
	if len(out) == 0 {
		return core.Fieldf(FieldLimitedApplicability, "no time period meets the period of validity %s to %s, so the zone would never apply",
			from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	f.Properties.LimitedApplicability = out
	return nil
}

// applicabilityOf answers whether f applies at at, through uspace-core
// ed318.Applies at the feature's centre: Unknown with the reason when
// it cannot be evaluated, never a guess.
func applicabilityOf(f *ed318.Feature, at time.Time, dl ed318.Daylight) (Applicability, error) {
	ok, err := ed318.Applies(f.Properties.LimitedApplicability, at, featureCentre(f), dl)
	switch {
	case err != nil:
		return Unknown, err
	case ok:
		return Applies, nil
	}
	return NotApplicable, nil
}

// ExportMode says what an export does with applicability.
type ExportMode int

// The export modes (M17).
const (
	// ExportAll keeps every feature as published.
	ExportAll ExportMode = iota
	// ExportFilter keeps the features that apply at the instant and
	// those that cannot be evaluated (annotated unknown), and leaves out
	// the ones that do not apply.
	ExportFilter
	// ExportAnnotate keeps every feature and annotates each.
	ExportAnnotate
)

// buildExport writes the ED-318 collection of the versions with meta,
// each feature bounded by its version's period of validity
// (withinValidity), filtered or annotated at at as mode says, through
// ed318.Export. A version whose applicability never meets its period of
// validity refuses the export 409, naming it.
func buildExport(set []Version, meta ed318.Metadata, mode ExportMode, at time.Time, dl ed318.Daylight) ([]byte, int, error) {
	fc, err := collect(featuresOf(set))
	if err != nil {
		return nil, 0, err
	}
	for i := range fc.Features {
		if err := withinValidity(&fc.Features[i], set[i].ValidFrom, set[i].ValidTo); err != nil {
			var fe *core.FieldError
			if errors.As(err, &fe) {
				fe = core.Fieldf(fmt.Sprintf("%s@%d.feature.%s", set[i].Identifier, set[i].ZoneVersion, fe.Field), "%s", fe.Reason)
			}
			return nil, 0, conflict("a zone version never applies within its period of validity; replace it before publishing", fe)
		}
	}
	if mode != ExportAll {
		kept := fc.Features[:0]
		for i := range fc.Features {
			f := fc.Features[i]
			a, _ := applicabilityOf(&f, at, dl)
			if mode == ExportFilter && a == NotApplicable {
				continue
			}
			if mode == ExportAnnotate || a == Unknown {
				ext := make(map[string]json.RawMessage, len(f.Properties.ExtendedProperties)+1)
				for k, v := range f.Properties.ExtendedProperties {
					ext[k] = v
				}
				ext[ApplicabilityKey] = json.RawMessage(`"` + string(a) + `"`)
				f.Properties.ExtendedProperties = ext
			}
			kept = append(kept, f)
		}
		fc.Features = kept
	}
	m := meta
	fc.Metadata = &m
	out, err := ed318.Export(fc)
	if err != nil {
		return nil, 0, err
	}
	return out, len(fc.Features), nil
}
