package zonesvc

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
)

// airspace.gov.ge (LESSONS Z-13) serves no data feed, only a Leaflet page
// whose zones are JavaScript variables in /Airspace/leaflet/zone/points.js:
//
//	var UGTB_CTR_points = [[41.875, 44.9083], ...];   // a polygon, [lat, lon]
//	var UGKO_CTR_point = [42.1766667, 42.4825];        // a circle's centre
//
// A circle's radius is in the page itself, in its L.circle(UGKO_CTR_point,
// {radius: 11112, ...}) call, in metres. The kind of a zone is the last
// `_` part of its variable name (CTR, TMA, ATZ, EPR, ...). Nothing says
// what restriction a zone carries, between which heights or when: those
// come from the authority's rules file (GovGeRules), and a kind without a
// rule refuses the conversion by name. The geometry is taken as it is.
// The format was read from the predecessor (utm airspace/gov_ge.py, read
// only on 2026-10-01); this code never fetches the site.

var (
	govGeVariable = regexp.MustCompile(`var\s+([A-Za-z0-9_]+?)_(points|point)\s*=\s*(\[[\s\S]*?\])\s*;`)
	govGeCircle   = regexp.MustCompile(`L\.circle\(\s*([A-Za-z0-9_]+?)_point\s*,\s*\{[^}]*?radius\s*:\s*([0-9]+(?:\.[0-9]+)?)`)
)

// maxGovGeShapes bounds the zones one conversion makes (E-10).
const maxGovGeShapes = 10000

// GovGeKind is what the authority says one kind of zone is. Every value
// goes into the ED-269 zone as given; nothing has a default, since each
// decides alerts. A missing limit is unbounded, as in ED-269.
type GovGeKind struct {
	Restriction    string
	Uom            string
	LowerReference string
	UpperReference string
	LowerLimit     *float64
	UpperLimit     *float64
	// Applicability is the ED-269 applicability list, as an ED-269 file
	// publishes it.
	Applicability []json.RawMessage
	Reason        []string
	Message       *string
}

// GovGeRules is the authority's rules file (docs/runbooks/zones.md).
type GovGeRules struct {
	Country string
	// Authority is the ED-269 zoneAuthority entry every zone names.
	Authority map[string]string
	Kinds     map[string]GovGeKind
	// Identifiers maps a variable name onto its ED-269 identifier, for
	// names longer than seven characters once the `_` are dropped.
	Identifiers map[string]string
}

// govGeShape is one zone as the site draws it.
type govGeShape struct {
	name    string
	kind    string
	ring    [][2]float64 // [lon, lat]
	center  *[2]float64  // [lon, lat]
	isPoint bool
}

func isNumberPair(v []any) bool {
	if len(v) != 2 {
		return false
	}
	for _, x := range v {
		f, ok := x.(float64)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
	}
	return true
}

// parseGovGePoints reads the zones of a points.js.
func parseGovGePoints(text string) ([]govGeShape, []*core.FieldError) {
	var shapes []govGeShape
	var errs []*core.FieldError
	for _, m := range govGeVariable.FindAllStringSubmatch(text, maxGovGeShapes+1) {
		if len(shapes) == maxGovGeShapes {
			return nil, []*core.FieldError{core.Fieldf("points_js", "more than %d zones", maxGovGeShapes)}
		}
		name, form, value := m[1], m[2], m[3]
		field := "points_js." + name
		kind := name
		if i := strings.LastIndex(name, "_"); i >= 0 {
			kind = name[i+1:]
		}
		var v any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			errs = append(errs, core.Fieldf(field, "is not a list of numbers"))
			continue
		}
		list, _ := v.([]any)
		if form == "point" {
			if !isNumberPair(list) {
				errs = append(errs, core.Fieldf(field, "a point must be [lat, lon]"))
				continue
			}
			c := [2]float64{list[1].(float64), list[0].(float64)}
			shapes = append(shapes, govGeShape{name: name, kind: kind, center: &c, isPoint: true})
			continue
		}
		ring := make([][2]float64, 0, len(list))
		ok := len(list) > 0
		for _, p := range list {
			pair, _ := p.([]any)
			if !isNumberPair(pair) {
				ok = false
				break
			}
			ring = append(ring, [2]float64{pair[1].(float64), pair[0].(float64)})
		}
		if !ok {
			errs = append(errs, core.Fieldf(field, "a polygon must be a list of [lat, lon]"))
			continue
		}
		if ring[0] != ring[len(ring)-1] {
			ring = append(ring, ring[0])
		}
		shapes = append(shapes, govGeShape{name: name, kind: kind, ring: ring})
	}
	return shapes, errs
}

// parseGovGeRadii reads each circle's radius in metres from the page.
func parseGovGeRadii(page string) map[string]float64 {
	out := map[string]float64{}
	for _, m := range govGeCircle.FindAllStringSubmatch(page, maxGovGeShapes) {
		if r, err := strconv.ParseFloat(m[2], 64); err == nil {
			out[m[1]] = r
		}
	}
	return out
}

// GovGeToED269 converts saved copies of points.js and the page into an
// ED-269 document under rules, checked by ed269.Parse before it is
// returned. It refuses, naming each zone, a kind with no rule, a circle
// with no radius and an identifier longer than ED-269 allows; nothing is
// converted unless everything is.
func GovGeToED269(pointsJS, page string, rules *GovGeRules) ([]byte, []*core.FieldError) {
	if len(pointsJS) > MaxDocumentBytes || len(page) > MaxDocumentBytes {
		return nil, []*core.FieldError{core.Fieldf("points_js", "points_js and page_html are each at most %d bytes", MaxDocumentBytes)}
	}
	shapes, errs := parseGovGePoints(pointsJS)
	if len(shapes) == 0 && len(errs) == 0 {
		errs = append(errs, core.Fieldf("points_js", "no zone variable (var NAME_points or var NAME_point) found"))
	}
	radii := parseGovGeRadii(page)
	features := make([]map[string]any, 0, len(shapes))
	for _, s := range shapes {
		field := "points_js." + s.name
		rule, ok := rules.Kinds[s.kind]
		if !ok {
			errs = append(errs, core.Fieldf(field, "kind %q has no rule in the rules file", s.kind))
			continue
		}
		identifier, ok := rules.Identifiers[s.name]
		if !ok {
			identifier = strings.ReplaceAll(s.name, "_", "")
		}
		if utf8.RuneCountInString(identifier) > ed269.DefaultLimits.IdentifierMax {
			errs = append(errs, core.Fieldf(field, "identifier %q is longer than %d; give one under identifiers in the rules file",
				identifier, ed269.DefaultLimits.IdentifierMax))
			continue
		}
		var projection map[string]any
		if s.isPoint {
			radiusM, ok := radii[s.name]
			if !ok {
				errs = append(errs, core.Fieldf(field, "a circle with no radius in the page"))
				continue
			}
			// The page gives metres; ED-269 gives the radius in the
			// volume's unit.
			radius := radiusM
			if rule.Uom == "FT" {
				radius = radiusM / core.FeetToMetres
			}
			projection = map[string]any{"type": "Circle", "center": []float64{s.center[0], s.center[1]}, "radius": radius}
		} else {
			projection = map[string]any{"type": "Polygon", "coordinates": [][][2]float64{s.ring}}
		}
		volume := map[string]any{
			"uomDimensions": rule.Uom, "lowerVerticalReference": rule.LowerReference,
			"upperVerticalReference": rule.UpperReference, "horizontalProjection": projection,
		}
		if rule.LowerLimit != nil {
			volume["lowerLimit"] = *rule.LowerLimit
		}
		if rule.UpperLimit != nil {
			volume["upperLimit"] = *rule.UpperLimit
		}
		authority := []map[string]string{}
		if len(rules.Authority) > 0 {
			authority = append(authority, rules.Authority)
		}
		feature := map[string]any{
			"identifier": identifier, "country": rules.Country, "name": s.name, "type": "COMMON",
			"restriction": rule.Restriction, "applicability": rule.Applicability, "zoneAuthority": authority,
			"geometry":           []map[string]any{volume},
			"extendedProperties": map[string]string{"source": "airspace.gov.ge", "kind": s.kind},
		}
		if rule.Reason != nil {
			feature["reason"] = rule.Reason
		}
		if rule.Message != nil {
			feature["message"] = *rule.Message
		}
		features = append(features, feature)
	}
	if len(errs) > 0 {
		sort.SliceStable(errs, func(i, j int) bool { return errs[i].Field < errs[j].Field })
		return nil, errs
	}
	doc, err := json.Marshal(map[string]any{"title": "airspace.gov.ge zones", "features": features})
	if err != nil {
		return nil, []*core.FieldError{core.Fieldf("rules", "the converted document is not encodable: %v", err)}
	}
	if _, probs := ed269.Parse(doc, ed269.Limits{}); probs != nil {
		out, _ := problemErrors(probs, func(p string) string { return fmt.Sprintf("converted.%s", p) })
		return nil, out
	}
	return doc, nil
}
