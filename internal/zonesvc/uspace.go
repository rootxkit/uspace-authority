package zonesvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// RequirementsKey is the extendedProperties member of a USPACE feature
// that holds the 2021/664 Art. 3(4) block, in the CISP's
// cis/uspace_requirements/v1 shape (the CISP owns the schema, M7; its
// PLAN §15 Q32 names the member).
const RequirementsKey = "uspace_requirements"

// The U-space services of Art. 3(3): the four always required and the
// two optional.
var (
	servicesAlways  = []string{"NID", "GEO", "FA", "TI"}
	servicesAllowed = []string{"NID", "GEO", "FA", "TI", "WX", "CM"}
)

// Bounds of the designation's members (cis/uspace_requirements/v1 and
// the uspace_airspaces columns).
const (
	maxAdjacent     = 1000
	maxIdentifierCh = 7
	maxNameCh       = 200
	maxRefCh        = 200
	maxIDCh         = 64
	// maxBlockBytes bounds the Art. 3(4) block (E-10).
	maxBlockBytes = 64 << 10
)

// requirements is the cis/uspace_requirements/v1 block, members in the
// schema's order.
type requirements struct {
	UASRequirements       json.RawMessage `json:"uas_requirements"`
	ServicePerformance    json.RawMessage `json:"service_performance"`
	OperationalConditions json.RawMessage `json:"operational_conditions"`
	AirspaceConstraints   json.RawMessage `json:"airspace_constraints"`
	ServicesRequired      []string        `json:"services_required"`
	Adjacent              []string        `json:"adjacent"`
}

func textField(field, s string, maxCh int, required bool) *core.FieldError {
	n := utf8.RuneCountInString(s)
	switch {
	case required && n == 0:
		return core.Fieldf(field, "required")
	case n > maxCh:
		return core.Fieldf(field, "longer than %d characters", maxCh)
	}
	return nil
}

// objectOf decodes raw as a JSON object, naming field when it is not.
func objectOf(field string, raw json.RawMessage) (map[string]json.RawMessage, *core.FieldError) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, core.Fieldf(field, "required")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, core.Fieldf(field, "must be a JSON object")
	}
	return m, nil
}

// positiveNumber checks member key of m: a finite number above zero,
// required when required is set.
func positiveNumber(field string, m map[string]json.RawMessage, key string, required bool) *core.FieldError {
	raw, ok := m[key]
	if !ok {
		if required {
			return core.Fieldf(field+"."+key, "required")
		}
		return nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return core.Fieldf(field+"."+key, "must be a number above 0")
	}
	return nil
}

// checkDesignation validates a designation against the CISP's
// cis/uspace_requirements/v1 (required members, the service list, the
// three performance numbers, the height ceiling, adjacent identifiers)
// and the uspace_airspaces columns' bounds. self is the airspace's own
// identifier, which adjacent may not name.
func checkDesignation(d *Designation, self, path string) []*core.FieldError {
	var errs []*core.FieldError
	add := func(fe *core.FieldError) {
		if fe != nil {
			errs = append(errs, fe)
		}
	}
	add(textField(path+".airspace_name", d.Name, maxNameCh, true))
	add(textField(path+".risk_assessment_ref", d.RiskAssessmentRef, maxRefCh, false))
	add(textField(path+".designation_ref", d.DesignationRef, maxRefCh, false))
	add(textField(path+".aip_ref", d.AIPRef, maxRefCh, false))
	add(textField(path+".ats_provider_id", d.ATSProviderID, maxIDCh, false))
	add(textField(path+".cisp_id", d.CISPID, maxIDCh, false))

	seen := map[string]bool{}
	for i, s := range d.ServicesRequired {
		switch {
		case !slices.Contains(servicesAllowed, s):
			add(core.Fieldf(fmt.Sprintf("%s.services_required[%d]", path, i), "%q is not one of NID, GEO, FA, TI, WX, CM", s))
		case seen[s]:
			add(core.Fieldf(fmt.Sprintf("%s.services_required[%d]", path, i), "%q is listed twice", s))
		}
		seen[s] = true
	}
	for _, s := range servicesAlways {
		if !seen[s] {
			add(core.Fieldf(path+".services_required", "must include %s: NID, GEO, FA and TI are always required (2021/664 Art. 3(3))", s))
		}
	}
	if _, fe := objectOf(path+".uas_requirements", d.UASRequirements); fe != nil {
		add(fe)
	}
	if _, fe := objectOf(path+".operational_conditions", d.OperationalConditions); fe != nil {
		add(fe)
	}
	if m, fe := objectOf(path+".service_performance", d.ServicePerformance); fe != nil {
		add(fe)
	} else {
		for _, k := range []string{"nid_update_hz", "ti_update_hz", "cis_latency_s"} {
			add(positiveNumber(path+".service_performance", m, k, true))
		}
	}
	if m, fe := objectOf(path+".airspace_constraints", d.AirspaceConstraints); fe != nil {
		add(fe)
	} else {
		add(positiveNumber(path+".airspace_constraints", m, "max_height_agl_m", false))
	}
	if len(d.AdjacentIDs) > maxAdjacent {
		add(core.Fieldf(path+".adjacent_ids", "more than %d entries", maxAdjacent))
	}
	adj := map[string]bool{}
	for i, a := range d.AdjacentIDs {
		f := fmt.Sprintf("%s.adjacent_ids[%d]", path, i)
		switch n := utf8.RuneCountInString(a); {
		case n == 0 || n > maxIdentifierCh:
			add(core.Fieldf(f, "must be an identifier of 1 to %d characters", maxIdentifierCh))
		case a == self:
			add(core.Fieldf(f, "names the airspace itself"))
		case adj[a]:
			add(core.Fieldf(f, "%q is listed twice", a))
		}
		adj[a] = true
	}
	return errs
}

// compactJSON is raw without insignificant white space.
func compactJSON(raw json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return raw
	}
	return b.Bytes()
}

// requirementsBlock is the cis/uspace_requirements/v1 object of d.
func requirementsBlock(d *Designation) (json.RawMessage, error) {
	adj := d.AdjacentIDs
	if adj == nil {
		adj = []string{}
	}
	b, err := json.Marshal(requirements{
		UASRequirements: compactJSON(d.UASRequirements), ServicePerformance: compactJSON(d.ServicePerformance),
		OperationalConditions: compactJSON(d.OperationalConditions), AirspaceConstraints: compactJSON(d.AirspaceConstraints),
		ServicesRequired: d.ServicesRequired, Adjacent: adj,
	})
	if err != nil {
		return nil, err
	}
	if len(b) > maxBlockBytes {
		return nil, core.Fieldf("designation", "the Art. 3(4) block is %d bytes; at most %d", len(b), maxBlockBytes)
	}
	return b, nil
}

// withRequirements returns the one-feature document raw with the
// designation's block written into extendedProperties under
// RequirementsKey. A feature that carries the member already is
// refused: the block is written from the designation only, so the two
// can never disagree.
func withRequirements(raw []byte, d *Designation) ([]byte, []*core.FieldError, int) {
	fc, probs := ed318.Parse(wrapFeature(raw), ed318.Limits{})
	if probs != nil {
		errs, more := problemErrors(probs, singleFeature)
		return nil, errs, more
	}
	if len(fc.Features) != 1 {
		return nil, []*core.FieldError{core.Fieldf("feature", "must be one ED-318 feature")}, 0
	}
	p := &fc.Features[0].Properties
	if _, ok := p.ExtendedProperties[RequirementsKey]; ok {
		return nil, []*core.FieldError{core.Fieldf("feature.properties.extendedProperties."+RequirementsKey,
			"is written from designation; leave it out of the feature")}, 0
	}
	block, err := requirementsBlock(d)
	if err != nil {
		return nil, []*core.FieldError{fieldOf(err, "designation")}, 0
	}
	if p.ExtendedProperties == nil {
		p.ExtendedProperties = map[string]json.RawMessage{}
	}
	p.ExtendedProperties[RequirementsKey] = block
	out, err := ed318.Export(fc)
	if err != nil {
		return nil, []*core.FieldError{fieldOf(err, "feature")}, 0
	}
	return out, nil, 0
}

// adjacentOf reads the adjacent identifiers of a stored USPACE feature.
func adjacentOf(feature json.RawMessage) ([]string, error) {
	var w struct {
		Properties struct {
			ExtendedProperties map[string]json.RawMessage `json:"extendedProperties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(feature, &w); err != nil {
		return nil, err
	}
	raw, ok := w.Properties.ExtendedProperties[RequirementsKey]
	if !ok {
		return nil, nil
	}
	var r requirements
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return r.Adjacent, nil
}
