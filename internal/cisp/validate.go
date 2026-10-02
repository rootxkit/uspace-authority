package cisp

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// RequirementsKey is the extendedProperties member of a USPACE feature
// that carries cis/uspace_requirements/v1 (the CISP's Q32).
const RequirementsKey = "uspace_requirements"

// ReasonDAR is the ED-318 reason of a dynamic restriction: the ANSP's
// (F2), never in an authority publication.
const ReasonDAR = "DAR"

// servedMembers are the top-level members the CISP writes when it serves
// a dataset; a publication carrying them is refused (the UsspList
// schema's "served only", and the same for ED-318 collections).
var servedMembers = []string{"cis_dataset", "cis_version", "cis_updated_at", "cis_publisher_stale_since"}

// Checked is what CheckPublication found in an accepted payload.
type Checked struct {
	FeatureCount int
	// Collection is the parsed ED-318 collection (nil for ussp_list).
	Collection *ed318.FeatureCollection
}

// CheckPublication holds payload to what the CISP accepts for ds before
// anything is signed (spec 02 F1, 06 T9, accepted whole or refused
// whole): an ED-318 collection through ed318.Parse and the CISP's
// dataset rules (no USPACE in zones, only USPACE in uspace_airspace, no
// DAR reason, unique identifiers, the cis/uspace_requirements/v1 block
// on every USPACE feature, validated against the pinned schema); the
// USSP list against the pinned cis/ussp_list/v1 with unique ussp_id.
// Neither may carry the members the CISP writes when serving. It
// returns every problem by JSON path and how many more were found than
// the problems list holds.
func (s *Schemas) CheckPublication(ds Dataset, payload []byte) (Checked, []*core.FieldError, int) {
	if !ds.Publishable() {
		return Checked{}, []*core.FieldError{core.Fieldf("dataset", "%q is not published by the authority", ds)}, 0
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return Checked{}, []*core.FieldError{core.Fieldf("$", "not a JSON object")}, 0
	}
	var probs []*core.FieldError
	for _, m := range servedMembers {
		if _, ok := top[m]; ok {
			probs = append(probs, core.Fieldf(m, "written by the CISP when it serves the dataset; refused in a publication"))
		}
	}
	if ds == DatasetUSSPList {
		probs = append(probs, s.Validate(SchemaUSSPList, payload, "")...)
		n, more := usspProblems(top)
		probs = append(probs, more...)
		if len(probs) > 0 {
			return Checked{}, probs, 0
		}
		return Checked{FeatureCount: n}, nil, 0
	}
	fc, pp := ed318.Parse(payload, ed318.Limits{})
	if pp != nil {
		for _, p := range pp.List {
			probs = append(probs, &core.FieldError{Field: p.Field, Reason: p.Reason})
		}
		return Checked{}, probs, pp.Truncated
	}
	seen := map[string]int{}
	for i := range fc.Features {
		p := &fc.Features[i].Properties
		at := fmt.Sprintf("features[%d].properties", i)
		switch {
		case ds == DatasetZones && p.Type == core.ZoneUSpace:
			probs = append(probs, core.Fieldf(at+".type", "USPACE is published in the uspace_airspace dataset, not zones"))
		case ds == DatasetUSpace && p.Type != core.ZoneUSpace:
			probs = append(probs, core.Fieldf(at+".type", "only USPACE is published in the uspace_airspace dataset"))
		}
		if slices.Contains(p.Reason, ReasonDAR) {
			probs = append(probs, core.Fieldf(at+".reason", "DAR is a dynamic restriction, published by the ANSP"))
		}
		if j, dup := seen[p.Identifier]; dup {
			probs = append(probs, core.Fieldf(at+".identifier", "%q is also features[%d]", p.Identifier, j))
		} else {
			seen[p.Identifier] = i
		}
		if p.Type == core.ZoneUSpace {
			block, ok := p.ExtendedProperties[RequirementsKey]
			if !ok {
				probs = append(probs, core.Fieldf(at+".extendedProperties."+RequirementsKey, "required on a USPACE feature (%s)", SchemaUSpaceRequirements))
				continue
			}
			probs = append(probs, s.Validate(SchemaUSpaceRequirements, block, at+".extendedProperties."+RequirementsKey)...)
		}
	}
	if len(probs) > 0 {
		return Checked{}, probs, 0
	}
	return Checked{FeatureCount: len(fc.Features), Collection: fc}, nil, 0
}

// usspProblems counts the USSPs of a list and refuses a repeated ussp_id
// (the schema cannot say it).
func usspProblems(top map[string]json.RawMessage) (int, []*core.FieldError) {
	var list []struct {
		USSPID string `json:"ussp_id"`
	}
	if err := json.Unmarshal(top["ussps"], &list); err != nil {
		return 0, nil // the schema already named it
	}
	var probs []*core.FieldError
	seen := map[string]int{}
	for i, u := range list {
		if u.USSPID == "" {
			continue
		}
		if j, dup := seen[u.USSPID]; dup {
			probs = append(probs, core.Fieldf(fmt.Sprintf("ussps[%d].ussp_id", i), "%q is also ussps[%d]", u.USSPID, j))
			continue
		}
		seen[u.USSPID] = i
	}
	return len(list), probs
}
