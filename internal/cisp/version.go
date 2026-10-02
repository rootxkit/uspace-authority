package cisp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
)

// RestrictionKey is the extendedProperties member the CISP adds to a
// served restriction feature (CisRestriction: id, ansp_ref, state,
// window).
const RestrictionKey = "cis_restriction"

// Version is one dataset version as the CISP served it, validated.
type Version struct {
	Dataset   Dataset
	Number    int64
	ETag      string
	UpdatedAt *time.Time
	// Body is the collection or list as served (or as merged from a
	// delta), the payload cis_cache holds.
	Body json.RawMessage
	// Features are the ED-318 features in order, each as served.
	Features []Feature
	// USSPs is the size of the USSP list.
	USSPs int
	// Delta is true when Body was merged from a delta.
	Delta bool
}

// FeatureCount is the number of features, or of USSPs in the list.
func (v *Version) FeatureCount() int {
	if v.Dataset.ED318() {
		return len(v.Features)
	}
	return v.USSPs
}

// Feature is one ED-318 feature as served, with the restriction block of
// a restrictions feature.
type Feature struct {
	Identifier  string
	Raw         json.RawMessage
	Restriction *cispclient.CisRestriction
}

// RefusalError is a version refused whole on receipt (spec 06 T9): the
// previous version stays.
type RefusalError struct {
	Dataset  Dataset
	Version  int64
	First    string
	Problems int
}

func (r *RefusalError) Error() string {
	return fmt.Sprintf("%s version %d refused (%d problems): %s", r.Dataset, r.Version, r.Problems, r.First)
}

// ParseVersion validates a served dataset body, never repairing it: an
// ED-318 collection through ed318.Parse (and, for restrictions, the
// CISP's cis_restriction block on every feature), the USSP list through
// the pinned cis/ussp_list/v1. The version is the body's cis_version,
// else X-CIS-Version; a body naming another dataset is refused.
func ParseVersion(s *Schemas, d Dataset, body []byte, etag string, headerVersion int64) (*Version, *RefusalError) {
	refuse := func(v int64, n int, format string, a ...any) (*Version, *RefusalError) {
		return nil, &RefusalError{Dataset: d, Version: v, First: fmt.Sprintf(format, a...), Problems: n}
	}
	var top struct {
		Dataset   *string           `json:"cis_dataset"`
		Version   *json.Number      `json:"cis_version"`
		UpdatedAt *time.Time        `json:"cis_updated_at"`
		Features  []json.RawMessage `json:"features"`
		USSPs     []json.RawMessage `json:"ussps"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return refuse(headerVersion, 1, "$: not a JSON object with the CISP's members (%s)", short(err.Error()))
	}
	version := headerVersion
	if top.Version != nil {
		n, err := strconv.ParseInt(top.Version.String(), 10, 64)
		if err != nil || n < 0 {
			return refuse(headerVersion, 1, "cis_version: not a version")
		}
		if headerVersion != 0 && n != headerVersion {
			return refuse(n, 1, "cis_version: %d, %s says %d", n, HeaderCISVersion, headerVersion)
		}
		version = n
	}
	if version <= 0 {
		return refuse(0, 1, "cis_version: absent; the version cannot be named")
	}
	if top.Dataset != nil && *top.Dataset != string(d) {
		return refuse(version, 1, "cis_dataset: %q, read as %s", short(*top.Dataset), d)
	}
	if etag == "" {
		etag = ETagOf(d, version)
	}
	v := &Version{Dataset: d, Number: version, ETag: etag, UpdatedAt: top.UpdatedAt, Body: body}
	if !d.ED318() {
		if probs := s.Validate(SchemaUSSPList, body, ""); len(probs) > 0 {
			return refuse(version, len(probs), "%s: %s", probs[0].Field, probs[0].Reason)
		}
		v.USSPs = len(top.USSPs)
		return v, nil
	}
	fc, pp := ed318.Parse(body, ed318.Limits{})
	if pp != nil {
		first := "$: refused"
		if len(pp.List) > 0 {
			first = pp.List[0].Field + ": " + pp.List[0].Reason
		}
		return refuse(version, len(pp.List)+pp.Truncated, "%s", first)
	}
	if len(top.Features) != len(fc.Features) {
		return refuse(version, 1, "features: %d read, %d parsed", len(top.Features), len(fc.Features))
	}
	v.Features = make([]Feature, len(fc.Features))
	for i := range fc.Features {
		p := &fc.Features[i].Properties
		f := Feature{Identifier: p.Identifier, Raw: top.Features[i]}
		if d == DatasetRestrictions {
			raw, ok := p.ExtendedProperties[RestrictionKey]
			if !ok {
				return refuse(version, 1, "features[%d].properties.extendedProperties.%s: required on a served restriction", i, RestrictionKey)
			}
			var r cispclient.CisRestriction
			if err := json.Unmarshal(raw, &r); err != nil || r.State == "" {
				return refuse(version, 1, "features[%d].properties.extendedProperties.%s: not the CISP's restriction block", i, RestrictionKey)
			}
			f.Restriction = &r
		}
		v.Features[i] = f
	}
	return v, nil
}
