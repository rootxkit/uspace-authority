package zonesvc

import (
	"encoding/json"
	"time"
)

// Dataset is one of the two published datasets this package authors.
type Dataset string

// The datasets (spec 02 F1, the CISP's dataset names).
const (
	DatasetZones  Dataset = "zones"
	DatasetUSpace Dataset = "uspace_airspace"
)

// Valid reports whether d is one of the datasets.
func (d Dataset) Valid() bool { return d == DatasetZones || d == DatasetUSpace }

// State is where a version is in its workflow.
type State string

// The states of a version: a draft is approved (designated, for a
// U-space airspace) and then published; a newer version supersedes it.
const (
	StateDraft      State = "draft"
	StateApproved   State = "approved"
	StatePublished  State = "published"
	StateSuperseded State = "superseded"
)

// ValidState reports whether s is a state.
func ValidState(s State) bool {
	switch s {
	case StateDraft, StateApproved, StatePublished, StateSuperseded:
		return true
	}
	return false
}

// Extension names a member that uses this project's extension of ED-318
// (LESSONS Z-05): accepted, and said so in every answer.
type Extension struct {
	Field  string
	Reason string
}

// wgs84Reason is the reason of a WGS84 extension.
const wgs84Reason = "WGS84 (height above the ellipsoid) is this project's extension, not a published ED-318 vertical reference (LESSONS Z-05)"

// Version is one stored version of a zone or a U-space airspace.
type Version struct {
	ID          int64
	Dataset     Dataset
	Identifier  string
	ZoneVersion int
	State       State
	Type        string
	Country     string
	// Feature is the master copy: the ED-318 feature exactly as
	// ed318.Export wrote it.
	Feature   json.RawMessage
	ValidFrom time.Time
	ValidTo   time.Time
	// WGS84Fields are the members using the WGS84 extension.
	WGS84Fields      []string
	PublishedVersion *int64
	PublishedAt      *time.Time
	PublishedBy      string
	CreatedAt        time.Time
	CreatedBy        string
	ApprovedAt       *time.Time
	ApprovedBy       string
	// Designation is set for a U-space airspace version.
	Designation *Designation
}

// Extensions lists the version's extension members.
func (v *Version) Extensions() []Extension {
	out := make([]Extension, 0, len(v.WGS84Fields))
	for _, f := range v.WGS84Fields {
		out = append(out, Extension{Field: f, Reason: wgs84Reason})
	}
	return out
}

// Designation is the 03 §1 designation of a U-space airspace version
// (2021/664 Art. 3 and 5). The Art. 3(4) members are kept as the JSON
// objects given; the block written into the feature is built from them
// (USpaceBlock).
type Designation struct {
	Name                  string
	ServicesRequired      []string
	UASRequirements       json.RawMessage
	ServicePerformance    json.RawMessage
	OperationalConditions json.RawMessage
	AirspaceConstraints   json.RawMessage
	AdjacentIDs           []string
	RiskAssessmentRef     string
	InControlledAirspace  bool
	ATSProviderID         string
	CISPID                string
	DesignationRef        string
	AIPRef                string
}

// Draft is one validated version to store: the feature and every column
// derived from it (Columns), with its period of validity.
type Draft struct {
	Dataset     Dataset
	Identifier  string
	Feature     json.RawMessage
	Columns     Columns
	ValidFrom   time.Time
	ValidTo     time.Time
	Designation *Designation
}

// Columns are the query columns derived from a feature, in the same
// statement that stores it.
type Columns struct {
	Country               string
	Type                  string
	Variant               string
	Name                  json.RawMessage
	Reason                []string
	OtherReasonInfo       json.RawMessage
	RestrictionConditions *string
	Region                *int
	RegulationExemption   *string
	Message               json.RawMessage
	GeometryType          string
	// GeometryGeoJSON is a plain GeoJSON geometry of a Polygon or a
	// collection (nil for a circle), for PostGIS.
	GeometryGeoJSON *string
	CenterLonDeg    *float64
	CenterLatDeg    *float64
	RadiusM         *float64
	LowerM          *float64
	LowerRef        *string
	UpperM          *float64
	UpperRef        *string
	Layers          json.RawMessage
	ED318Extra      json.RawMessage
	WGS84Fields     []string
	Limited         json.RawMessage
	ZoneAuthority   json.RawMessage
	DataSource      json.RawMessage
	Extended        json.RawMessage
}

// BBox is a latitude/longitude box in degrees (a prefilter, never a
// judgement).
type BBox struct {
	MinLatDeg, MinLonDeg, MaxLatDeg, MaxLonDeg float64
}

// Centre is the middle of the box: where applicability is evaluated.
func (b BBox) Centre() (latDeg, lonDeg float64) {
	return (b.MinLatDeg + b.MaxLatDeg) / 2, (b.MinLonDeg + b.MaxLonDeg) / 2
}

// Publication is one F1 outbox row.
type Publication struct {
	ID           int64
	Dataset      Dataset
	Version      int64
	PayloadHash  string
	FeatureCount int
	// Signature is the detached JWS of the payload (WP-6's outbox; nil
	// only without one, in the unit tests).
	Signature *string
	State     string
	CreatedAt time.Time
}

// Published is what one publication did.
type Published struct {
	Dataset      Dataset
	ZonesVersion int64
	Versions     []Version
	Publication  Publication
}

// Applicability is the three-valued answer of a zone's applicability at
// an instant (M17's cis_applicability values).
type Applicability string

// The answers.
const (
	Applies       Applicability = "applies"
	NotApplicable Applicability = "not_applicable"
	Unknown       Applicability = "unknown"
)
