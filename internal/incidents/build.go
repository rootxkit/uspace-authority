package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// Pack kinds (06 §2 T6).
const (
	KindOversight = "oversight"
	KindLegal     = "legal"
)

// Section states in a manifest.
const (
	StateIncluded    = "included"
	StateNone        = "none"
	StateUnavailable = "unavailable"
	StateWithheld    = "withheld"
)

// Bases of a section (E-04: what was observed and what was inferred).
const (
	BasisObserved = "observed" // received or measured by this system
	BasisRecorded = "recorded" // written by this system's people or processes
	BasisReceived = "received" // a peer's statement, as received
	BasisInferred = "inferred" // derived by this system
)

// Slugs of the pack refusals.
const (
	SlugPackTooLarge       = "pack_too_large"
	SlugWindowTooLarge     = "window_too_large"
	SlugPolicyUnavailable  = "policy_unavailable"
	SlugStorageUnavailable = "evidence_storage_unavailable"
	SlugPackBusy           = "pack_busy"
	SlugTampered           = "evidence_tampered"
)

// ManifestSchema names the manifest's shape (docs/runbooks/incidents.md).
const ManifestSchema = "evidence-pack/v1"

// Sources are the relational reads of a pack (gen.Queries).
type Sources interface {
	PackViolations(ctx context.Context, arg gen.PackViolationsParams) ([]gen.PackViolationsRow, error)
	PackZoneVersions(ctx context.Context, arg gen.PackZoneVersionsParams) ([]gen.PackZoneVersionsRow, error)
	PackZonesInForce(ctx context.Context, arg gen.PackZonesInForceParams) ([]gen.PackZonesInForceRow, error)
	PackPolicies(ctx context.Context, versions []int64) ([]gen.PackPoliciesRow, error)
	PackActivePolicy(ctx context.Context) (gen.PackActivePolicyRow, error)
	PackEvents(ctx context.Context, arg gen.PackEventsParams) ([]gen.Event, error)
	PackUSSPBaseURLs(ctx context.Context, maxRows int32) ([]gen.PackUSSPBaseURLsRow, error)
}

// Telemetry are the telemetry reads of a pack (reader.Queries, the
// SELECT-only role).
type Telemetry interface {
	EvidenceTrackIDs(ctx context.Context, arg reader.EvidenceTrackIDsParams) ([]string, error)
	EvidenceTracks(ctx context.Context, arg reader.EvidenceTracksParams) ([]reader.EvidenceTracksRow, error)
	EvidenceTransmitters(ctx context.Context, arg reader.EvidenceTransmittersParams) ([]string, error)
	EvidenceFrames(ctx context.Context, arg reader.EvidenceFramesParams) ([]reader.EvidenceFramesRow, error)
	EvidenceWriterGaps(ctx context.Context, arg reader.EvidenceWriterGapsParams) ([]reader.EvidenceWriterGapsRow, error)
	EvidenceUSSPFlights(ctx context.Context, arg reader.EvidenceUSSPFlightsParams) ([]reader.EvidenceUSSPFlightsRow, error)
	EvidenceOldestUSSPFlight(ctx context.Context) (time.Time, error)
	EvidenceMannedTracks(ctx context.Context, arg reader.EvidenceMannedTracksParams) ([]reader.EvidenceMannedTracksRow, error)
}

// PersonalData resolves an operator's personal data from the registry
// for a legal pack; the registry records each read with the purpose.
type PersonalData interface {
	Operator(ctx context.Context, registration, purpose string, actor audit.Actor) (map[string]string, error)
}

// Builder assembles a pack's manifest and files.
type Builder struct {
	Sources Sources
	// Telemetry nil: the telemetry sections are unavailable, said so.
	Telemetry Telemetry
	// Records nil: no USSP record is fetched, said so.
	Records *Records
	// Personal nil: a legal pack's personal data is unavailable, said so.
	Personal PersonalData
	// MaxRows bounds every section; a section holding more refuses the
	// pack (never thinned, B-13).
	MaxRows int
	// MaxRecords bounds the USSP records fetched per pack; the rest are
	// unavailable with that reason.
	MaxRecords int
	// MaxZones bounds the zone versions named and in force.
	MaxZones int
	// MannedMarginM pads the evidence's extent for the manned traffic a
	// pack includes (WP-15; INCIDENTS_MANNED_MARGIN_M); 0 is the
	// configuration's default.
	MannedMarginM float64
	// PublicPart keeps an operator registration's public part only,
	// wherever the pack names one; nil leaves the value as stored.
	PublicPart PublicPartFunc
}

// BuildInput is one pack to build.
type BuildInput struct {
	Incident  View
	PackID    string
	Kind      string
	From, To  time.Time
	Purpose   string
	CaseRef   string
	Actor     audit.Actor
	CreatedAt time.Time
}

// Section is one part of the manifest.
type Section struct {
	State  string   `json:"state"`
	Reason string   `json:"reason,omitempty"`
	Basis  string   `json:"basis,omitempty"`
	Count  int      `json:"count"`
	Files  []string `json:"files,omitempty"`
}

// TrackSummary is one track's line in the manifest.
type TrackSummary struct {
	TrackID  string `json:"track_id"`
	File     string `json:"file"`
	Samples  int    `json:"samples"`
	Segments int    `json:"segments"`
	Holes    int    `json:"holes"`
}

// RecordSummary is one USSP record's line in the manifest.
type RecordSummary struct {
	USSPID   string `json:"ussp_id"`
	FlightID string `json:"flight_id"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	File     string `json:"file,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// AGLNumber is one height above ground the pack holds, with the ground
// it was taken from (D-05).
type AGLNumber struct {
	ViolationID   string          `json:"violation_id"`
	Name          string          `json:"name"`
	ValueM        float64         `json:"value_m"`
	State         string          `json:"state"`
	Reason        string          `json:"reason,omitempty"`
	TerrainSource json.RawMessage `json:"terrain_source,omitempty"`
}

// FileDigest is one file of the archive with its hash.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// Window is a pack's [from, to).
type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Segmenting says how tracks were cut.
type Segmenting struct {
	MaxGapS       float64 `json:"max_gap_s"`
	PolicyVersion int64   `json:"policy_version"`
	Rule          string  `json:"rule"`
}

// Manifest is manifest.json and the manifest column. It holds no
// personal data, whatever the kind.
type Manifest struct {
	Schema         string             `json:"schema"`
	PackID         string             `json:"pack_id"`
	IncidentID     string             `json:"incident_id"`
	Kind           string             `json:"kind"`
	Window         Window             `json:"window"`
	CreatedAt      string             `json:"created_at"`
	CreatedBy      string             `json:"created_by"`
	Purpose        string             `json:"purpose"`
	CaseRef        string             `json:"case_ref,omitempty"`
	Redaction      string             `json:"redaction"`
	Segmenting     Segmenting         `json:"segmenting"`
	Sections       map[string]Section `json:"sections"`
	Tracks         []TrackSummary     `json:"tracks"`
	USSPRecords    []RecordSummary    `json:"ussp_records"`
	AGLNumbers     []AGLNumber        `json:"agl_numbers"`
	FramesWithheld int                `json:"frame_payloads_withheld"`
	Inferred       []string           `json:"inferred"`
	Files          []FileDigest       `json:"files"`
}

// Section names.
const (
	SecIncident     = "incident"
	SecViolations   = "violations"
	SecTracks       = "tracks"
	SecFrames       = "raw_frames"
	SecWriterGaps   = "writer_gaps"
	SecUSSPFlights  = "ussp_flights"
	SecUSSPRecords  = "ussp_records"
	SecManned       = "manned_tracks"
	SecZones        = "zones"
	SecPolicies     = "policies"
	SecEvents       = "events"
	SecGround       = "ground"
	SecPersonalData = "personal_data"
)

// payloadTypes are the ODID message types whose raw payload an
// oversight pack carries: Basic ID (0), Location (1), Authentication (2)
// and Operator ID (5, the public part). System (4) carries the remote
// pilot position, Self-ID (3) free text and a Message Pack (15) either,
// so their payloads are withheld and kept by hash (06 §2 T6).
var payloadTypes = []int16{0, 1, 2, 5}

// ODID message type 1 is Location.
const odidLocation = 1

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func stampPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := stamp(*t)
	return &s
}

func rawOrNull(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}

func tooLarge(section string, maxRows int) error {
	return httpx.Refuse(http.StatusRequestEntityTooLarge, SlugPackTooLarge,
		"a section of the window holds more rows than a pack carries; it is refused rather than thinned: narrow the window",
		core.Fieldf(section, "more than %d rows", maxRows))
}

// reason is the text an unreadable source leaves in the manifest.
func reason(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// builder state of one pack.
type build struct {
	b       *Builder
	in      BuildInput
	ctx     context.Context
	m       Manifest
	files   []Entry
	tracks  []string
	serials []string
	regs    []string

	violationRows []gen.PackViolationsRow
	trackRows     []reader.EvidenceTracksRow
	usspRows      []reader.EvidenceUSSPFlightsRow
	// box is the extent of every position in the evidence.
	box bbox
}

func (st *build) add(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	st.files = append(st.files, Entry{Path: path, Data: append(data, '\n')})
	return nil
}

func (st *build) section(name string, s Section) { st.m.Sections[name] = s }

func addUnique(list []string, v ...string) []string {
	for _, x := range v {
		if x != "" && !slices.Contains(list, x) {
			list = append(list, x)
		}
	}
	return list
}

// Build reads every source and returns the manifest (without its file
// list, which Seal completes) and the files. A source that fails is a
// section unavailable with its reason; a section past MaxRows refuses
// the pack (413); the policy that cuts the tracks must be readable
// (503 otherwise: tracks are never cut with a threshold of this code's
// own).
func (b *Builder) Build(ctx context.Context, in BuildInput) (Manifest, []Entry, error) {
	st := &build{b: b, in: in, ctx: ctx, m: Manifest{
		Schema: ManifestSchema, PackID: in.PackID, IncidentID: in.Incident.Incident.IncidentID, Kind: in.Kind,
		Window: Window{From: stamp(in.From), To: stamp(in.To)}, CreatedAt: stamp(in.CreatedAt), CreatedBy: in.Actor.ID,
		Purpose: in.Purpose, Sections: map[string]Section{}, Tracks: []TrackSummary{}, USSPRecords: []RecordSummary{},
		AGLNumbers: []AGLNumber{}, Inferred: []string{}, Files: []FileDigest{},
	}}
	if in.Kind == KindLegal {
		st.m.CaseRef = in.CaseRef
		st.m.Redaction = "legal: personal data resolved from the registry for the purpose and case reference, in personal_data/; the archive is sealed at rest"
	} else {
		st.m.Redaction = "oversight: no personal data; operators by registration public part and aircraft by serial only; frame payloads that may carry the remote pilot position withheld and kept by hash"
	}
	pol, err := b.Sources.PackActivePolicy(ctx)
	if err != nil {
		return Manifest{}, nil, httpx.Refuse(http.StatusServiceUnavailable, SlugPolicyUnavailable,
			"the active policy (max_gap_s cuts the tracks) cannot be read: "+reason(err))
	}
	st.m.Segmenting = Segmenting{MaxGapS: pol.MaxGapS, PolicyVersion: pol.Version,
		Rule: "a track is cut at every silence longer than max_gap_s, every recorded writer gap and every sample without a position; holes are labelled, never interpolated (B-13)"}
	for _, a := range in.Incident.Aircraft {
		st.tracks = addUnique(st.tracks, a.TrackIds...)
		if a.Serial != nil {
			st.serials = addUnique(st.serials, *a.Serial)
		}
		if a.OperatorReg != nil {
			st.regs = addUnique(st.regs, *a.OperatorReg)
		}
	}
	steps := []func() error{st.incident, st.violations, st.telemetry, st.manned, st.zones, st.policies, st.events, st.ground, st.records,
		st.personal}
	for _, step := range steps {
		if err := step(); err != nil {
			return Manifest{}, nil, err
		}
	}
	st.m.Inferred = append(st.m.Inferred,
		"a hole's writer_gap cause is attributed by time: a recorded gap of the tracks or frames table inside the hole, not necessarily of this aircraft",
		"a sample without a position is attributed to a track through the transmitters that broadcast the track's serial in the window",
		"identification fields are the judgement of the time (uspace-core identify); basis as_broadcast is the transmitter's claim (06 §2 T1)",
		"every height above ground is derived from AMSL and the ground dataset named beside it (D-02, D-05)")
	return st.m, st.files, nil
}

func (st *build) incident() error {
	v := st.in.Incident
	inc := v.Incident
	aircraft := make([]map[string]any, 0, len(v.Aircraft))
	for _, a := range v.Aircraft {
		aircraft = append(aircraft, map[string]any{"serial": a.Serial, "operator_reg": a.OperatorReg,
			"registry_uas_id": a.RegistryUasID, "track_ids": a.TrackIds, "identification": rawOrNull(a.Identification),
			"added_by": a.AddedBy, "added_at": stamp(a.AddedAt)})
	}
	notes := make([]map[string]any, 0, len(v.Notes))
	for _, n := range v.Notes {
		notes = append(notes, map[string]any{"id": n.ID, "author": n.Author, "body": n.Body, "created_at": stamp(n.CreatedAt)})
	}
	doc := map[string]any{
		"incident_id": inc.IncidentID, "kind": inc.Kind, "occurred_at": stamp(inc.OccurredAt), "opened_from": inc.OpenedFrom,
		"source_violation_id": inc.SourceViolationID, "notice_ref": inc.NoticeRef, "intent_refs": inc.IntentRefs,
		"narrative": inc.Narrative, "severity": inc.Severity, "status": inc.Status, "assignee": inc.Assignee,
		"closed_at": stampPtr(inc.ClosedAt), "opened_by": inc.OpenedBy, "created_at": stamp(inc.CreatedAt),
		"updated_at": stamp(inc.UpdatedAt), "aircraft": aircraft, "notes": notes,
	}
	st.section(SecIncident, Section{State: StateIncluded, Basis: BasisRecorded, Count: 1, Files: []string{"incident.json"}})
	return st.add("incident.json", doc)
}

// violations reads the incident's violations; they extend the tracks
// and serials of the pack.
func (st *build) violations() error {
	b, in := st.b, st.in
	from := in.From
	rows, err := b.Sources.PackViolations(st.ctx, gen.PackViolationsParams{SourceViolationID: in.Incident.Incident.SourceViolationID,
		TrackIds: st.tracks, Serials: st.serials, WindowFrom: &from, WindowTo: in.To, Lim: int32(b.MaxRows + 1)})
	if err != nil {
		st.section(SecViolations, Section{State: StateUnavailable, Basis: BasisObserved, Reason: "the violations cannot be read: " + reason(err)})
		return nil
	}
	if len(rows) > b.MaxRows {
		return tooLarge(SecViolations, b.MaxRows)
	}
	st.violationRows = rows
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		st.tracks = addUnique(st.tracks, r.TrackID)
		st.tracks = addUnique(st.tracks, r.EvidenceTrackIds...)
		if r.Serial != nil {
			st.serials = addUnique(st.serials, *r.Serial)
		}
		if r.OperatorReg != nil {
			st.regs = addUnique(st.regs, *st.public(r.OperatorReg))
		}
		out = append(out, map[string]any{
			"violation_id": r.ViolationID, "kind": r.Kind, "severity": r.Severity, "alert_key": r.AlertKey, "track_id": r.TrackID,
			"serial": r.Serial, "operator_reg": st.public(r.OperatorReg), "registry_uas_id": r.RegistryUasID, "zone_id": r.ZoneID,
			"zone_version": r.ZoneVersion, "zone_type": r.ZoneType, "detector_state": r.DetectorState,
			"opened_at": stamp(r.OpenedAt), "closed_at": stampPtr(r.ClosedAt), "clear_reason": r.ClearReason,
			"last_captured_at": stamp(r.LastCapturedAt), "policy_version": r.PolicyVersion, "peak_name": r.PeakName,
			"peak_value": r.PeakValue, "detail": rawOrNull(r.Detail), "clearing_detail": rawOrNull(r.ClearingDetail),
			"terrain_source": rawOrNull(r.TerrainSource), "in_uspace": r.InUspace, "evidence_trust": r.EvidenceTrust,
			"evidence_refs": rawOrNull(r.EvidenceRefs), "evidence_track_ids": r.EvidenceTrackIds,
			"evidence_excerpt": rawOrNull(r.EvidenceExcerpt), "excerpt_samples": r.ExcerptSamples,
			"excerpt_truncated": r.ExcerptTruncated, "cell5": r.Cell5, "status": r.Status, "reviewed_by": r.ReviewedBy,
			"reviewed_at": stampPtr(r.ReviewedAt), "review_note": r.ReviewNote, "created_at": stamp(r.CreatedAt),
		})
	}
	if len(rows) == 0 {
		st.section(SecViolations, Section{State: StateNone, Basis: BasisObserved, Reason: "no violation of the incident's aircraft in the window"})
		return nil
	}
	st.section(SecViolations, Section{State: StateIncluded, Basis: BasisObserved, Count: len(rows), Files: []string{"violations.json"}})
	return st.add("violations.json", out)
}
