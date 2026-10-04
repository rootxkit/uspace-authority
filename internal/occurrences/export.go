package occurrences

import (
	"encoding/json"
	"slices"
	"time"
)

// FormatECCAIRSDraft is the de-identified JSON layout of this build
// (docs/PLAN.md §14 Q-A12, the demo default): the 376/2014 Annex I
// fields this system knows, under names that say what they hold, with
// the mapping to ECCAIRS attributes documented in
// docs/runbooks/occurrences.md and marked unverified. The E5X writer is
// a later Exporter; the format is the owner's decision (spec 08 Q9).
const FormatECCAIRSDraft = "eccairs-compatible-draft"

// Producer names this system in an export.
const Producer = "uspace-authority"

// ExportMeta is what an export says about itself.
type ExportMeta struct {
	ExportID  string
	CreatedAt time.Time
	From, To  time.Time
}

// Exporter writes the de-identified document of a set of reports in one
// format. It receives whole reports and must leave out the reporter
// (organisation, reference, person) and anything naming a person; the
// tests hold every registered exporter to that.
type Exporter interface {
	Format() string
	Export(meta ExportMeta, reports []Report) ([]byte, error)
}

// Exporters are the formats of this build by name.
type Exporters map[string]Exporter

// Formats lists the names, sorted.
func (e Exporters) Formats() []string {
	out := make([]string, 0, len(e))
	for k := range e {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// DefaultExporters are the formats this build knows.
func DefaultExporters() Exporters {
	return Exporters{FormatECCAIRSDraft: ECCAIRSDraft{}}
}

// ECCAIRSDraft writes FormatECCAIRSDraft.
type ECCAIRSDraft struct{}

// Format implements Exporter.
func (ECCAIRSDraft) Format() string { return FormatECCAIRSDraft }

type draftAircraft struct {
	SerialNumber         string `json:"serial_number,omitempty"`
	OperatorRegistration string `json:"operator_registration,omitempty"`
}

type draftManned struct {
	ICAO24   string `json:"icao24_address,omitempty"`
	Callsign string `json:"callsign,omitempty"`
}

type draftSeparation struct {
	HorizontalM *float64 `json:"horizontal_m,omitempty"`
	VerticalM   *float64 `json:"vertical_m,omitempty"`
	At          *string  `json:"at,omitempty"`
}

type draftRecord struct {
	OccurrenceID           string           `json:"occurrence_id"`
	ReportingChannel       string           `json:"reporting_channel"`
	ReporterCategory       string           `json:"reporter_category"`
	OccurrenceCategory     string           `json:"occurrence_category"`
	OccurredAt             string           `json:"utc_date_time"`
	BecameAwareAt          string           `json:"became_aware_at"`
	ReceivedAt             string           `json:"received_at"`
	ReportedWithinDeadline bool             `json:"reported_within_deadline"`
	RiskClassification     *string          `json:"risk_classification"`
	State                  string           `json:"state"`
	Aircraft               []draftAircraft  `json:"aircraft"`
	MannedAircraft         []draftManned    `json:"manned_aircraft"`
	MinimumSeparation      *draftSeparation `json:"minimum_separation"`
	Narrative              string           `json:"narrative"`
	NarrativeRedaction     string           `json:"narrative_redaction"`
}

type draftDocument struct {
	Format        string        `json:"format"`
	FormatVersion int           `json:"format_version"`
	ExportID      string        `json:"export_id"`
	CreatedAt     string        `json:"created_at"`
	Producer      string        `json:"producer"`
	Window        draftWindow   `json:"window"`
	Deidentified  bool          `json:"deidentified"`
	FieldMapping  string        `json:"field_mapping"`
	Notice        string        `json:"notice"`
	RecordCount   int           `json:"record_count"`
	Records       []draftRecord `json:"records"`
}

type draftWindow struct {
	ReceivedFrom string `json:"received_from"`
	ReceivedTo   string `json:"received_to"`
}

// narrativeRedaction says what the export did to the narrative: nothing.
// The narrative is free text; the officer reviews it and redacts any
// name before the record is filed (the console warns, WP-23).
const narrativeRedaction = "not_redacted: exported as reported; review and redact names before filing"

// Export implements Exporter. The reporter's organisation, reference and
// person, the flight ids, authorisation numbers and intent references
// (which lead back to an operator's account at a USSP), the evidence
// URLs and the officers' analysis and follow-up are left out; aircraft
// are given by serial and the registration number's public part only.
func (ECCAIRSDraft) Export(meta ExportMeta, reports []Report) ([]byte, error) {
	doc := draftDocument{Format: FormatECCAIRSDraft, FormatVersion: 1, ExportID: meta.ExportID, CreatedAt: stamp(meta.CreatedAt),
		Producer: Producer, Window: draftWindow{ReceivedFrom: stamp(meta.From), ReceivedTo: stamp(meta.To)}, Deidentified: true,
		FieldMapping: "docs/runbooks/occurrences.md#export-field-mapping",
		Notice:       "draft layout pending the owner's decision on E5X (plan Q-A12); attribute mapping unverified against the ECCAIRS taxonomy",
		RecordCount:  len(reports), Records: make([]draftRecord, 0, len(reports))}
	for i := range reports {
		r := &reports[i]
		rec := draftRecord{OccurrenceID: r.ID, ReportingChannel: r.Channel, ReporterCategory: reporterCategory(r.Origin),
			OccurrenceCategory: r.Category, OccurredAt: stamp(r.OccurredAt), BecameAwareAt: stamp(r.BecameAwareAt),
			ReceivedAt: stamp(r.ReceivedAt), ReportedWithinDeadline: r.Within72h, State: r.State,
			Aircraft: make([]draftAircraft, 0, len(r.Aircraft)), MannedAircraft: make([]draftManned, 0, len(r.Manned)),
			Narrative: r.Narrative, NarrativeRedaction: narrativeRedaction}
		if r.RiskClassification != "" {
			c := r.RiskClassification
			rec.RiskClassification = &c
		}
		for _, a := range r.Aircraft {
			rec.Aircraft = append(rec.Aircraft, draftAircraft{SerialNumber: a.Serial, OperatorRegistration: a.OperatorReg})
		}
		for _, m := range r.Manned {
			rec.MannedAircraft = append(rec.MannedAircraft, draftManned(m))
		}
		if s := r.MinSeparation; s != nil {
			rec.MinimumSeparation = &draftSeparation{HorizontalM: s.HM, VerticalM: s.VM, At: stampPtr(s.At)}
		}
		doc.Records = append(doc.Records, rec)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// reporterCategory is the kind of reporter without its identity.
func reporterCategory(origin string) string {
	if origin == OriginOperator {
		return "uas_operator"
	}
	return "organisation"
}
