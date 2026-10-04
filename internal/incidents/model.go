package incidents

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
)

// Kinds of incident (spec 03 §1 incidents.kind).
const (
	KindAirprox            = "airprox"
	KindNonconformance     = "nonconformance"
	KindLostLink           = "lost_link"
	KindEmergency          = "emergency"
	KindViolationEscalated = "violation_escalated"
	KindOther              = "other"
)

var kinds = []string{KindAirprox, KindNonconformance, KindLostLink, KindEmergency, KindViolationEscalated, KindOther}

// Where an incident was opened from (03 §1 incidents.opened_from). Never
// from an occurrence report (376/2014 Art. 15-16).
const (
	FromViolation      = "violation"
	FromOwnObservation = "own_observation"
	FromANSPNotice     = "ansp_notice"
	FromUSSPNotice     = "ussp_notice"
	// FromPoliceRequest is set by a police export of an area and a
	// window (WP-19, OpenForPolice) and never by hand.
	FromPoliceRequest = "police_request"
)

var origins = []string{FromViolation, FromOwnObservation, FromANSPNotice, FromUSSPNotice, FromPoliceRequest}

// Statuses of an incident.
const (
	StatusOpen     = "open"
	StatusAssigned = "assigned"
	StatusClosed   = "closed"
)

var statuses = []string{StatusOpen, StatusAssigned, StatusClosed}

// Severities, the ecosystem's (core.Severity).
var severities = []string{string(core.SeverityInfo), string(core.SeverityWarning), string(core.SeverityCritical)}

// Bounds of what one incident holds (E-10). The database repeats them.
const (
	MaxAircraft     = 32
	MaxTrackIDs     = 16
	MaxIntentRefs   = 32
	MaxNotes        = 500
	MaxNarrative    = 20000
	MaxNote         = 4000
	MaxRefLen       = 256
	MaxNoticeRefLen = 200
	MaxIdentLen     = 64
)

// Aircraft is one aircraft of an incident as stored: what identified it
// at the time. OperatorReg is the registration number's public part
// only (spec 06 §5).
type Aircraft struct {
	Serial         *string
	OperatorReg    *string
	RegistryUASID  *string
	TrackIDs       []string
	Identification Identification
}

// Identification is the identification as judged at the time.
type Identification struct {
	Status        string `json:"status,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Basis         string `json:"basis,omitempty"`
	EvidenceTrust string `json:"evidence_trust,omitempty"`
}

// NewIncident is an incident to open by hand (an observation or a
// notice).
type NewIncident struct {
	Kind       string
	OccurredAt time.Time
	OpenedFrom string
	NoticeRef  *string
	Severity   string
	Narrative  string
	IntentRefs []string
	Aircraft   []Aircraft
}

// Patch is a change of an incident; nil members are left alone.
type Patch struct {
	Narrative   *string
	Severity    *string
	Status      *string
	Assignee    *string
	IntentRefs  *[]string
	AddAircraft []Aircraft
	Note        *string
}

// PublicPartFunc returns the public part of an operator registration
// number (uspace-core regnum under the active policy's pattern): a
// secret part is dropped, never stored.
type PublicPartFunc func(reg string) string

func oneOf(field, v string, allowed []string) error {
	if !slices.Contains(allowed, v) {
		return core.Fieldf(field, "%q is not one of %s", v, strings.Join(allowed, ", "))
	}
	return nil
}

func textLen(field, v string, maxRunes int) error {
	if !utf8.ValidString(v) {
		return core.Fieldf(field, "not valid UTF-8")
	}
	if utf8.RuneCountInString(v) > maxRunes {
		return core.Fieldf(field, "longer than %d characters", maxRunes)
	}
	return nil
}

func checkRefs(field string, refs []string, maxRefs int) error {
	if len(refs) > maxRefs {
		return core.Fieldf(field, "at most %d", maxRefs)
	}
	for i, r := range refs {
		if r == "" {
			return core.Fieldf(field, "member %d is empty", i)
		}
		if err := textLen(field, r, MaxRefLen); err != nil {
			return err
		}
	}
	return nil
}

// normaliseAircraft checks a and stores the operator registration's
// public part only.
func normaliseAircraft(field string, a Aircraft, public PublicPartFunc) (Aircraft, error) {
	if a.Serial != nil && (*a.Serial == "" || len(*a.Serial) > 64) {
		return a, core.Fieldf(field+".serial", "1 to 64 characters")
	}
	if a.OperatorReg != nil {
		if *a.OperatorReg == "" || len(*a.OperatorReg) > 64 {
			return a, core.Fieldf(field+".operator_reg", "1 to 64 characters")
		}
		p := strings.TrimSpace(*a.OperatorReg)
		if public != nil {
			p = public(p)
		}
		if p == "" {
			return a, core.Fieldf(field+".operator_reg", "no public part")
		}
		a.OperatorReg = &p
	}
	if err := checkRefs(field+".track_ids", a.TrackIDs, MaxTrackIDs); err != nil {
		return a, err
	}
	if a.Serial == nil && a.OperatorReg == nil && len(a.TrackIDs) == 0 {
		return a, core.Fieldf(field, "needs a serial, an operator_reg or a track id")
	}
	for name, v := range map[string]string{"status": a.Identification.Status, "reason": a.Identification.Reason,
		"basis": a.Identification.Basis, "evidence_trust": a.Identification.EvidenceTrust} {
		if len(v) > MaxIdentLen {
			return a, core.Fieldf(field+".identification."+name, "longer than %d", MaxIdentLen)
		}
	}
	if a.TrackIDs == nil {
		a.TrackIDs = []string{}
	}
	return a, nil
}

// checkNew validates an incident opened by hand.
func checkNew(in *NewIncident, public PublicPartFunc, viaPolice bool) error {
	if err := oneOf("kind", in.Kind, kinds); err != nil {
		return err
	}
	if err := oneOf("opened_from", in.OpenedFrom, origins); err != nil {
		return err
	}
	if in.OpenedFrom == FromViolation {
		return core.Fieldf("opened_from", "an incident is opened from a violation by escalating it (POST /v1/violations/{id}/review)")
	}
	if (in.OpenedFrom == FromPoliceRequest) != viaPolice {
		return core.Fieldf("opened_from", "police_request is set by a police export (POST /v1/police/exports) only")
	}
	notice := in.OpenedFrom == FromANSPNotice || in.OpenedFrom == FromUSSPNotice
	switch {
	case notice && (in.NoticeRef == nil || *in.NoticeRef == ""):
		return core.Fieldf("notice_ref", "required for a notice")
	case in.NoticeRef != nil && len(*in.NoticeRef) > MaxNoticeRefLen:
		return core.Fieldf("notice_ref", "longer than %d", MaxNoticeRefLen)
	}
	if in.OccurredAt.IsZero() {
		return core.Fieldf("occurred_at", "required")
	}
	if err := oneOf("severity", in.Severity, severities); err != nil {
		return err
	}
	if err := textLen("narrative", in.Narrative, MaxNarrative); err != nil {
		return err
	}
	if err := checkRefs("intent_refs", in.IntentRefs, MaxIntentRefs); err != nil {
		return err
	}
	if len(in.Aircraft) > MaxAircraft {
		return core.Fieldf("aircraft", "at most %d", MaxAircraft)
	}
	for i := range in.Aircraft {
		a, err := normaliseAircraft(fieldIndex("aircraft", i), in.Aircraft[i], public)
		if err != nil {
			return err
		}
		in.Aircraft[i] = a
	}
	return nil
}

func fieldIndex(name string, i int) string {
	return name + "[" + strconv.Itoa(i) + "]"
}

// checkStatus checks the status an incident moves to. Every move
// between open, assigned and closed is allowed, so a closed case can
// always be reopened; assigned needs an assignee.
func checkStatus(to string, assignee *string) error {
	if err := oneOf("status", to, statuses); err != nil {
		return err
	}
	if to == StatusAssigned && (assignee == nil || *assignee == "") {
		return core.Fieldf("assignee", "required to assign")
	}
	return nil
}
