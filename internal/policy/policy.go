package policy

import (
	"errors"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// HeightLimitInUspace says whether the 120 m rule is judged inside a
// U-space airspace for a flight the USSP authorised.
const (
	HeightEvaluate           = "evaluate"
	HeightSkipWhenAuthorised = "skip_when_authorised"
)

// Thresholds are the values of one policy version. Units are in the
// names (E-13); every number is finite and positive (E-15).
type Thresholds struct {
	HeightLimitAGLM         float64       `json:"height_limit_agl_m"`
	PressureUncertaintyM    float64       `json:"pressure_uncertainty_m"`
	ZoneConditionalSeverity core.Severity `json:"zone_conditional_severity"`
	MismatchSeverity        core.Severity `json:"mismatch_severity"`
	IdentificationSeverity  core.Severity `json:"identification_severity"`
	SpoofDistanceM          float64       `json:"spoof_distance_m"`
	IdentityTTLS            float64       `json:"identity_ttl_s"`
	MaxGapS                 float64       `json:"max_gap_s"`
	IdentifyWithinS         float64       `json:"identify_within_s"`
	BroadcastToleranceS     float64       `json:"broadcast_tolerance_s"`
	MaxLatencyS             float64       `json:"max_latency_s"`
	LiveMaxAgeS             float64       `json:"live_max_age_s"`
	ClearAfterS             float64       `json:"clear_after_s"`
	StaleAfterS             float64       `json:"stale_after_s"`
	DPViewDiagonalKM        float64       `json:"dp_view_diagonal_km"`
	DPPollHz                float64       `json:"dp_poll_hz"`
	CISStaleBoundS          float64       `json:"cis_stale_bound_s"`
	HeightLimitInUspace     string        `json:"height_limit_in_uspace"`
	// RegistrationNumberPattern is the operator registration-number
	// format (G-07, spec Q5) the registry validates against through
	// uspace-core regnum (WP-3).
	RegistrationNumberPattern string `json:"registration_number_pattern"`
}

// Defaults are the documented defaults, equal to the predecessor's and
// to the column defaults and seeded version 1 of migration
// 00003_authority_policy (an integration test compares them).
func Defaults() Thresholds {
	return Thresholds{
		HeightLimitAGLM:         120,
		PressureUncertaintyM:    250,
		ZoneConditionalSeverity: core.SeverityWarning,
		MismatchSeverity:        core.SeverityWarning,
		IdentificationSeverity:  core.SeverityCritical,
		SpoofDistanceM:          300,
		IdentityTTLS:            15,
		MaxGapS:                 3,
		IdentifyWithinS:         4,
		BroadcastToleranceS:     1,
		MaxLatencyS:             5,
		LiveMaxAgeS:             10,
		ClearAfterS:             3,
		StaleAfterS:             15,
		DPViewDiagonalKM:        7,
		DPPollHz:                1,
		CISStaleBoundS:          300,
		HeightLimitInUspace:     HeightEvaluate,
		// regnum.DefaultPattern, the EU shape (G-07).
		RegistrationNumberPattern: regnum.DefaultPattern,
	}
}

// numbers lists every numeric threshold with its field name.
func (t Thresholds) numbers() []struct {
	field string
	value float64
} {
	return []struct {
		field string
		value float64
	}{
		{"height_limit_agl_m", t.HeightLimitAGLM},
		{"pressure_uncertainty_m", t.PressureUncertaintyM},
		{"spoof_distance_m", t.SpoofDistanceM},
		{"identity_ttl_s", t.IdentityTTLS},
		{"max_gap_s", t.MaxGapS},
		{"identify_within_s", t.IdentifyWithinS},
		{"broadcast_tolerance_s", t.BroadcastToleranceS},
		{"max_latency_s", t.MaxLatencyS},
		{"live_max_age_s", t.LiveMaxAgeS},
		{"clear_after_s", t.ClearAfterS},
		{"stale_after_s", t.StaleAfterS},
		{"dp_view_diagonal_km", t.DPViewDiagonalKM},
		{"dp_poll_hz", t.DPPollHz},
		{"cis_stale_bound_s", t.CISStaleBoundS},
	}
}

// MaxPatternLen bounds Thresholds.RegistrationNumberPattern (the column's
// CHECK in migration 00009_registry).
const MaxPatternLen = 256

var severities = []core.Severity{core.SeverityInfo, core.SeverityWarning, core.SeverityCritical}

// Validate refuses a threshold that would disarm a check (E-15): zero,
// negative, NaN or infinite numbers, an unknown severity or mode. Every
// field at fault is named, so one request shows every mistake.
func (t Thresholds) Validate() error {
	var errs []error
	for _, n := range t.numbers() {
		if !core.IsFinite(n.value) || n.value <= 0 {
			errs = append(errs, core.Fieldf(n.field, "must be a finite number greater than zero"))
		}
	}
	for _, s := range []struct {
		field string
		value core.Severity
	}{
		{"zone_conditional_severity", t.ZoneConditionalSeverity},
		{"mismatch_severity", t.MismatchSeverity},
		{"identification_severity", t.IdentificationSeverity},
	} {
		if !slices.Contains(severities, s.value) {
			errs = append(errs, core.Fieldf(s.field, "must be info, warning or critical"))
		}
	}
	if t.HeightLimitInUspace != HeightEvaluate && t.HeightLimitInUspace != HeightSkipWhenAuthorised {
		errs = append(errs, core.Fieldf("height_limit_in_uspace", "must be evaluate or skip_when_authorised"))
	}
	switch {
	case t.RegistrationNumberPattern == "":
		errs = append(errs, core.Fieldf("registration_number_pattern", "required"))
	case len(t.RegistrationNumberPattern) > MaxPatternLen:
		errs = append(errs, core.Fieldf("registration_number_pattern", "longer than %d bytes", MaxPatternLen))
	default:
		if _, err := regnum.NewValidator(t.RegistrationNumberPattern); err != nil {
			errs = append(errs, core.Fieldf("registration_number_pattern", "not a valid regular expression"))
		}
	}
	return errors.Join(errs...)
}

// Policy is one stored version.
type Policy struct {
	Version int64
	Thresholds
	Note        string
	Active      bool
	CreatedAt   time.Time
	CreatedBy   string
	ActivatedAt *time.Time
	ActivatedBy string
}

func fromRow(r gen.AuthorityPolicy) Policy {
	p := Policy{
		Version: r.Version,
		Thresholds: Thresholds{
			HeightLimitAGLM:         r.HeightLimitAglM,
			PressureUncertaintyM:    r.PressureUncertaintyM,
			ZoneConditionalSeverity: core.Severity(r.ZoneConditionalSeverity),
			MismatchSeverity:        core.Severity(r.MismatchSeverity),
			IdentificationSeverity:  core.Severity(r.IdentificationSeverity),
			SpoofDistanceM:          r.SpoofDistanceM,
			IdentityTTLS:            r.IdentityTtlS,
			MaxGapS:                 r.MaxGapS,
			IdentifyWithinS:         r.IdentifyWithinS,
			BroadcastToleranceS:     r.BroadcastToleranceS,
			MaxLatencyS:             r.MaxLatencyS,
			LiveMaxAgeS:             r.LiveMaxAgeS,
			ClearAfterS:             r.ClearAfterS,
			StaleAfterS:             r.StaleAfterS,
			DPViewDiagonalKM:        r.DpViewDiagonalKm,
			DPPollHz:                r.DpPollHz,
			CISStaleBoundS:          r.CisStaleBoundS,
			HeightLimitInUspace:     r.HeightLimitInUspace,

			RegistrationNumberPattern: r.RegistrationNumberPattern,
		},
		Note:        r.Note,
		Active:      r.Active,
		CreatedAt:   r.CreatedAt,
		CreatedBy:   r.CreatedBy,
		ActivatedAt: r.ActivatedAt,
	}
	if r.ActivatedBy != nil {
		p.ActivatedBy = *r.ActivatedBy
	}
	return p
}

func insertParams(version int64, t Thresholds, note, by string, at time.Time) gen.InsertPolicyParams {
	return gen.InsertPolicyParams{
		Version:                   version,
		HeightLimitAglM:           t.HeightLimitAGLM,
		PressureUncertaintyM:      t.PressureUncertaintyM,
		ZoneConditionalSeverity:   string(t.ZoneConditionalSeverity),
		MismatchSeverity:          string(t.MismatchSeverity),
		IdentificationSeverity:    string(t.IdentificationSeverity),
		SpoofDistanceM:            t.SpoofDistanceM,
		IdentityTtlS:              t.IdentityTTLS,
		MaxGapS:                   t.MaxGapS,
		IdentifyWithinS:           t.IdentifyWithinS,
		BroadcastToleranceS:       t.BroadcastToleranceS,
		MaxLatencyS:               t.MaxLatencyS,
		LiveMaxAgeS:               t.LiveMaxAgeS,
		ClearAfterS:               t.ClearAfterS,
		StaleAfterS:               t.StaleAfterS,
		DpViewDiagonalKm:          t.DPViewDiagonalKM,
		DpPollHz:                  t.DPPollHz,
		CisStaleBoundS:            t.CISStaleBoundS,
		HeightLimitInUspace:       t.HeightLimitInUspace,
		RegistrationNumberPattern: t.RegistrationNumberPattern,
		Note:                      note,
		CreatedAt:                 at,
		CreatedBy:                 by,
	}
}
