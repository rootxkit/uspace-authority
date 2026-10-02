package tokens

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// Family is a row of the scope catalogue (WP-2 normative table B).
type Family string

// The families of table B.
const (
	FamilyCIS       Family = "cis"
	FamilyAuthority Family = "authority"
	FamilyANSP      Family = "ansp"
	FamilyLab       Family = "lab"
	FamilyF3548     Family = "f3548"
	FamilyF3411     Family = "f3411"
	FamilyUSSP      Family = "ussp_issuer"
)

// Scope is one entry of the catalogue.
type Scope struct {
	Name   string
	Family Family
	// Standard scopes (F3548 utm.*, F3411 rid.*) may be requested for
	// any audience host, because peers are discovered through the DSS
	// and the CIS USSP list, not configured (00 §7, M18). National scopes
	// need the host on the client's audience list.
	Standard bool
	// Reserved scopes are in the catalogue but never issued
	// (cis.publish:ats_data until the Annex V SLA names the items).
	Reserved bool
	// LabOnly scopes are issued to the lab client only (dp.observe, Q-A7).
	LabOnly bool
	// ForeignIssuer scopes exist at a USSP's issuer only, never here
	// (ussp.*): listed so that the catalogue is the whole ecosystem's,
	// and refused by this issuer.
	ForeignIssuer bool
}

// LabClientID is the one client that may hold lab-only scopes (M24).
const LabClientID = "lab-01"

// catalogue is WP-2 normative table B, in the table's order. It is the
// only copy in code; scopes_test.go reads the table from
// docs/WORKPACKAGES/WP-2.md and fails on any difference, and every
// other list (the contract's description, the runbook) is checked
// against this one.
var catalogue = []Scope{
	{Name: "cis.read", Family: FamilyCIS},
	{Name: "cis.publish:zones", Family: FamilyCIS},
	{Name: "cis.publish:uspace", Family: FamilyCIS},
	{Name: "cis.publish:ussp_list", Family: FamilyCIS},
	{Name: "cis.publish:restrictions", Family: FamilyCIS},
	{Name: "cis.publish:ats_data", Family: FamilyCIS, Reserved: true},
	{Name: "registry.validate", Family: FamilyAuthority},
	{Name: "ussp.records", Family: FamilyAuthority},
	{Name: "occurrences.write", Family: FamilyAuthority},
	{Name: "certificates.status", Family: FamilyAuthority},
	{Name: "police.query", Family: FamilyAuthority},
	{Name: "ansp.traffic", Family: FamilyANSP},
	{Name: "ansp.coordination", Family: FamilyANSP},
	{Name: "ansp.requests", Family: FamilyANSP},
	{Name: "dp.observe", Family: FamilyLab, LabOnly: true},
	{Name: "utm.strategic_coordination", Family: FamilyF3548, Standard: true},
	{Name: "utm.constraint_processing", Family: FamilyF3548, Standard: true},
	{Name: "utm.constraint_management", Family: FamilyF3548, Standard: true},
	{Name: "utm.conformance_monitoring_sa", Family: FamilyF3548, Standard: true},
	{Name: "utm.availability_arbitration", Family: FamilyF3548, Standard: true},
	{Name: "rid.service_provider", Family: FamilyF3411, Standard: true},
	{Name: "rid.display_provider", Family: FamilyF3411, Standard: true},
	{Name: "ussp.intents", Family: FamilyUSSP, ForeignIssuer: true},
	{Name: "ussp.telemetry", Family: FamilyUSSP, ForeignIssuer: true},
	{Name: "ussp.traffic", Family: FamilyUSSP, ForeignIssuer: true},
	{Name: "ussp.geo", Family: FamilyUSSP, ForeignIssuer: true},
}

// Catalogue returns a copy of table B.
func Catalogue() []Scope { return slices.Clone(catalogue) }

// LookupScope returns the catalogue entry of name.
func LookupScope(name string) (Scope, bool) {
	i := slices.IndexFunc(catalogue, func(s Scope) bool { return s.Name == name })
	if i < 0 {
		return Scope{}, false
	}
	return catalogue[i], true
}

// IssuedHere lists the scopes this issuer can issue to some client: the
// catalogue without the reserved and the foreign-issuer rows. It is
// scopes_supported in the issuer metadata.
func IssuedHere() []string {
	var out []string
	for _, s := range catalogue {
		if !s.Reserved && !s.ForeignIssuer {
			out = append(out, s.Name)
		}
	}
	return out
}

// Refusal reasons of a scope (counter and events vocabulary).
const (
	ReasonScopeUnknown       = "scope_not_in_catalogue"
	ReasonScopeReserved      = "scope_reserved"
	ReasonScopeForeign       = "scope_of_another_issuer"
	ReasonScopeLabOnly       = "scope_lab_only"
	ReasonScopeNotAllowed    = "scope_not_allowed_for_client"
	ReasonScopeMissing       = "scope_missing"
	ReasonAudienceMissing    = "audience_missing"
	ReasonAudienceInvalid    = "audience_invalid"
	ReasonAudienceNotAllowed = "audience_not_allowed_for_client"
	ReasonAudienceMultiple   = "audience_multiple"
)

// ScopeError is a refused scope with its reason.
type ScopeError struct {
	Scope  string
	Reason string
}

func (e *ScopeError) Error() string {
	switch e.Reason {
	case ReasonScopeUnknown:
		return quote(e.Scope) + " is not in the scope catalogue (WP-2 table B)"
	case ReasonScopeReserved:
		return quote(e.Scope) + " is reserved and never issued"
	case ReasonScopeForeign:
		return quote(e.Scope) + " is issued by a USSP's issuer, never by this one"
	case ReasonScopeLabOnly:
		return quote(e.Scope) + " is issued to " + LabClientID + " only"
	case ReasonScopeNotAllowed:
		return quote(e.Scope) + " is not on this client's scope list"
	default:
		return quote(e.Scope) + ": " + e.Reason
	}
}

// CheckGrantable refuses a scope that no client may hold here, or that
// clientID may not hold whatever its registration says: outside the
// catalogue, reserved, of a USSP's issuer, or lab-only for another
// client. It is applied when a client is registered and again when a
// token is requested.
func CheckGrantable(scope, clientID string) error {
	s, ok := LookupScope(scope)
	switch {
	case !ok:
		return &ScopeError{Scope: scope, Reason: ReasonScopeUnknown}
	case s.Reserved:
		return &ScopeError{Scope: scope, Reason: ReasonScopeReserved}
	case s.ForeignIssuer:
		return &ScopeError{Scope: scope, Reason: ReasonScopeForeign}
	case s.LabOnly && clientID != LabClientID:
		return &ScopeError{Scope: scope, Reason: ReasonScopeLabOnly}
	}
	return nil
}

// MaxScopes bounds the scopes of one request or one client.
const MaxScopes = 32

// ParseScopeParam splits an RFC 6749 scope parameter (space-separated,
// NQCHAR) into distinct scopes in the order given.
func ParseScopeParam(raw string) ([]string, error) {
	if len(raw) > 2048 {
		return nil, core.Fieldf("scope", "longer than 2048 bytes")
	}
	var out []string
	for s := range strings.SplitSeq(raw, " ") {
		if s == "" {
			continue
		}
		for _, r := range s {
			// RFC 6749 appendix A.4: NQCHAR = %x21 / %x23-5B / %x5D-7E.
			if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
				return nil, core.Fieldf("scope", "%s contains a character outside RFC 6749 NQCHAR", quote(s))
			}
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
		if len(out) > MaxScopes {
			return nil, core.Fieldf("scope", "more than %d scopes", MaxScopes)
		}
	}
	return out, nil
}

// HasNational reports whether any of scopes is national (not standard):
// the audience must then be on the client's list.
func HasNational(scopes []string) bool {
	for _, name := range scopes {
		if s, ok := LookupScope(name); !ok || !s.Standard {
			return true
		}
	}
	return false
}

// quote renders a value from a request for an error text: quoted and
// cut, so a long or odd value cannot flood a log or a response.
func quote(s string) string {
	const limit = 64
	r := []rune(strings.ToValidUTF8(s, "?"))
	if len(r) > limit {
		return strconv.Quote(string(r[:limit])) + "..."
	}
	return strconv.Quote(string(r))
}
