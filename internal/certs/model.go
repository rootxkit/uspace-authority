package certs

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Holders of a certificate.
const (
	HolderUSSP = "ussp"
	HolderCISP = "cisp"
)

// Statuses (spec 03 §1), derived by the database from Facts.
const (
	StatusIssued    = "issued"
	StatusOperating = "operating"
	StatusCeased    = "ceased"
	StatusSuspended = "suspended"
	StatusLimited   = "limited"
	StatusRevoked   = "revoked"
	StatusLapsed    = "lapsed"
)

// Statuses lists every status.
var Statuses = []string{StatusIssued, StatusOperating, StatusCeased, StatusSuspended, StatusLimited, StatusRevoked, StatusLapsed}

// Operations states (the holder's notices).
const (
	OpsNotStarted = "not_started"
	OpsOperating  = "operating"
	OpsCeased     = "ceased"
)

// The services. The six Annex VI names are those of the CISP's
// cis/ussp_list/v1; the CISP holds the common information service.
const (
	ServiceNetworkIdentification = "network_identification"
	ServiceGeoAwareness          = "geo_awareness"
	ServiceFlightAuthorisation   = "flight_authorisation"
	ServiceTrafficInformation    = "traffic_information"
	ServiceWeather               = "weather"
	ServiceConformance           = "conformance_monitoring"
	ServiceCommonInformation     = "common_information"
)

// USSPServices are the Annex VI services in the list's order.
var USSPServices = []string{
	ServiceNetworkIdentification, ServiceGeoAwareness, ServiceFlightAuthorisation,
	ServiceTrafficInformation, ServiceWeather, ServiceConformance,
}

// Bounds of a certificate (the column CHECKs of 00018_certificates and
// cis/ussp_list/v1).
const (
	MaxHolderName  = 200
	MaxAddress     = 500
	MaxEmail       = 254
	MaxPhone       = 50
	MaxURL         = 2048
	MaxConditions  = 4000
	MaxLimitations = 50
	MaxLimitation  = 1000
	MaxReason      = 1000
	MaxReference   = 200
	MaxCodeLen     = 8
)

var codePattern = regexp.MustCompile(`^[A-Z0-9]{1,8}$`)

// CheckCode refuses a code that is not one to eight upper-case ASCII
// letters and digits (M8). Whether it is taken is the store's answer.
func CheckCode(code string) error {
	switch {
	case code == "":
		return core.Fieldf("code", "required")
	case len(code) > MaxCodeLen:
		return core.Fieldf("code", "%d characters; at most %d", len(code), MaxCodeLen)
	case !codePattern.MatchString(code):
		return core.Fieldf("code", "upper-case letters A-Z and digits only")
	}
	return nil
}

// ClientIDFor is the client id of a holder (M24): ussp-<code>-01 for a
// USSP, cisp-01 for the CISP.
func ClientIDFor(holder, code string) string {
	if holder == HolderCISP {
		return "cisp-01"
	}
	return "ussp-" + code + "-01"
}

// The scopes a certificate's client holds (WP-2 table B; 06 §3, least
// privilege). Every USSP validates registrations, reports occurrences,
// notifies its operating status, provides network identification as an
// F3411 Service Provider and reads the CIS (it is a subscriber); its
// other services add the F3548 scopes and the F3411 display role they
// need. The CISP calls this system for its own operating-status notices
// only: its CIS endpoints take tokens, they need none from here.
var (
	usspBaseScopes = []string{"registry.validate", "occurrences.write", "certificates.status", "rid.service_provider", "cis.read"}
	serviceScopes  = map[string][]string{
		ServiceNetworkIdentification: {"rid.display_provider"},
		ServiceGeoAwareness:          {"utm.constraint_processing"},
		ServiceFlightAuthorisation:   {"utm.strategic_coordination"},
		ServiceTrafficInformation:    {"rid.display_provider"},
		ServiceWeather:               nil,
		ServiceConformance:           {"utm.conformance_monitoring_sa"},
	}
	cispScopes = []string{"certificates.status"}
)

// ScopesFor derives the client scopes of a holder's services, distinct,
// in a stable order.
func ScopesFor(holder string, services []string) []string {
	if holder == HolderCISP {
		return slices.Clone(cispScopes)
	}
	out := slices.Clone(usspBaseScopes)
	for _, s := range USSPServices {
		if !slices.Contains(services, s) {
			continue
		}
		for _, sc := range serviceScopes[s] {
			if !slices.Contains(out, sc) {
				out = append(out, sc)
			}
		}
	}
	return out
}

// CheckServices refuses services that do not fit the holder: a USSP
// holds one or more distinct Annex VI services, the CISP exactly the
// common information service. It returns them in the canonical order.
func CheckServices(holder string, services []string) ([]string, error) {
	if len(services) == 0 {
		return nil, core.Fieldf("services", "at least one service")
	}
	for i, s := range services {
		if slices.Index(services, s) != i {
			return nil, core.Fieldf("services["+strconv.Itoa(i)+"]", "%s appears twice", s)
		}
	}
	if holder == HolderCISP {
		if len(services) != 1 || services[0] != ServiceCommonInformation {
			return nil, core.Fieldf("services", "the CISP holds exactly common_information")
		}
		return []string{ServiceCommonInformation}, nil
	}
	out := make([]string, 0, len(services))
	for i, s := range services {
		if !slices.Contains(USSPServices, s) {
			return nil, core.Fieldf("services["+strconv.Itoa(i)+"]", "%q is not an Annex VI U-space service", s)
		}
	}
	for _, s := range USSPServices {
		if slices.Contains(services, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// CheckHTTPSURL accepts an absolute https URL without user info, query
// or fragment, or http to a loopback host (the lab and tests), of at
// most MaxURL bytes.
func CheckHTTPSURL(field, raw string) error {
	if len(raw) > MaxURL {
		return core.Fieldf(field, "longer than %d bytes", MaxURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return core.Fieldf(field, "not an absolute URL without user info, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return core.Fieldf(field, "https is required (http only to a loopback host)")
		}
	default:
		return core.Fieldf(field, "https is required")
	}
	if len(u.Hostname()) > 253 {
		return core.Fieldf(field, "host longer than 253 characters")
	}
	return nil
}

// CheckLimitations refuses an empty or over-long limitation.
func CheckLimitations(field string, ls []string) error {
	if len(ls) > MaxLimitations {
		return core.Fieldf(field, "more than %d limitations", MaxLimitations)
	}
	for i, l := range ls {
		if strings.TrimSpace(l) == "" || len(l) > MaxLimitation {
			return core.Fieldf(field+"["+strconv.Itoa(i)+"]", "1 to %d characters", MaxLimitation)
		}
	}
	return nil
}

// Facts are what a certificate's status is derived from; they change
// independently, so lifting one never clears another.
type Facts struct {
	Operations string
	Limited    bool
	Suspended  bool
	// Ended is revoked or lapsed, final; empty while the certificate
	// lives.
	Ended string
}

// Status is the status the database derives from f (the generated
// column of 00018_certificates; a test compares the two).
func (f Facts) Status() string {
	switch {
	case f.Ended != "":
		return f.Ended
	case f.Suspended:
		return StatusSuspended
	case f.Operations == OpsCeased:
		return StatusCeased
	case f.Limited:
		return StatusLimited
	case f.Operations == OpsOperating:
		return StatusOperating
	}
	return StatusIssued
}

// Listed reports whether a USSP certificate with f is on the USSP list
// (given it is within its validity): operating or limited, with its
// holder operating.
func (f Facts) Listed() bool {
	s := f.Status()
	return f.Operations == OpsOperating && (s == StatusOperating || s == StatusLimited)
}

// Actions of the authority on a certificate.
const (
	ActionSuspend   = "suspend"
	ActionLimit     = "limit"
	ActionRevoke    = "revoke"
	ActionReinstate = "reinstate"
	ActionLapse     = "lapse"
)

// The holder's notices (02 F7).
const (
	NoticeStarted   = "started"
	NoticeCeased    = "ceased"
	NoticeRestarted = "restarted"
)

// SlugTransition is the problem of a transition the status does not
// admit.
const SlugTransition = "certificate_transition_refused"

// ErrTransition is a refused transition; its text says why.
var ErrTransition = errors.New("transition refused")

func refused(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrTransition, fmt.Sprintf(format, a...))
}

// Apply is the transition graph of the authority's actions: the facts
// after action on f, or ErrTransition saying why it is refused.
//
//	suspend    any living certificate not suspended
//	limit      any living certificate not limited
//	revoke     any living certificate
//	reinstate  a suspended one (the limitation stays), else a limited one
//	lapse      a living one not operating (the job checks the periods)
func Apply(f Facts, action string) (Facts, error) {
	if f.Ended != "" {
		return f, refused("the certificate is %s; it does not change status any more", f.Ended)
	}
	switch action {
	case ActionSuspend:
		if f.Suspended {
			return f, refused("the certificate is suspended already")
		}
		f.Suspended = true
	case ActionLimit:
		if f.Limited {
			return f, refused("the certificate is limited already; correct its limitations with PATCH")
		}
		f.Limited = true
	case ActionRevoke:
		f.Ended = StatusRevoked
	case ActionReinstate:
		switch {
		case f.Suspended:
			f.Suspended = false
		case f.Limited:
			f.Limited = false
		default:
			return f, refused("the certificate is neither suspended nor limited")
		}
	case ActionLapse:
		if f.Operations == OpsOperating {
			return f, refused("an operating certificate does not lapse")
		}
		f.Ended = StatusLapsed
	default:
		return f, refused("unknown action %q", action)
	}
	return f, nil
}

// Notice is the transition graph of the holder's notices:
//
//	started    not started -> operating (not while suspended)
//	ceased     operating -> ceased (also while suspended)
//	restarted  ceased -> operating (not while suspended)
func Notice(f Facts, state string) (Facts, error) {
	if f.Ended != "" {
		return f, refused("the certificate is %s; no operating status is recorded against it", f.Ended)
	}
	switch state {
	case NoticeStarted:
		if f.Operations != OpsNotStarted {
			return f, refused("operations started already (%s)", f.Operations)
		}
		if f.Suspended {
			return f, refused("the certificate is suspended; operations cannot start")
		}
		f.Operations = OpsOperating
	case NoticeCeased:
		if f.Operations != OpsOperating {
			return f, refused("operations are not running (%s)", f.Operations)
		}
		f.Operations = OpsCeased
	case NoticeRestarted:
		if f.Operations != OpsCeased {
			return f, refused("operations have not ceased (%s)", f.Operations)
		}
		if f.Suspended {
			return f, refused("the certificate is suspended; operations cannot restart")
		}
		f.Operations = OpsOperating
	default:
		return f, refused("unknown state %q", state)
	}
	return f, nil
}

// conflict is the 409 problem of a refused transition.
func conflict(err error) error {
	return httpx.Refuse(http.StatusConflict, SlugTransition, strings.TrimPrefix(err.Error(), ErrTransition.Error()+": "))
}

// MaxNoticeAhead is how far ahead of the database clock a notice's at
// may be (a holder's clock running fast).
const MaxNoticeAhead = 5 * time.Minute

// CheckNoticeTime refuses an at before the issue or more than
// MaxNoticeAhead after now (the database clock).
func CheckNoticeTime(at, issued, now time.Time) error {
	switch {
	case at.Before(issued):
		return core.Fieldf("at", "before the certificate was issued (%s)", issued.UTC().Format(time.RFC3339))
	case at.After(now.Add(MaxNoticeAhead)):
		return core.Fieldf("at", "more than %s ahead of the authority's clock", MaxNoticeAhead)
	}
	return nil
}
