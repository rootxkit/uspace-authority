package occurrences

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/api/gen"
)

// Schema is the message name of the intake body (spec 04 §3.3; owned
// here, M14).
const Schema = "occurrence/v1"

// Bounds of a report (E-10). The intake route's body cap is
// MaxIntakeBytes; within it every list and text is bounded again.
const (
	MaxIntakeBytes    = 256 << 10
	MaxItems          = 50
	MaxEvidenceURLs   = 20
	MaxURLBytes       = 2048
	MaxTextBytes      = 128
	MaxIntentRefBytes = 64
	MaxOrgBytes       = 160
	MaxNarrativeBytes = 20000
	MaxAnalysisBytes  = 20000
	MaxPersonRefBytes = 128
	MaxRiskClassBytes = 64
	MaxPurposeBytes   = 200
	MaxReportRefBytes = 128
	operatorOrgPrefix = "operator:"
)

// Channels, categories and states (03 §1 occurrence_reports).
const (
	ChannelMandatory = "mandatory"
	ChannelVoluntary = "voluntary"

	OriginClient   = "client"
	OriginOperator = "operator"

	StateReceived   = "received"
	StateClassified = "classified"
	StateAnalysed   = "analysed"
	StateClosed     = "closed"
)

// Categories are the 376/2014 Art. 4(1) classes of occurrence/v1.
var Categories = []string{"airprox", "nonconformance_in_prohibited", "lost_link_in_uspace", "emergency", "other"}

var (
	icao24Pattern    = regexp.MustCompile(`^[0-9a-f]{6}$`)
	riskClassPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// Aircraft is one UAS of a report as stored: the operator registration
// is its public part only.
type Aircraft struct {
	Serial              string `json:"serial,omitempty"`
	OperatorReg         string `json:"operator_reg,omitempty"`
	FlightID            string `json:"flight_id,omitempty"`
	AuthorisationNumber string `json:"authorisation_number,omitempty"`
}

// Manned is one manned aircraft of a report.
type Manned struct {
	ICAO24   string `json:"icao24,omitempty"`
	Callsign string `json:"callsign,omitempty"`
}

// Separation is the minimum separation of a report, in metres.
type Separation struct {
	HM *float64   `json:"h_m,omitempty"`
	VM *float64   `json:"v_m,omitempty"`
	At *time.Time `json:"at,omitempty"`
}

// Input is an occurrence/v1 body, checked and normalised. PersonRef is
// the reporter's reference: sealed before it is stored, never logged,
// audited, hashed or exported.
type Input struct {
	ReportRef     string
	Channel       string
	OccurredAt    time.Time
	BecameAwareAt time.Time
	ReportedAt    *time.Time
	Category      string
	ReporterOrg   string // as the body named it; the token's sub is recorded
	PersonRef     string `json:"-"`
	Aircraft      []Aircraft
	Manned        []Manned
	IntentRefs    []string
	MinSeparation *Separation
	Narrative     string
	EvidenceURLs  []string
}

// PublicPartFunc keeps a registration number's public part.
type PublicPartFunc func(string) string

// PublicPartOf is the public part under the pattern pattern returns
// (uspace-core regnum, G-04, G-07); without a policy yet, regnum's
// default pattern.
//
// regnum strips the secret part only when the head is a registration
// number under the pattern, and returns anything else unchanged. A
// report is not a registration: what it names is stored and exported
// for years, so here a trailing EU secret suffix (a hyphen and three
// ASCII letters or digits) is dropped whatever the head looks like. The
// price is that a number whose own last segment is three characters
// ("GEO-OP-ABC" under a pattern that refuses "GEO-OP") is stored
// shortened; storing a secret is the worse error (G-04).
func PublicPartOf(pattern func() (string, bool)) PublicPartFunc {
	return func(reg string) string {
		p := ""
		if pattern != nil {
			if cur, ok := pattern(); ok {
				p = cur
			}
		}
		v, err := regnum.NewValidator(p)
		if err != nil {
			v, _ = regnum.NewValidator("")
		}
		reg = strings.TrimSpace(reg)
		if pub := v.PublicPart(reg); pub != reg {
			return pub // the pattern recognised the head: cut once, never twice
		}
		return stripSecretSuffix(reg)
	}
}

// secretSuffix is the EU secret part at the end of a registration: a
// hyphen and three ASCII letters or digits, after something.
var secretSuffix = regexp.MustCompile(`^(.+)-[A-Za-z0-9]{3}$`)

// stripSecretSuffix drops a trailing secret suffix from a trimmed value.
func stripSecretSuffix(reg string) string {
	if m := secretSuffix.FindStringSubmatch(reg); m != nil {
		return m[1]
	}
	return reg
}

// fieldErrs collects field errors in order.
type fieldErrs struct{ list []error }

func (e *fieldErrs) add(field, format string, args ...any) {
	e.list = append(e.list, core.Fieldf(field, format, args...))
}

func (e *fieldErrs) err() error { return errors.Join(e.list...) }

// text checks an optional string: valid UTF-8, no NUL or other control
// character but tab and line breaks (PostgreSQL text and jsonb hold no
// NUL), at most maxBytes; reason never echoes the value.
func text(e *fieldErrs, field, v string, maxBytes int, multiline bool) string {
	switch {
	case len(v) > maxBytes:
		e.add(field, "is %d bytes; at most %d", len(v), maxBytes)
	case !utf8.ValidString(v):
		e.add(field, "is not valid UTF-8")
	case strings.ContainsFunc(v, func(r rune) bool {
		return unicode.IsControl(r) && (!multiline || (r != '\n' && r != '\r' && r != '\t'))
	}):
		e.add(field, "holds a control character")
	}
	return v
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Normalise checks an intake body and returns it normalised: times in
// UTC, every operator registration cut to its public part, lists never
// nil. Every problem is a field error naming the member (JSON path), and
// none echoes a person's reference.
func Normalise(b *gen.OccurrenceReport, publicPart PublicPartFunc) (Input, error) {
	var e fieldErrs
	if b == nil {
		e.add("body", "required")
		return Input{}, e.err()
	}
	if string(b.Schema) != Schema {
		e.add("schema", "must be %q", Schema)
	}
	in := Input{ReportRef: strings.TrimSpace(text(&e, "report_ref", b.ReportRef, MaxReportRefBytes, false))}
	if in.ReportRef == "" {
		e.add("report_ref", "required")
	}
	in.Channel = string(b.Channel)
	if in.Channel != ChannelMandatory && in.Channel != ChannelVoluntary {
		e.add("channel", "is not mandatory or voluntary")
	}
	in.Category = string(b.Category)
	if !slices.Contains(Categories, in.Category) {
		e.add("category", "is not one of %s", strings.Join(Categories, ", "))
	}
	if b.OccurredAt.IsZero() {
		e.add("occurred_at", "required")
	}
	if b.BecameAwareAt.IsZero() {
		e.add("became_aware_at", "required")
	}
	in.OccurredAt, in.BecameAwareAt = b.OccurredAt.UTC(), b.BecameAwareAt.UTC()
	if !b.OccurredAt.IsZero() && !b.BecameAwareAt.IsZero() && in.BecameAwareAt.Before(in.OccurredAt) {
		e.add("became_aware_at", "is before occurred_at")
	}
	if b.ReportedAt != nil {
		t := b.ReportedAt.UTC()
		in.ReportedAt = &t
	}
	if r := b.Reporter; r != nil {
		in.ReporterOrg = strings.TrimSpace(text(&e, "reporter.org", deref(r.Org), MaxOrgBytes, false))
		if p := deref(r.PersonRef); p != "" {
			// The reasons never echo the value: it is a person's reference.
			in.PersonRef = strings.TrimSpace(text(&e, "reporter.person_ref", p, MaxPersonRefBytes, false))
		}
	}
	in.Aircraft = []Aircraft{}
	if b.Aircraft != nil {
		if len(*b.Aircraft) > MaxItems {
			e.add("aircraft", "has %d items; at most %d", len(*b.Aircraft), MaxItems)
		} else {
			for i, a := range *b.Aircraft {
				path := fmt.Sprintf("aircraft[%d]", i)
				x := Aircraft{
					Serial:              strings.TrimSpace(text(&e, path+".serial", deref(a.Serial), MaxTextBytes, false)),
					OperatorReg:         strings.TrimSpace(text(&e, path+".operator_reg", deref(a.OperatorReg), MaxTextBytes, false)),
					FlightID:            strings.TrimSpace(text(&e, path+".flight_id", deref(a.FlightId), MaxTextBytes, false)),
					AuthorisationNumber: strings.TrimSpace(text(&e, path+".authorisation_number", deref(a.AuthorisationNumber), MaxTextBytes, false)),
				}
				if x.OperatorReg != "" && publicPart != nil {
					// The EU secret part is dropped here, never stored (G-04).
					x.OperatorReg = publicPart(x.OperatorReg)
				}
				in.Aircraft = append(in.Aircraft, x)
			}
		}
	}
	in.Manned = []Manned{}
	if b.Manned != nil {
		if len(*b.Manned) > MaxItems {
			e.add("manned", "has %d items; at most %d", len(*b.Manned), MaxItems)
		} else {
			for i, m := range *b.Manned {
				path := fmt.Sprintf("manned[%d]", i)
				x := Manned{ICAO24: deref(m.Icao24), Callsign: strings.TrimSpace(text(&e, path+".callsign", deref(m.Callsign), MaxTextBytes, false))}
				if x.ICAO24 != "" && !icao24Pattern.MatchString(x.ICAO24) {
					e.add(path+".icao24", "is not six lower-case hexadecimal digits")
				}
				in.Manned = append(in.Manned, x)
			}
		}
	}
	in.IntentRefs = []string{}
	if b.IntentRefs != nil {
		if len(*b.IntentRefs) > MaxItems {
			e.add("intent_refs", "has %d items; at most %d", len(*b.IntentRefs), MaxItems)
		} else {
			for i, r := range *b.IntentRefs {
				path := fmt.Sprintf("intent_refs[%d]", i)
				r = strings.TrimSpace(text(&e, path, r, MaxIntentRefBytes, false))
				if r == "" {
					e.add(path, "is empty")
				}
				in.IntentRefs = append(in.IntentRefs, r)
			}
		}
	}
	if s := b.MinSeparation; s != nil {
		sep := &Separation{HM: s.HM, VM: s.VM}
		for name, v := range map[string]*float64{"min_separation.h_m": s.HM, "min_separation.v_m": s.VM} {
			if v != nil && (!core.IsFinite(*v) || *v < 0) {
				e.add(name, "must be a number of metres, at least 0")
			}
		}
		if s.At != nil {
			at := s.At.UTC()
			sep.At = &at
		}
		in.MinSeparation = sep
	}
	in.Narrative = text(&e, "narrative", deref(b.Narrative), MaxNarrativeBytes, true)
	in.EvidenceURLs = []string{}
	if b.EvidenceUrls != nil {
		if len(*b.EvidenceUrls) > MaxEvidenceURLs {
			e.add("evidence_urls", "has %d items; at most %d", len(*b.EvidenceUrls), MaxEvidenceURLs)
		} else {
			for i, raw := range *b.EvidenceUrls {
				path := fmt.Sprintf("evidence_urls[%d]", i)
				raw = strings.TrimSpace(text(&e, path, raw, MaxURLBytes, false))
				if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					e.add(path, "is not an absolute http or https URL")
				}
				in.EvidenceURLs = append(in.EvidenceURLs, raw)
			}
		}
	}
	if err := e.err(); err != nil {
		return Input{}, err
	}
	return in, nil
}

// stamp is the canonical form of an instant in the content hash and the
// export: UTC, nanosecond precision trimmed.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func stampPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := stamp(*t)
	return &s
}

// ContentHash is the SHA-256 of a report's content as normalised, the
// replay check of the idempotent intake: the same report delivered again
// hashes the same. The reporter's person reference is not hashed (a
// short reference is guessable from its hash); whether one was sent is.
func ContentHash(in *Input) string {
	type sep struct {
		HM *float64 `json:"h_m"`
		VM *float64 `json:"v_m"`
		At *string  `json:"at"`
	}
	var s *sep
	if in.MinSeparation != nil {
		s = &sep{HM: in.MinSeparation.HM, VM: in.MinSeparation.VM, At: stampPtr(in.MinSeparation.At)}
	}
	canonical := struct {
		Schema        string     `json:"schema"`
		ReportRef     string     `json:"report_ref"`
		Channel       string     `json:"channel"`
		OccurredAt    string     `json:"occurred_at"`
		BecameAwareAt string     `json:"became_aware_at"`
		ReportedAt    *string    `json:"reported_at"`
		Category      string     `json:"category"`
		HasPerson     bool       `json:"has_person"`
		Aircraft      []Aircraft `json:"aircraft"`
		Manned        []Manned   `json:"manned"`
		IntentRefs    []string   `json:"intent_refs"`
		MinSeparation *sep       `json:"min_separation"`
		Narrative     string     `json:"narrative"`
		EvidenceURLs  []string   `json:"evidence_urls"`
	}{Schema, in.ReportRef, in.Channel, stamp(in.OccurredAt), stamp(in.BecameAwareAt), stampPtr(in.ReportedAt), in.Category,
		in.PersonRef != "", in.Aircraft, in.Manned, in.IntentRefs, s, in.Narrative, in.EvidenceURLs}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Within reports whether a report received at received was within the
// reporting deadline after its reporter became aware (376/2014 Art.
// 4(7)-(8)): exactly at the deadline is within. It is the rule the
// within_72h column computes (migration 00020_occurrences), restated for
// the tests that hold the two together.
func Within(becameAware, received time.Time, deadline time.Duration) bool {
	return received.Sub(becameAware) <= deadline
}

// Report is a stored report.
type Report struct {
	ID                 string
	ReporterOrg        string
	ReportRef          string
	Channel            string
	Origin             string
	PersonSealed       []byte
	PersonKeyID        string
	OccurredAt         time.Time
	BecameAwareAt      time.Time
	ReportedAt         *time.Time
	ReceivedAt         time.Time
	DeadlineS          int
	Within72h          bool
	Category           string
	Aircraft           []Aircraft
	Manned             []Manned
	IntentRefs         []string
	MinSeparation      *Separation
	Narrative          string
	EvidenceURLs       []string
	ContentHash        string
	RiskClassification string
	ClassifiedAt       *time.Time
	ClassifiedBy       string
	Analysis           string
	FollowUp           string
	State              string
	ClosedAt           *time.Time
	UpdatedAt          time.Time
	UpdatedBy          string
}

// NewReport is what the intake inserts.
type NewReport struct {
	ID           string
	ReporterOrg  string
	Origin       string
	PersonSealed []byte
	PersonKeyID  string
	DeadlineS    int
	ContentHash  string
	Input
}

// Filter selects a page of reports.
type Filter struct {
	State, Category, Channel string
	From, To                 *time.Time
	CursorReceived           *time.Time
	CursorID                 string
	Limit                    int
}

// Export is a recorded de-identified export.
type Export struct {
	ID          string
	CreatedAt   time.Time
	CreatedBy   string
	Format      string
	ContentHash string
	SizeBytes   int64
	RecordCount int
	From, To    time.Time
}

// validRiskClasses checks a configured classification scheme.
func validRiskClasses(classes []string) error {
	if len(classes) == 0 {
		return core.Fieldf("OCCURRENCES_RISK_CLASSES", "names no class")
	}
	seen := map[string]bool{}
	for _, c := range classes {
		if !riskClassPattern.MatchString(c) {
			return core.Fieldf("OCCURRENCES_RISK_CLASSES", "%q is not 1 to 64 of [a-z0-9_]", c)
		}
		if seen[c] {
			return core.Fieldf("OCCURRENCES_RISK_CLASSES", "%q is listed twice", c)
		}
		seen[c] = true
	}
	return nil
}
