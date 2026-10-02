package registry

import (
	"encoding/json"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"
	"github.com/rootxkit/uspace-core/serial"
)

// Status is a registration status (spec 03 §1).
type Status string

// The registration statuses. Expired is set by the expiry job only.
const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusRevoked   Status = "revoked"
	StatusExpired   Status = "expired"
)

// Entity types of the change feed, the audit log and the projection.
const (
	EntityOperator = "operator"
	EntityUAS      = "uas"
	EntityPilot    = "pilot"
)

// Operator types (947 Art. 14(2)).
const (
	OperatorNatural = "natural"
	OperatorLegal   = "legal"
)

// Sources of a registration (spec 03 §1).
const (
	SourcePortal = "portal"
	SourceImport = "uas_gov_ge_import"
	SourceManual = "manual"
)

// Remote ID capabilities of a UAS.
var ridCapabilities = []string{"direct", "network", "both", "none"}

// Bounds of the free-text fields; the OpenAPI schema states the same.
const (
	maxNameLen      = 200
	maxAddressLen   = 500
	maxEmailLen     = 254
	maxPhoneLen     = 32
	maxRefLen       = 64
	maxMarkLen      = 32
	maxMakerLen     = 100
	maxReasonLen    = 500
	maxSerialLen    = 64
	maxPersonRefLen = 64
	minPersonRefLen = 4
	maxMTOMG        = 10_000_000
	// MaxAuthorisationsBytes bounds the authorisations JSON of one
	// operator (E-10).
	MaxAuthorisationsBytes = 64 << 10
	// secretLen is the EU secret part: three ASCII letters or digits
	// (spec 06 §5).
	secretLen = 3
)

// Operator is a UAS operator without personal data: what every registry
// read returns.
type Operator struct {
	ID                     string
	OperatorType           string
	RegistrationNumber     string // the public part as registered
	HasSecretPart          bool
	CompetencyConfirmation bool
	Authorisations         json.RawMessage
	Status                 Status
	StatusReason           string
	ValidFrom              time.Time
	ValidUntil             time.Time
	Source                 string
	RegistryVersion        int64
	CreatedAt              time.Time
	CreatedBy              string
	UpdatedAt              time.Time
	UpdatedBy              string
}

// OperatorPII is an operator's personal data (947 Art. 14(2)(a)-(c),
// (g)). It is sealed at rest and served only with a purpose.
type OperatorPII struct {
	FullName                  string
	LegalName                 string
	DateOfBirth               string // YYYY-MM-DD
	LegalIdentificationNumber string
	PostalAddress             string
	ContactEmail              string
	ContactPhone              string
	InsurancePolicyNumber     string
}

// NewOperator is a registration request.
type NewOperator struct {
	OperatorType           string
	RegistrationNumber     string
	SecretPart             string
	PII                    OperatorPII
	CompetencyConfirmation bool
	Authorisations         json.RawMessage
	ValidFrom              time.Time // zero means now
	ValidUntil             time.Time
	Source                 string // empty means manual
}

// OperatorPatch changes what is not nil.
type OperatorPatch struct {
	FullName                  *string
	LegalName                 *string
	DateOfBirth               *string
	LegalIdentificationNumber *string
	PostalAddress             *string
	ContactEmail              *string
	ContactPhone              *string
	InsurancePolicyNumber     *string
	CompetencyConfirmation    *bool
	Authorisations            json.RawMessage // nil keeps
	ValidUntil                *time.Time
}

// UAS is a registered aircraft.
type UAS struct {
	ID               string
	OperatorID       string
	Serial           string // as given, trimmed (G-05)
	SerialFold       string // serial.FoldKey (G-12)
	ManufacturerCode string
	RegistrationMark string
	Manufacturer     string
	Model            string
	OwnerRef         string
	ClassLabel       string // "" is unlabelled
	MTOMG            *int
	RIDCapability    string
	Status           Status
	StatusReason     string
	RegisteredAt     time.Time
	RegistryVersion  int64
	CreatedBy        string
	UpdatedAt        time.Time
	UpdatedBy        string
}

// NewUAS is a registration request.
type NewUAS struct {
	OperatorID       string
	Serial           string
	RegistrationMark string
	Manufacturer     string
	Model            string
	OwnerRef         string
	ClassLabel       string
	MTOMG            *int
	RIDCapability    string
}

// UASPatch changes what is not nil; a pointer to "" clears an optional
// text field.
type UASPatch struct {
	RegistrationMark *string
	Manufacturer     *string
	Model            *string
	OwnerRef         *string
	ClassLabel       *string
	MTOMG            *int
	RIDCapability    *string
}

// Pilot is a remote pilot without personal data.
type Pilot struct {
	ID              string
	OperatorID      string // "" when none
	Status          Status
	StatusReason    string
	Competencies    []Competency
	RegistryVersion int64
	CreatedAt       time.Time
	CreatedBy       string
	UpdatedAt       time.Time
	UpdatedBy       string
}

// PilotPII is a pilot's personal data as served with a purpose.
type PilotPII struct {
	Name           string
	PersonRefLast4 string
}

// NewPilot is a registration request.
type NewPilot struct {
	PersonRef  string // the national id; never stored in clear
	Name       string
	OperatorID string
}

// PilotPatch changes what is not nil; OperatorID "" detaches.
type PilotPatch struct {
	Name       *string
	OperatorID *string
}

// Competency is one recorded competency of a pilot.
type Competency struct {
	Competency     string
	CertificateRef string
	ValidUntil     time.Time
	RecordedAt     time.Time
	RecordedBy     string
}

var (
	nationalCompetency = regexp.MustCompile(`^national_[a-z0-9_]{1,32}$`)
	idPattern          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	datePattern        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	phonePattern       = regexp.MustCompile(`^\+?[0-9 ()-]{4,32}$`)
)

// ValidCompetency reports whether c is a competency the registry
// records: A1_A3, A2, STS_01, STS_02 or national_<code>.
func ValidCompetency(c string) bool {
	switch c {
	case "A1_A3", "A2", "STS_01", "STS_02":
		return true
	}
	return nationalCompetency.MatchString(c)
}

// ValidID reports whether id has the shape of a registry id.
func ValidID(id string) bool { return idPattern.MatchString(id) }

func text(field, value string, maxLen int, required bool) error {
	switch {
	case required && strings.TrimSpace(value) == "":
		return &core.FieldError{Field: field, Reason: "required"}
	case utf8.RuneCountInString(value) > maxLen:
		return core.Fieldf(field, "longer than %d characters", maxLen)
	case !utf8.ValidString(value):
		return core.Fieldf(field, "not valid UTF-8")
	}
	return nil
}

func absent(field, value, operatorType string) error {
	if value != "" {
		return core.Fieldf(field, "not part of a %s person's registration", operatorType)
	}
	return nil
}

// validatePII checks an operator's personal data for its type.
func validatePII(operatorType string, p OperatorPII, now time.Time) []error {
	var errs []error
	switch operatorType {
	case OperatorNatural:
		errs = append(errs, text("full_name", p.FullName, maxNameLen, true), validDate("date_of_birth", p.DateOfBirth, now),
			absent("legal_name", p.LegalName, operatorType), absent("legal_identification_number", p.LegalIdentificationNumber, operatorType))
	case OperatorLegal:
		errs = append(errs, text("legal_name", p.LegalName, maxNameLen, true),
			text("legal_identification_number", p.LegalIdentificationNumber, maxRefLen, true),
			absent("full_name", p.FullName, operatorType), absent("date_of_birth", p.DateOfBirth, operatorType))
	default:
		errs = append(errs, core.Fieldf("operator_type", "must be natural or legal"))
	}
	errs = append(errs,
		text("postal_address", p.PostalAddress, maxAddressLen, true),
		text("insurance_policy_number", p.InsurancePolicyNumber, maxRefLen, false),
		validEmail(p.ContactEmail), validPhone(p.ContactPhone))
	return errs
}

func validDate(field, value string, now time.Time) error {
	if value == "" {
		return &core.FieldError{Field: field, Reason: "required"}
	}
	d, err := time.Parse(time.DateOnly, value)
	if !datePattern.MatchString(value) || err != nil {
		return core.Fieldf(field, "not a date YYYY-MM-DD")
	}
	if !d.Before(now) {
		return core.Fieldf(field, "must be in the past")
	}
	return nil
}

func validEmail(value string) error {
	if err := text("contact_email", value, maxEmailLen, true); err != nil {
		return err
	}
	a, err := mail.ParseAddress(value)
	if err != nil || a.Address != value || a.Name != "" {
		return core.Fieldf("contact_email", "not an e-mail address")
	}
	return nil
}

func validPhone(value string) error {
	if err := text("contact_phone", value, maxPhoneLen, true); err != nil {
		return err
	}
	if !phonePattern.MatchString(value) {
		return core.Fieldf("contact_phone", "digits, spaces, parentheses and hyphens, with an optional leading +")
	}
	return nil
}

func validAuthorisations(raw json.RawMessage) error {
	if raw == nil {
		return nil
	}
	if len(raw) > MaxAuthorisationsBytes {
		return core.Fieldf("authorisations", "longer than %d bytes", MaxAuthorisationsBytes)
	}
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return core.Fieldf("authorisations", "must be an array of objects")
	}
	return nil
}

// validSecretPart checks the EU secret part: exactly three ASCII
// letters or digits (regnum's definition of the suffix, spec 06 §5).
func validSecretPart(s string) error {
	if s == "" {
		return nil
	}
	if len(s) != secretLen {
		return core.Fieldf("secret_part", "must be exactly %d characters", secretLen)
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return core.Fieldf("secret_part", "only ASCII letters and digits")
		}
	}
	return nil
}

// checkNewOperator validates a registration under v and returns the
// public part and the compare key to store (regnum, G-04, G-07). It
// never derives either by hand.
func checkNewOperator(v *regnum.Validator, in *NewOperator, now time.Time) (public, key string, err error) {
	errs := validatePII(in.OperatorType, in.PII, now)
	if e := v.Validate(in.RegistrationNumber); e != nil {
		errs = append(errs, e)
	}
	errs = append(errs, validSecretPart(in.SecretPart), validAuthorisations(in.Authorisations))
	if in.Source == "" {
		in.Source = SourceManual
	}
	if in.Source != SourcePortal && in.Source != SourceImport && in.Source != SourceManual {
		errs = append(errs, core.Fieldf("source", "must be portal, uas_gov_ge_import or manual"))
	}
	if in.ValidFrom.IsZero() {
		in.ValidFrom = now
	}
	switch {
	case in.ValidUntil.IsZero():
		errs = append(errs, &core.FieldError{Field: "valid_until", Reason: "required"})
	case !in.ValidUntil.After(in.ValidFrom):
		errs = append(errs, core.Fieldf("valid_until", "must be after valid_from"))
	}
	if err := errors.Join(errs...); err != nil {
		return "", "", err
	}
	public, key = v.Public(in.RegistrationNumber)
	return public, key, nil
}

// applyOperatorPatch returns pii and o with p applied, validated as a
// whole.
func applyOperatorPatch(o Operator, pii OperatorPII, p OperatorPatch, now time.Time) (Operator, OperatorPII, error) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&pii.FullName, p.FullName)
	set(&pii.LegalName, p.LegalName)
	set(&pii.DateOfBirth, p.DateOfBirth)
	set(&pii.LegalIdentificationNumber, p.LegalIdentificationNumber)
	set(&pii.PostalAddress, p.PostalAddress)
	set(&pii.ContactEmail, p.ContactEmail)
	set(&pii.ContactPhone, p.ContactPhone)
	set(&pii.InsurancePolicyNumber, p.InsurancePolicyNumber)
	if p.CompetencyConfirmation != nil {
		o.CompetencyConfirmation = *p.CompetencyConfirmation
	}
	errs := validatePII(o.OperatorType, pii, now)
	if p.Authorisations != nil {
		errs = append(errs, validAuthorisations(p.Authorisations))
		o.Authorisations = p.Authorisations
	}
	if p.ValidUntil != nil {
		if !p.ValidUntil.After(o.ValidFrom) {
			errs = append(errs, core.Fieldf("valid_until", "must be after valid_from"))
		}
		o.ValidUntil = *p.ValidUntil
	}
	return o, pii, errors.Join(errs...)
}

// manufacturerCode is the uniqueness scope of a serial: the first four
// characters of a CTA-2063-A serial, the serial itself otherwise.
func manufacturerCode(sn string) string {
	if serial.ValidateCTA2063A(sn) == nil {
		return sn[:4]
	}
	return sn
}

func validUASDetails(u *UAS) []error {
	errs := []error{
		text("registration_mark", u.RegistrationMark, maxMarkLen, false),
		text("manufacturer", u.Manufacturer, maxMakerLen, false),
		text("model", u.Model, maxMakerLen, false),
		text("owner_ref", u.OwnerRef, maxRefLen, false),
	}
	if u.MTOMG != nil && (*u.MTOMG < 1 || *u.MTOMG > maxMTOMG) {
		errs = append(errs, core.Fieldf("mtom_g", "must be 1 to %d", maxMTOMG))
	}
	valid := false
	for _, c := range ridCapabilities {
		valid = valid || u.RIDCapability == c
	}
	if !valid {
		errs = append(errs, core.Fieldf("rid_capability", "must be direct, network, both or none"))
	}
	// G-06: the class decides whether the serial must be CTA-2063-A;
	// uspace-core judges it.
	if err := serial.ValidateForClass(u.Serial, u.ClassLabel); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// checkNewUAS validates a registration and fills the derived keys.
func checkNewUAS(in NewUAS) (UAS, error) {
	sn := serial.Normalize(in.Serial) //nolint:misspell // uspace-core's API name
	u := UAS{
		OperatorID: in.OperatorID, Serial: sn, SerialFold: serial.FoldKey(sn), ManufacturerCode: manufacturerCode(sn),
		RegistrationMark: in.RegistrationMark, Manufacturer: in.Manufacturer, Model: in.Model, OwnerRef: in.OwnerRef,
		ClassLabel: in.ClassLabel, MTOMG: in.MTOMG, RIDCapability: in.RIDCapability,
	}
	errs := validUASDetails(&u)
	if !ValidID(in.OperatorID) {
		errs = append(errs, core.Fieldf("operator_id", "not a registry id"))
	}
	if utf8.RuneCountInString(sn) > maxSerialLen {
		errs = append(errs, core.Fieldf("serial", "longer than %d characters", maxSerialLen))
	}
	return u, errors.Join(errs...)
}

// applyUASPatch returns u with p applied, validated as a whole (a class
// change re-validates the serial).
func applyUASPatch(u UAS, p UASPatch) (UAS, error) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&u.RegistrationMark, p.RegistrationMark)
	set(&u.Manufacturer, p.Manufacturer)
	set(&u.Model, p.Model)
	set(&u.OwnerRef, p.OwnerRef)
	set(&u.ClassLabel, p.ClassLabel)
	set(&u.RIDCapability, p.RIDCapability)
	if p.MTOMG != nil {
		m := *p.MTOMG
		u.MTOMG = &m
	}
	err := errors.Join(validUASDetails(&u)...)
	return u, err
}

// normalPersonRef is a national id as hashed: trimmed.
func normalPersonRef(ref string) string { return strings.TrimSpace(ref) }

// last4 is the last four characters kept for clerical verification.
func last4(ref string) string {
	r := []rune(ref)
	if len(r) > 4 {
		r = r[len(r)-4:]
	}
	return string(r)
}

func checkNewPilot(in NewPilot) error {
	ref := normalPersonRef(in.PersonRef)
	errs := []error{text("name", in.Name, maxNameLen, true)}
	switch n := utf8.RuneCountInString(ref); {
	case n == 0:
		errs = append(errs, &core.FieldError{Field: "person_ref", Reason: "required"})
	case n < minPersonRefLen || n > maxPersonRefLen:
		errs = append(errs, core.Fieldf("person_ref", "must be %d to %d characters", minPersonRefLen, maxPersonRefLen))
	}
	if in.OperatorID != "" && !ValidID(in.OperatorID) {
		errs = append(errs, core.Fieldf("operator_id", "not a registry id"))
	}
	return errors.Join(errs...)
}

func checkCompetency(c Competency) error {
	var errs []error
	if !ValidCompetency(c.Competency) {
		errs = append(errs, core.Fieldf("competency", "must be A1_A3, A2, STS_01, STS_02 or national_<code>"))
	}
	errs = append(errs, text("certificate_ref", c.CertificateRef, maxRefLen, true))
	if c.ValidUntil.IsZero() {
		errs = append(errs, &core.FieldError{Field: "valid_until", Reason: "required"})
	}
	return errors.Join(errs...)
}
