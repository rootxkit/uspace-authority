package regimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
)

// MaxRulesBytes bounds the rules file (E-10).
const MaxRulesBytes = 1 << 20

// Formats of an export.
const (
	FormatCSV  = "csv"
	FormatJSON = "json"
)

// Field names of an operator record: the registry's names (2019/947
// Art. 14(2), RegistryOperatorInput), plus source_id, the source's own
// id of the record, and status.
var operatorFields = []string{
	"source_id", "registration_number", "secret_part", "operator_type", "full_name", "legal_name", "date_of_birth",
	"legal_identification_number", "postal_address", "contact_email", "contact_phone", "insurance_policy_number",
	"competency_confirmation", "valid_from", "valid_until", "status",
}

// Field names of an aircraft record. mtom is in the rules file's
// mtom_unit; operator_registration_number names the owner.
var uasFields = []string{
	"source_id", "serial", "operator_registration_number", "class_label", "mtom", "manufacturer", "model",
	"registration_mark", "owner_ref", "rid_capability", "status",
}

// The fields a record needs, from a column or a default.
var (
	operatorRequired = []string{"source_id", "registration_number", "operator_type", "valid_until", "status"}
	uasRequired      = []string{"source_id", "serial", "operator_registration_number", "rid_capability", "status"}
	// fromColumnOnly are fields a default cannot stand in for: each
	// record has its own.
	fromColumnOnly = []string{"source_id", "registration_number", "serial", "operator_registration_number"}
)

// The values a values map may map onto, per field; a field absent here
// takes the mapped text as it is.
var mappedTargets = map[string][]string{
	"operator_type":           {"natural", "legal"},
	"status":                  {"active", "suspended", "revoked"},
	"competency_confirmation": {"true", "false"},
	"class_label":             {"", "C0", "C1", "C2", "C3", "C4", "C5", "C6"},
	"rid_capability":          {"direct", "network", "both", "none"},
}

// EntityRules maps one kind of record: columns names the export's column
// of each field; values maps an export's value onto the registry's
// (compared trimmed, ASCII letters folded, G-12); defaults is the value
// of a field whose column is absent or empty, in the registry's terms.
type EntityRules struct {
	Columns  map[string]string            `json:"columns"`
	Values   map[string]map[string]string `json:"values"`
	Defaults map[string]string            `json:"defaults"`
}

// Rules is the rules file (docs/runbooks/registry-import.md): how a
// uas.gov.ge export maps onto the registry. It is configuration
// (REGISTRY_IMPORT_RULES_FILE), agreed with GCAA, never committed with
// real data.
type Rules struct {
	// RulesVersion names this rules file in every import's events row.
	RulesVersion string `json:"rules_version"`
	// Format is the format of a fetched export (REGISTRY_IMPORT_URL); an
	// upload says its own by its Content-Type.
	Format string `json:"format"`
	CSV    struct {
		Delimiter string `json:"delimiter"`
	} `json:"csv"`
	// RegistrationNumberPattern is the shape the export's numbers
	// follow, checked before the registry's own pattern (the policy's,
	// G-07); empty checks only the policy's.
	RegistrationNumberPattern string `json:"registration_number_pattern"`
	// SecretSuffix splits a number written with its EU secret part
	// ("<public>-<3 letters or digits>") into the two.
	SecretSuffix bool `json:"secret_suffix"`
	// DateFormats are tried in order: tokens YYYY MM DD hh mm ss, T and
	// punctuation literal, or RFC3339.
	DateFormats []string `json:"date_formats"`
	// UTCOffset is the offset of a date or time without one ("+04:00").
	UTCOffset string `json:"utc_offset"`
	// MTOMUnit is the unit of the mtom column: g or kg.
	MTOMUnit  string      `json:"mtom_unit"`
	Operators EntityRules `json:"operators"`
	UAS       EntityRules `json:"uas"`

	pattern *regexp.Regexp
	layouts []layout
	offset  *time.Location
	// folded are the values maps with their keys folded.
	folded map[string]map[string]map[string]string
}

type layout struct {
	goLayout string
	hasTime  bool
	hasZone  bool
}

// LoadRules reads and checks the rules file at path.
func LoadRules(path string) (*Rules, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return nil, core.Fieldf("REGISTRY_IMPORT_RULES_FILE", "%q cannot be read: %v", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxRulesBytes+1))
	if err != nil {
		return nil, core.Fieldf("REGISTRY_IMPORT_RULES_FILE", "%q cannot be read", path)
	}
	if len(raw) > MaxRulesBytes {
		return nil, core.Fieldf("REGISTRY_IMPORT_RULES_FILE", "%q is larger than %d bytes", path, MaxRulesBytes)
	}
	return ParseRules(raw)
}

// ParseRules decodes and checks a rules file, naming every field at
// fault (rules.<path>).
func ParseRules(raw []byte) (*Rules, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Rules
	if err := dec.Decode(&r); err != nil {
		return nil, core.Fieldf("rules", "not a rules file: %v", err)
	}
	if dec.More() {
		return nil, core.Fieldf("rules", "one JSON object only")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

var rulesVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (r *Rules) check() error {
	var errs []error
	if !rulesVersionPattern.MatchString(r.RulesVersion) {
		errs = append(errs, core.Fieldf("rules.rules_version", "1 to 64 of [A-Za-z0-9._-]"))
	}
	switch r.Format {
	case FormatCSV, FormatJSON:
	default:
		errs = append(errs, core.Fieldf("rules.format", "must be csv or json"))
	}
	if d := r.CSV.Delimiter; d != "" && (utf8.RuneCountInString(d) != 1 || d == "\"" || d == "\n" || d == "\r") {
		errs = append(errs, core.Fieldf("rules.csv.delimiter", "one character other than a quote or a line break"))
	}
	if p := r.RegistrationNumberPattern; p != "" {
		re, err := regexp.Compile(`^(?:` + p + `)$`)
		switch {
		case len(p) > 256:
			errs = append(errs, core.Fieldf("rules.registration_number_pattern", "longer than 256 characters"))
		case err != nil:
			errs = append(errs, core.Fieldf("rules.registration_number_pattern", "not a regular expression: %v", err))
		default:
			r.pattern = re
		}
	}
	if len(r.DateFormats) == 0 || len(r.DateFormats) > 16 {
		errs = append(errs, core.Fieldf("rules.date_formats", "1 to 16 formats"))
	}
	for i, f := range r.DateFormats {
		l, err := parseLayout(f)
		if err != nil {
			errs = append(errs, core.Fieldf(fmt.Sprintf("rules.date_formats[%d]", i), "%v", err))
			continue
		}
		r.layouts = append(r.layouts, l)
	}
	loc, err := parseOffset(r.UTCOffset)
	if err != nil {
		errs = append(errs, core.Fieldf("rules.utc_offset", "%v", err))
	}
	r.offset = loc
	switch r.MTOMUnit {
	case "g", "kg":
	case "":
		r.MTOMUnit = "g"
	default:
		errs = append(errs, core.Fieldf("rules.mtom_unit", "must be g or kg"))
	}
	r.folded = map[string]map[string]map[string]string{}
	errs = append(errs, r.checkEntity("operators", &r.Operators, operatorFields, operatorRequired)...)
	errs = append(errs, r.checkEntity("uas", &r.UAS, uasFields, uasRequired)...)
	return errors.Join(errs...)
}

func (r *Rules) checkEntity(name string, e *EntityRules, fields, required []string) []error {
	var errs []error
	path := "rules." + name
	for f, col := range e.Columns {
		if !slices.Contains(fields, f) {
			errs = append(errs, core.Fieldf(path+".columns."+f, "not a field of %s (%s)", name, strings.Join(fields, ", ")))
		}
		if strings.TrimSpace(col) == "" || len(col) > 128 {
			errs = append(errs, core.Fieldf(path+".columns."+f, "a column name of 1 to 128 bytes"))
		}
	}
	for f, v := range e.Defaults {
		switch {
		case !slices.Contains(fields, f):
			errs = append(errs, core.Fieldf(path+".defaults."+f, "not a field of %s", name))
		case slices.Contains(fromColumnOnly, f):
			errs = append(errs, core.Fieldf(path+".defaults."+f, "each record has its own; map a column"))
		case mappedTargets[f] != nil && !slices.Contains(mappedTargets[f], v):
			errs = append(errs, core.Fieldf(path+".defaults."+f, "must be one of %s", strings.Join(mappedTargets[f], ", ")))
		}
	}
	for _, f := range required {
		_, col := e.Columns[f]
		_, def := e.Defaults[f]
		if !col && !def {
			errs = append(errs, core.Fieldf(path+".columns."+f, "required: map a column (or give a default)"))
		}
	}
	folded := map[string]map[string]string{}
	for f, m := range e.Values {
		if !slices.Contains(fields, f) {
			errs = append(errs, core.Fieldf(path+".values."+f, "not a field of %s", name))
			continue
		}
		fm := map[string]string{}
		for from, to := range m {
			key := foldKey(from)
			if _, dup := fm[key]; dup {
				errs = append(errs, core.Fieldf(path+".values."+f, "%q is given twice (compared trimmed, ignoring case)", from))
			}
			if t := mappedTargets[f]; t != nil && !slices.Contains(t, to) {
				errs = append(errs, core.Fieldf(path+".values."+f+"."+from, "must map onto one of %q", t))
			}
			fm[key] = to
		}
		folded[f] = fm
	}
	r.folded[name] = folded
	return errs
}

// foldKey is a value as the values maps compare it: trimmed, ASCII
// letters upper-cased and nothing else (G-12).
func foldKey(s string) string {
	b := []byte(strings.TrimSpace(s))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

var tokenLayouts = []struct{ token, layout string }{
	{"YYYY", "2006"}, {"MM", "01"}, {"DD", "02"}, {"hh", "15"}, {"mm", "04"}, {"ss", "05"},
}

// parseLayout turns a date format of the rules file into a Go layout.
func parseLayout(f string) (layout, error) {
	if f == "RFC3339" {
		return layout{goLayout: time.RFC3339, hasTime: true, hasZone: true}, nil
	}
	if f == "" || len(f) > 32 {
		return layout{}, errors.New("1 to 32 characters, or RFC3339")
	}
	var out strings.Builder
	var hasDate [3]bool
	hasTime := false
	for i := 0; i < len(f); {
		matched := false
		for j, t := range tokenLayouts {
			if strings.HasPrefix(f[i:], t.token) {
				out.WriteString(t.layout)
				i += len(t.token)
				matched = true
				if j < 3 {
					hasDate[j] = true
				} else {
					hasTime = true
				}
				break
			}
		}
		if matched {
			continue
		}
		c := f[i]
		if c != 'T' && ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return layout{}, fmt.Errorf("%q: only the tokens YYYY MM DD hh mm ss, T and separators", f)
		}
		out.WriteByte(c)
		i++
	}
	if !hasDate[0] || !hasDate[1] || !hasDate[2] {
		return layout{}, fmt.Errorf("%q: YYYY, MM and DD are required", f)
	}
	return layout{goLayout: out.String(), hasTime: hasTime}, nil
}

var offsetPattern = regexp.MustCompile(`^([+-])(\d{2}):(\d{2})$`)

func parseOffset(s string) (*time.Location, error) {
	if s == "" {
		return nil, errors.New(`required, for example "+04:00"`)
	}
	m := offsetPattern.FindStringSubmatch(s)
	if m == nil {
		return nil, errors.New(`must be +HH:MM or -HH:MM`)
	}
	h := int(m[2][0]-'0')*10 + int(m[2][1]-'0')
	mi := int(m[3][0]-'0')*10 + int(m[3][1]-'0')
	if h > 14 || mi > 59 {
		return nil, errors.New("out of range")
	}
	secs := (h*60 + mi) * 60
	if m[1] == "-" {
		secs = -secs
	}
	return time.FixedZone(s, secs), nil
}

// Columns names the columns the rules read for kind, for the report.
func (r *Rules) Columns(kind string) map[string]string {
	if kind == "uas" {
		return r.UAS.Columns
	}
	return r.Operators.Columns
}
