package police

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
)

// Kinds of police_queries row.
const (
	KindAircraft = "aircraft"
	KindOperator = "operator"
	KindSerial   = "serial"
	KindExport   = "export"
	KindDownload = "download"
)

// Bounds of what a police request carries (E-10; migration 00021
// repeats them).
const (
	MaxCaseRef     = 100
	MaxQueryBytes  = 4096
	maxPurposeLen  = 64
	maxBBoxLen     = 128
	maxIdentityLen = 64
)

var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Purposes are the configured purposes of a police query (Q-A14): which
// may be named, and which of them release personal data.
type Purposes struct {
	all []string
	pii []string
}

// NewPurposes checks the configured lists: every purpose a lower-case
// code, none twice, at least one, and the personal-data ones a subset.
// The errors name the variables.
func NewPurposes(all, pii []string) (Purposes, error) {
	var errs []error
	if len(all) == 0 {
		errs = append(errs, core.Fieldf("POLICE_PURPOSES", "names no purpose"))
	}
	for i, p := range all {
		if !purposePattern.MatchString(p) {
			errs = append(errs, core.Fieldf("POLICE_PURPOSES", "%q is not 1 to 64 of [a-z0-9_] starting with a letter", p))
		} else if slices.Index(all, p) != i {
			errs = append(errs, core.Fieldf("POLICE_PURPOSES", "%q is listed twice", p))
		}
	}
	for i, p := range pii {
		if !slices.Contains(all, p) {
			errs = append(errs, core.Fieldf("POLICE_PII_PURPOSES", "%q is not one of POLICE_PURPOSES", p))
		} else if slices.Index(pii, p) != i {
			errs = append(errs, core.Fieldf("POLICE_PII_PURPOSES", "%q is listed twice", p))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Purposes{}, err
	}
	return Purposes{all: slices.Clone(all), pii: slices.Clone(pii)}, nil
}

// All lists the purposes.
func (p Purposes) All() []string { return slices.Clone(p.all) }

// PII lists the purposes that release personal data.
func (p Purposes) PII() []string { return slices.Clone(p.pii) }

// AllowsPII reports whether purpose releases personal data.
func (p Purposes) AllowsPII(purpose string) bool { return slices.Contains(p.pii, purpose) }

// Check reads a request's purpose: one of the configured list.
func (p Purposes) Check(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	switch {
	case v == "":
		return "", core.Fieldf("purpose", "required: every police query states its purpose (one of %s)", strings.Join(p.all, ", "))
	case len(v) > maxPurposeLen || !slices.Contains(p.all, v):
		return "", core.Fieldf("purpose", "%q is not one of %s", clip(v), strings.Join(p.all, ", "))
	}
	return v, nil
}

// CheckCaseRef reads a case reference: required, at most MaxCaseRef
// characters of UTF-8 without control characters, trimmed.
func CheckCaseRef(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	switch {
	case v == "":
		return "", core.Fieldf("case_ref", "required: every police query names its case")
	case !utf8.ValidString(v) || utf8.RuneCountInString(v) > MaxCaseRef:
		return "", core.Fieldf("case_ref", "at most %d characters of UTF-8", MaxCaseRef)
	case strings.IndexFunc(v, unicode.IsControl) >= 0:
		return "", core.Fieldf("case_ref", "contains a control character")
	}
	return v, nil
}

// BBox is a query's box, WGS84 degrees.
type BBox struct {
	MinLon, MinLat, MaxLon, MaxLat float64
}

// ParseBBox reads min_lon,min_lat,max_lon,max_lat: four finite numbers
// in range, min below max, and no side longer than maxSideDeg degrees.
// The error names field.
func ParseBBox(field, s string, maxSideDeg float64) (BBox, error) {
	if len(s) > maxBBoxLen {
		return BBox{}, core.Fieldf(field, "longer than %d characters", maxBBoxLen)
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return BBox{}, core.Fieldf(field, "must be min_lon,min_lat,max_lon,max_lat")
	}
	var v [4]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || !core.IsFinite(f) {
			return BBox{}, core.Fieldf(field, "every member must be a finite number")
		}
		v[i] = f
	}
	b := BBox{MinLon: v[0], MinLat: v[1], MaxLon: v[2], MaxLat: v[3]}
	switch {
	case b.MinLon < -180 || b.MaxLon > 180 || b.MinLat < -90 || b.MaxLat > 90:
		return BBox{}, core.Fieldf(field, "outside WGS84 degrees")
	case !(b.MinLon < b.MaxLon) || !(b.MinLat < b.MaxLat):
		return BBox{}, core.Fieldf(field, "min must be below max")
	case b.MaxLon-b.MinLon > maxSideDeg || b.MaxLat-b.MinLat > maxSideDeg:
		return BBox{}, core.Fieldf(field, "a side is longer than %g degrees (POLICE_MAX_BBOX_DEG): narrow the box", maxSideDeg)
	}
	return b, nil
}

// String is the box as a query parameter.
func (b BBox) String() string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	return f(b.MinLon) + "," + f(b.MinLat) + "," + f(b.MaxLon) + "," + f(b.MaxLat)
}

// checkIdentity reads a path identity (a registration number or a
// serial): trimmed, 1 to maxIdentityLen bytes of printable UTF-8.
func checkIdentity(field, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	switch {
	case v == "" || len(v) > maxIdentityLen:
		return "", core.Fieldf(field, "1 to %d characters", maxIdentityLen)
	case !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0:
		return "", core.Fieldf(field, "not printable UTF-8")
	}
	return v, nil
}

// Window is a time window of an aircraft query or an export.
type Window struct {
	From, To time.Time
	Live     bool
	AsOf     time.Time
}

// windowFor places an aircraft query on now (the telemetry database's
// clock): live without at, else at with atWindow either side, refused
// in the future or older than maxAge.
func windowFor(at *time.Time, now time.Time, live, atWindow, maxAge time.Duration) (Window, error) {
	if at == nil {
		return Window{From: now.Add(-live), To: now, Live: true, AsOf: now}, nil
	}
	t := at.UTC()
	switch {
	case t.After(now):
		return Window{}, core.Fieldf("at", "in the future")
	case now.Sub(t) > maxAge:
		return Window{}, core.Fieldf("at", "older than the online retention (%s, POLICE_HISTORY_MAX_AGE_S)", maxAge)
	}
	to := t.Add(atWindow)
	if to.After(now) {
		to = now
	}
	return Window{From: t.Add(-atWindow), To: to, AsOf: t}, nil
}

// clip bounds a value echoed into an error.
func clip(v string) string {
	v = strings.ToValidUTF8(v, "?")
	if len(v) > 64 {
		v = v[:64]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}
