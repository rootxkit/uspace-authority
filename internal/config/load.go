package config

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// LookupFunc reads one environment variable; os.LookupEnv in production,
// a map in tests.
type LookupFunc func(name string) (string, bool)

// Struct tags understood by Load, written by hand (no library):
//
//	env:"NAME"          the variable (required on every leaf field)
//	default:"value"     used when the variable is unset or empty
//	required:"true"     unset or empty is an error naming the variable
//	secret:"true"       redacted by String and Help shows no default
//	enum:"a|b"          the value must be one of these
//	kind:"url"          the value must parse as an absolute URL
//	min:"n" / max:"n"   bounds of an integer or a float
//	help:"text"         one line for --help
//
// Supported field types: string, bool, int, float64, time.Duration
// (Go syntax, "15s"), []string (comma-separated, trimmed). A nested
// struct field without an env tag is walked (Common is embedded that
// way).

const redacted = "<redacted>"

// Load fills cfg (a pointer to a struct) from lookup and validates it.
// Every problem is a *core.FieldError whose Field is the variable name;
// all of them are returned, joined, so a deployment sees every mistake
// in one run.
func Load(cfg any, lookup LookupFunc) error {
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return &core.FieldError{Field: "config", Reason: "load needs a pointer to a struct"}
	}
	var errs []error
	walk(v.Elem(), func(f reflect.Value, sf reflect.StructField) {
		if err := loadField(f, sf, lookup); err != nil {
			errs = append(errs, err)
		}
	})
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if val, ok := cfg.(interface{ Validate() error }); ok {
		return val.Validate()
	}
	return nil
}

// FieldErrors flattens a Load error into its *core.FieldError parts.
func FieldErrors(err error) []*core.FieldError {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []*core.FieldError
		for _, e := range j.Unwrap() {
			out = append(out, FieldErrors(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return []*core.FieldError{fe}
	}
	return nil
}

func walk(v reflect.Value, fn func(reflect.Value, reflect.StructField)) {
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		f := v.Field(i)
		if _, ok := sf.Tag.Lookup("env"); !ok {
			if f.Kind() == reflect.Struct {
				walk(f, fn)
			}
			continue
		}
		fn(f, sf)
	}
}

func loadField(f reflect.Value, sf reflect.StructField, lookup LookupFunc) error {
	name := sf.Tag.Get("env")
	raw, ok := lookup(name)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		if sf.Tag.Get("required") == "true" {
			return &core.FieldError{Field: name, Reason: "required"}
		}
		raw = sf.Tag.Get("default")
		if raw == "" {
			return nil
		}
	}
	if enum := sf.Tag.Get("enum"); enum != "" && !slices.Contains(strings.Split(enum, "|"), raw) {
		return core.Fieldf(name, "must be one of %s", strings.ReplaceAll(enum, "|", ", "))
	}
	if sf.Tag.Get("kind") == "url" {
		if err := checkURL(raw); err != nil {
			return &core.FieldError{Field: name, Reason: err.Error()}
		}
	}
	return setValue(f, name, raw, sf)
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return errors.New("must be an absolute URL with a scheme and a host")
	}
	return nil
}

var durationType = reflect.TypeFor[time.Duration]()

func setValue(f reflect.Value, name, raw string, sf reflect.StructField) error {
	switch {
	case f.Type() == durationType:
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return core.Fieldf(name, "must be a positive duration such as 15s")
		}
		f.SetInt(int64(d))
	case f.Kind() == reflect.String:
		f.SetString(raw)
	case f.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return core.Fieldf(name, "must be true or false")
		}
		f.SetBool(b)
	case f.Kind() == reflect.Int:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return core.Fieldf(name, "must be an integer")
		}
		if err := bounds(name, float64(n), sf); err != nil {
			return err
		}
		f.SetInt(int64(n))
	case f.Kind() == reflect.Float64:
		x, err := strconv.ParseFloat(raw, 64)
		if err != nil || !core.IsFinite(x) {
			return core.Fieldf(name, "must be a finite number")
		}
		if err := bounds(name, x, sf); err != nil {
			return err
		}
		f.SetFloat(x)
	case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
		var out []string
		for p := range strings.SplitSeq(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		f.Set(reflect.ValueOf(out))
	default:
		return core.Fieldf(name, "unsupported field type %s", f.Type())
	}
	return nil
}

func bounds(name string, x float64, sf reflect.StructField) error {
	if s := sf.Tag.Get("min"); s != "" {
		if lo, err := strconv.ParseFloat(s, 64); err == nil && x < lo {
			return core.Fieldf(name, "must be at least %s", s)
		}
	}
	if s := sf.Tag.Get("max"); s != "" {
		if hi, err := strconv.ParseFloat(s, 64); err == nil && x > hi {
			return core.Fieldf(name, "must be at most %s", s)
		}
	}
	return nil
}

// Describe renders cfg as "NAME=value" pairs in declaration order with
// every secret redacted. The String methods of the process structs call
// it, so a configuration can be logged at start without leaking.
func Describe(cfg any) string {
	v := reflect.Indirect(reflect.ValueOf(cfg))
	var parts []string
	walk(v, func(f reflect.Value, sf reflect.StructField) {
		val := fmt.Sprint(f.Interface())
		if f.Kind() == reflect.Slice {
			val = strings.Join(f.Interface().([]string), ",")
		}
		if sf.Tag.Get("secret") == "true" {
			if f.IsZero() {
				val = ""
			} else {
				val = redacted
			}
		}
		parts = append(parts, sf.Tag.Get("env")+"="+val)
	})
	return strings.Join(parts, " ")
}

// Help lists every variable cfg reads, one per line, with whether it is
// required, its default (never for a secret) and its help text. The
// process prints it for --help.
func Help(cfg any) string {
	v := reflect.Indirect(reflect.ValueOf(cfg))
	var b strings.Builder
	walk(v, func(_ reflect.Value, sf reflect.StructField) {
		b.WriteString(sf.Tag.Get("env"))
		var notes []string
		if sf.Tag.Get("required") == "true" {
			notes = append(notes, "required")
		}
		if d := sf.Tag.Get("default"); d != "" && sf.Tag.Get("secret") != "true" {
			notes = append(notes, "default "+d)
		}
		if e := sf.Tag.Get("enum"); e != "" {
			notes = append(notes, "one of "+strings.ReplaceAll(e, "|", ", "))
		}
		if sf.Tag.Get("secret") == "true" {
			notes = append(notes, "secret")
		}
		if len(notes) > 0 {
			b.WriteString(" (" + strings.Join(notes, "; ") + ")")
		}
		if h := sf.Tag.Get("help"); h != "" {
			b.WriteString("\n    " + h)
		}
		b.WriteString("\n")
	})
	return b.String()
}
