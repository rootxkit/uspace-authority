package zonesvc

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// Format is the format an import was read as.
type Format string

// The import formats, detected by their wrapper.
const (
	FormatED318 Format = "ed318"
	FormatED269 Format = "ed269"
)

// DefaultLang is the language of an ED-269 file's texts when the import
// does not name one.
const DefaultLang = "en-GB"

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// detect names the format of an import by its wrapper: a top-level
// `type` (FeatureCollection) is ED-318; `UASZoneList`, or `features`
// without `type`, is ED-269 (LESSONS Z-03: both published ED-269
// wrappers). Anything else is read as ED-318, whose parser then says
// what is wrong with it.
func detect(raw []byte) Format {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &top); err != nil {
		return FormatED318
	}
	if _, ok := top[ed269.WrapperUASZoneList]; ok {
		return FormatED269
	}
	if _, ok := top["type"]; ok {
		return FormatED318
	}
	if _, ok := top[ed269.WrapperFeatures]; ok {
		return FormatED269
	}
	return FormatED318
}

// Imported is an import read and checked: one checked feature per zone,
// the format, and the period of validity the ED-318 metadata gave.
type imported struct {
	format   Format
	features []checked
	metaFrom *time.Time
	metaTo   *time.Time
}

// readImport reads a whole import, all or nothing (LESSONS Z-02): an
// ED-318 collection through ed318.Parse, an ED-269 document through
// ed269.Parse and ed318.FromED269 (what ED-318 cannot hold is refused
// by name), then every zone through the checks a single write gets. On
// any problem nothing is returned but every problem by JSON path,
// capped, with the count beyond the cap. Every zone must belong to ds;
// an empty ds takes each zone's own (the vector tests' round trip).
func readImport(raw []byte, lang string, ds Dataset) (*imported, []*core.FieldError, int) {
	if len(raw) > MaxDocumentBytes {
		return nil, []*core.FieldError{core.Fieldf("$", "is %d bytes; at most %d", len(raw), MaxDocumentBytes)}, 0
	}
	if lang == "" {
		lang = DefaultLang
	}
	format := detect(raw)
	var fc *ed318.FeatureCollection
	if format == FormatED269 {
		doc, probs := ed269.Parse(raw, ed269.Limits{})
		if probs != nil {
			errs, more := problemErrors(probs, identity)
			return nil, errs, more
		}
		var err error
		if fc, err = ed318.FromED269(doc, ed318.Metadata{}, lang); err != nil {
			return nil, []*core.FieldError{asField(err, "$")}, 0
		}
	} else {
		var probs *ed269.Problems
		if fc, probs = ed318.Parse(raw, ed318.Limits{}); probs != nil {
			errs, more := problemErrors(probs, identity)
			return nil, errs, more
		}
	}
	if len(fc.Features) == 0 {
		return nil, []*core.FieldError{core.Fieldf("features", "no zone to import")}, 0
	}
	features, errs, more := checkCollection(fc, ds, identity)
	if len(errs) > 0 {
		return nil, errs, more
	}
	out := &imported{format: format, features: features}
	if m := fc.Metadata; m != nil {
		if m.ValidFrom != nil {
			t := m.ValidFrom.Time
			out.metaFrom = &t
		}
		if m.ValidTo != nil {
			t := m.ValidTo.Time
			out.metaTo = &t
		}
	}
	return out, nil, 0
}
