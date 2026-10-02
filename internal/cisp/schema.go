package cisp

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-authority/api/clients"
)

// The CISP's schemas this system validates against (the CISP owns
// them, M7; pinned in api/clients/cisp-schemas with api/clients/SOURCE).
const (
	SchemaUSpaceRequirements = "cis/uspace_requirements/v1"
	SchemaUSSPList           = "cis/ussp_list/v1"
)

// Schemas holds the compiled pinned schemas.
type Schemas struct {
	byName map[string]*jsonschema.Schema
}

// LoadSchemas compiles the pinned copies embedded from api/clients. The
// compiler asserts formats (date-time, uri) and loads nothing from the
// network: every schema it needs is added as a resource first.
func LoadSchemas() (*Schemas, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	s := &Schemas{byName: map[string]*jsonschema.Schema{}}
	ids := map[string]string{}
	for _, name := range []string{SchemaUSpaceRequirements, SchemaUSSPList} {
		raw, err := fs.ReadFile(clients.CISPSchemas, "cisp-schemas/"+name+".json")
		if err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", name, err)
		}
		m, ok := doc.(map[string]any)
		id, _ := m["$id"].(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("pinned schema %s has no $id", name)
		}
		if err := c.AddResource(id, doc); err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", name, err)
		}
		ids[name] = id
	}
	for name, id := range ids {
		sch, err := c.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("pinned schema %s does not compile: %w", name, err)
		}
		s.byName[name] = sch
	}
	return s, nil
}

// Validate checks raw against the named schema and returns every
// problem, its field the JSON path under prefix ("" is the document
// itself, named "$"), sorted by field.
func (s *Schemas) Validate(name string, raw []byte, prefix string) []*core.FieldError {
	sch, ok := s.byName[name]
	if !ok {
		return []*core.FieldError{core.Fieldf(orRoot(prefix), "no pinned schema %s", name)}
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return []*core.FieldError{core.Fieldf(orRoot(prefix), "not JSON")}
	}
	err = sch.Validate(inst)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []*core.FieldError{core.Fieldf(orRoot(prefix), "%s", err.Error())}
	}
	var out []*core.FieldError
	seen := map[string]bool{}
	for _, leaf := range leaves(ve) {
		field := joinPath(prefix, leaf.InstanceLocation)
		reason := leafReason(leaf)
		if key := field + "\x00" + reason; !seen[key] {
			seen[key] = true
			out = append(out, &core.FieldError{Field: field, Reason: reason})
		}
	}
	slices.SortStableFunc(out, func(a, b *core.FieldError) int { return strings.Compare(a.Field, b.Field) })
	return out
}

// leaves are the failures that caused ve: the errors without causes.
func leaves(ve *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(ve.Causes) == 0 {
		return []*jsonschema.ValidationError{ve}
	}
	var out []*jsonschema.ValidationError
	for _, c := range ve.Causes {
		out = append(out, leaves(c)...)
	}
	return out
}

// leafReason is the error's text without the location prefix the
// library writes.
func leafReason(ve *jsonschema.ValidationError) string {
	u := ve.BasicOutput()
	if u != nil && u.Error != nil {
		return u.Error.String()
	}
	for _, e := range u.Errors {
		if e.Error != nil {
			return e.Error.String()
		}
	}
	return "does not match the schema"
}

// joinPath writes a JSON pointer's tokens as the dotted path the
// problems use (ussps[0].base_url) under prefix.
func joinPath(prefix string, tokens []string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, t := range tokens {
		if _, err := strconv.Atoi(t); err == nil {
			b.WriteString("[" + t + "]")
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(t)
	}
	return orRoot(b.String())
}

func orRoot(s string) string {
	if s == "" {
		return "$"
	}
	return s
}
