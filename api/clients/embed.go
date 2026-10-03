// Package clients holds the pinned copies of the sibling contracts this
// system calls (api/clients/SOURCE, reconciliation M11): the CISP's
// OpenAPI file, from which internal/cisp/cispclient is generated, and
// the CISP's JSON Schemas, embedded here so internal/cisp validates a
// publication against the copy CI compares with the CISP's commit; and
// the ANSP's OpenAPI file with its track/manned/v1 schema (WP-15), which
// internal/manned validates every manned body against.
package clients

import "embed"

// CISPSchemas is cisp-schemas/: the CISP's cis/* schemas and examples
// at the commit api/clients/SOURCE records.
//
//go:embed cisp-schemas
var CISPSchemas embed.FS

// ANSPSchemas is ansp-schemas/: the ANSP's track/manned/v1 schema, the
// envelope it references and the ANSP's examples, at the commit
// api/clients/SOURCE records (WP-15).
//
//go:embed ansp-schemas
var ANSPSchemas embed.FS
