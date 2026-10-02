// Package clients holds the pinned copies of the sibling contracts this
// system calls (api/clients/SOURCE, reconciliation M11): the CISP's
// OpenAPI file, from which internal/cisp/cispclient is generated, and
// the CISP's JSON Schemas, embedded here so internal/cisp validates a
// publication against the copy CI compares with the CISP's commit.
package clients

import "embed"

// CISPSchemas is cisp-schemas/: the CISP's cis/* schemas and examples
// at the commit api/clients/SOURCE records.
//
//go:embed cisp-schemas
var CISPSchemas embed.FS
