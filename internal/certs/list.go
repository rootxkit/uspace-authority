package certs

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// ListSchema is the CISP's schema of the USSP list (M7; pinned under
// api/clients/cisp-schemas/cis/ussp_list/v1.json).
const ListSchema = "cis/ussp_list/v1"

// MaxListed bounds the USSP list (cis/ussp_list/v1 ussps maxItems).
const MaxListed = 200

// USSPList is cis/ussp_list/v1 as the authority publishes it: without
// the cis_* members the CISP adds when it serves the list.
type USSPList struct {
	Schema string      `json:"schema"`
	Issued time.Time   `json:"issued"`
	USSPs  []ListEntry `json:"ussps"`
}

// ListEntry is one USSP of the list.
type ListEntry struct {
	USSPID                   string      `json:"ussp_id"`
	Name                     string      `json:"name"`
	Contact                  ListContact `json:"contact"`
	CertificateID            string      `json:"certificate_id"`
	BaseURL                  string      `json:"base_url"`
	Services                 []string    `json:"services"`
	CertificationLimitations []string    `json:"certification_limitations"`
	ValidFrom                time.Time   `json:"valid_from"`
	ValidUntil               time.Time   `json:"valid_until"`
	TermsURL                 string      `json:"terms_url"`
	Status                   string      `json:"status"`
}

// ListContact is the organisation's published contact; an empty member
// is left out (the schema's minimum lengths).
type ListContact struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URL   string `json:"url,omitempty"`
}

// ErrListTooLong is a list past MaxListed: refused, never cut (a USSP
// silently left off the list is a USSP hidden).
var ErrListTooLong = fmt.Errorf("more than %d USSPs operate; the list cannot be published", MaxListed)

// BuildList is the USSP list of rows (ListedUSSPCertificates, by code)
// issued at issued: ussp_id is the certificate's code (M8), the
// limitations are the certification limitations, the validity is the
// certificate's. The CISP's own checks (the pinned schema, unique ids)
// are applied by the outbox before anything is signed.
func BuildList(rows []pggen.Certificate, issued time.Time) ([]byte, int, error) {
	if len(rows) > MaxListed {
		return nil, 0, ErrListTooLong
	}
	l := USSPList{Schema: ListSchema, Issued: issued.UTC().Truncate(time.Second), USSPs: make([]ListEntry, 0, len(rows))}
	for i := range rows {
		r := &rows[i]
		limits := slices.Clone(r.Limitations)
		if limits == nil {
			limits = []string{}
		}
		l.USSPs = append(l.USSPs, ListEntry{
			USSPID: r.Code, Name: r.HolderName,
			Contact:       ListContact{Email: r.HolderEmail, Phone: r.HolderPhone, URL: r.HolderUrl},
			CertificateID: r.ID, BaseURL: r.BaseUrl, Services: slices.Clone(r.Services),
			CertificationLimitations: limits, ValidFrom: r.IssuedAt.UTC(), ValidUntil: r.ValidUntil.UTC(),
			TermsURL: r.TermsUrl, Status: r.Status,
		})
	}
	b, err := json.Marshal(l)
	return b, len(l.USSPs), err
}
