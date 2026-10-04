package police

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/logging"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// ExportRequest is POST /v1/police/exports: exactly one of IncidentID
// and BBox.
type ExportRequest struct {
	Purpose    string
	CaseRef    string
	From, To   time.Time
	IncidentID string
	BBox       *string
}

// piiPurpose reads a purpose that must release personal data (a legal
// pack carries it).
func (s *Service) piiPurpose(raw string) (string, error) {
	purpose, err := s.Purposes.Check(raw)
	if err != nil {
		return "", err
	}
	if !s.Purposes.AllowsPII(purpose) {
		return "", httpx.Refuse(http.StatusForbidden, SlugPurposeNotPII,
			"a legal evidence pack carries personal data: the purpose must be one of POLICE_PII_PURPOSES",
			core.Fieldf("purpose", "%q answers status only", purpose))
	}
	return purpose, nil
}

// exportAircraft is the incident aircraft of what the picture held in
// box over w: one per track, its identity as identified.
func (s *Service) exportAircraft(seen []sighting) []incidents.Aircraft {
	out := make([]incidents.Aircraft, 0, len(seen))
	for i := range seen {
		r := &seen[i].row
		a := incidents.Aircraft{Serial: r.Serial, RegistryUASID: r.RegistryUasID, TrackIDs: []string{r.TrackID},
			Identification: incidents.Identification{Status: r.IdentStatus, Reason: r.IdentReason, Basis: r.IdentBasis, EvidenceTrust: r.Trust}}
		if reg := s.registration(r); reg != "" {
			a.OperatorReg = &reg
		}
		out = append(out, a)
	}
	return out
}

// Export builds a legal evidence pack for an incident, or for the
// aircraft the picture held in a box over the window (opening the
// authority's case file for it). The export is recorded before the
// build; the pack's events rows carry the query and the case.
func (s *Service) Export(ctx context.Context, r ExportRequest) (gen.PoliceExport, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return gen.PoliceExport{}, err
	}
	purpose, err := s.piiPurpose(r.Purpose)
	if err != nil {
		return gen.PoliceExport{}, err
	}
	caseRef, err := CheckCaseRef(r.CaseRef)
	if err != nil {
		return gen.PoliceExport{}, err
	}
	if (r.IncidentID == "") == (r.BBox == nil) {
		return gen.PoliceExport{}, core.Fieldf("incident_id", "give exactly one of incident_id and query")
	}
	if r.From.IsZero() || !r.To.After(r.From) {
		return gen.PoliceExport{}, core.Fieldf("to", "must be after from")
	}
	from, to := r.From.UTC(), r.To.UTC()
	// The pack's own checks (its window above all) come before any read,
	// record or opened incident: a request the pack would refuse leaves
	// no orphan incident and spends no budget.
	packReq := incidents.PackRequest{Kind: incidents.KindLegal, From: from, To: to, Purpose: purpose, CaseRef: caseRef}
	if err := s.Packs.CheckRequest(true, packReq); err != nil {
		return gen.PoliceExport{}, err
	}
	query := map[string]any{"from": from, "to": to}
	var (
		count    int
		aircraft []incidents.Aircraft
		box      BBox
	)
	if r.IncidentID != "" {
		if !ulidPattern.MatchString(r.IncidentID) {
			return gen.PoliceExport{}, core.Fieldf("incident_id", "not an incident id")
		}
		query["incident_id"] = r.IncidentID
		rctx, cancel := s.bounded(ctx)
		view, err := s.Incidents.Get(rctx, r.IncidentID)
		cancel()
		if err != nil {
			return gen.PoliceExport{}, err
		}
		count = len(view.Aircraft)
	} else {
		if box, err = ParseBBox("query.bbox", *r.BBox, s.Limits.MaxBBoxDeg); err != nil {
			return gen.PoliceExport{}, err
		}
		query["bbox"] = box.String()
		rctx, cancel := s.bounded(ctx)
		seen, truncated, err := s.readAircraft(rctx, box, Window{From: from, To: to}, incidents.MaxAircraft, false)
		cancel()
		if err != nil {
			return gen.PoliceExport{}, err
		}
		if truncated {
			return gen.PoliceExport{}, httpx.Refuse(http.StatusRequestEntityTooLarge, SlugTooManyAircraft,
				"the picture held more aircraft in the box over the window than one case file holds; narrow the box or the window",
				core.Fieldf("query.bbox", "more than %d aircraft", incidents.MaxAircraft))
		}
		aircraft = s.exportAircraft(seen)
		count = len(aircraft)
	}
	e := Entry{Kind: KindExport, Purpose: purpose, CaseRef: caseRef, Query: query, ResultCount: count, PII: true, Caller: c}
	if err := s.record(ctx, &e); err != nil {
		return gen.PoliceExport{}, err
	}
	pctx := piiContext(ctx, &e)
	incidentID, opened := r.IncidentID, false
	if r.BBox != nil {
		if count == 0 {
			return gen.PoliceExport{}, httpx.Refuse(http.StatusUnprocessableEntity, SlugNothingToExport,
				"the picture held no aircraft in the box over the window; the query is recorded")
		}
		view, err := s.Incidents.OpenForPolice(pctx, c.Actor, incidents.PoliceRequest{Agency: c.Agency, CaseRef: caseRef, OccurredAt: from,
			Narrative: fmt.Sprintf("Opened by a police export (agency %s, case %s) of the box %s over [%s, %s).", c.Agency, caseRef,
				box.String(), from.Format(time.RFC3339), to.Format(time.RFC3339)), Aircraft: aircraft})
		if err != nil {
			return gen.PoliceExport{}, err
		}
		incidentID, opened = view.Incident.IncidentID, true
	}
	pack, err := s.Packs.Create(pctx, c.Actor, true, incidentID, packReq)
	if err != nil {
		return gen.PoliceExport{}, err
	}
	s.inc(CounterExports)
	if err := s.Ledger.InsertExport(context.WithoutCancel(ctx), Export{PackID: pack.PackID, IncidentID: incidentID, QueryID: e.ID,
		Agency: c.Agency, UserID: c.UserID}); err != nil {
		// The pack is built and recorded (evidence_pack_built); only the
		// agency's link is missing, so its download is refused (404)
		// until an admin hands it over: fail closed, said loudly.
		s.inc(CounterExportNotLinked)
		logging.Error(ctx, s.logger(), "police export built but not linked to its agency", err,
			slog.String("pack_id", pack.PackID), slog.String("agency", c.Agency))
		return gen.PoliceExport{}, err
	}
	return exportOut(&e, &pack, opened), nil
}

func exportOut(e *Entry, p *pggen.EvidencePack, opened bool) gen.PoliceExport {
	return gen.PoliceExport{QueryId: e.ID, Purpose: e.Purpose, CaseRef: e.CaseRef, PiiReleased: true, PackId: p.PackID,
		IncidentId: p.IncidentID, IncidentOpened: opened, From: p.WindowFrom.UTC(), To: p.WindowTo.UTC(), ContentHash: p.ContentHash,
		SizeBytes: p.SizeBytes, Signature: p.Signature, SignatureKid: p.SignatureKid, CreatedAt: p.CreatedAt.UTC(),
		Download: "/v1/police/exports/" + p.PackID + "/download"}
}

// Download serves a pack exported for the caller's agency, after
// recording the download; WP-17 checks the hash before a byte is served
// and records evidence_pack_downloaded.
func (s *Service) Download(ctx context.Context, packID, rawPurpose, rawCaseRef string) ([]byte, pggen.EvidencePack, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, pggen.EvidencePack{}, err
	}
	purpose, err := s.piiPurpose(rawPurpose)
	if err != nil {
		return nil, pggen.EvidencePack{}, err
	}
	caseRef, err := CheckCaseRef(rawCaseRef)
	if err != nil {
		return nil, pggen.EvidencePack{}, err
	}
	x, found, err := s.Ledger.ExportByPack(ctx, packID)
	if err != nil {
		return nil, pggen.EvidencePack{}, err
	}
	if !found || x.Agency != c.Agency {
		if found {
			s.inc(CounterRefusedAgency)
			s.refused(ctx, c, "not_this_agency", map[string]any{"pack_id": packID, "case_ref": caseRef})
		}
		return nil, pggen.EvidencePack{}, httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no export of this agency has this pack",
			core.Fieldf("pack_id", "not an export of agency %q", c.Agency))
	}
	e := Entry{Kind: KindDownload, Purpose: purpose, CaseRef: caseRef,
		Query: map[string]any{"pack_id": packID, "incident_id": x.IncidentID, "export_query_id": x.QueryID}, ResultCount: 1, PII: true, Caller: c}
	if err := s.record(ctx, &e); err != nil {
		return nil, pggen.EvidencePack{}, err
	}
	data, row, err := s.Packs.Download(piiContext(ctx, &e), c.Actor, true, x.IncidentID, packID, purpose)
	if err != nil {
		return nil, row, err
	}
	s.inc(CounterDownloads)
	return data, row, nil
}
