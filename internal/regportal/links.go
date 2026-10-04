package regportal

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/occurrences"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// RequestLink mails a single-use occurrence-report link to the e-mail
// address the registry holds for the registration number, when the
// registration is in good standing. The answer is the same whatever the
// number (nil), so the request reveals nothing; only the client
// address's budget is refused (429). A link past the operator's own
// budget, or for a number not in good standing, is not mailed (counted).
func (s *Service) RequestLink(ctx context.Context, number, lang, remoteIP string) error {
	if err := s.needOperatorReports(); err != nil {
		return err
	}
	number = strings.TrimSpace(number)
	if number == "" || len(number) > regnum.MaxLen {
		return core.Fieldf("registration_number", "required, at most %d characters", regnum.MaxLen)
	}
	if lang == "" {
		lang = "en"
	}
	if !validLang(lang) {
		return core.Fieldf("lang", "must be en or ka")
	}
	ipHash := s.Signer.Hash("ip", remoteIP)
	// The address's budget is spent first and on its own: every request
	// counts, whatever the number names.
	if err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		return spend(ctx, q, BucketLinkIP, ipHash, s.Config.LinksIP, s.Config.Window)
	}); err != nil {
		return s.budget(err)
	}
	contact, found, err := s.Registry.ContactForLink(ctx, number)
	if err != nil {
		return err
	}
	if !found || !contact.Valid || contact.ContactEmail == "" {
		s.count(CounterLinksUnmailed)
		return nil
	}
	linkID, err := newID()
	if err != nil {
		return err
	}
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := spend(ctx, q, BucketLinkOperator, s.Signer.Hash("operator", contact.OperatorID), s.Config.LinksOperator, s.Config.Window); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		exp := now.Add(s.Config.LinkTTL)
		tok, err := s.Signer.Sign(Claims{Purpose: PurposeOperator, Subject: contact.OperatorID, Link: linkID,
			Number: contact.RegistrationNumber, Exp: exp.Unix()})
		if err != nil {
			return err
		}
		if err := s.queueMail(ctx, q, MailLink, lang, "", Message{To: contact.ContactEmail, Vars: map[string]string{
			"number": contact.RegistrationNumber, "expires": stamp(exp), "link": s.link("/occurrences/new", tok),
		}}); err != nil {
			return err
		}
		return s.record(ctx, q, audit.Event{Actor: applicantActor(), EntityType: "uas_operator", EntityID: contact.OperatorID,
			EventType: audit.EventRegistryOperatorLinkRequested, Payload: map[string]any{
				"registration_number": contact.RegistrationNumber, "link_id": linkID, "expires_at": exp.UTC(), "remote_ip_hash": ipHash,
			}})
	})
	var be *BudgetSpentError
	if errors.As(err, &be) {
		// The operator's own budget: answered as any other request, so
		// a caller learns nothing about the number.
		s.count(CounterLinksUnmailed)
		return nil
	}
	if err != nil {
		return err
	}
	s.count(CounterLinksMailed)
	return nil
}

func linkRefused(detail string) error {
	return httpx.Refuse(http.StatusUnauthorized, SlugLinkSpent, detail)
}

// ReportOccurrence takes an operator's occurrence report through its
// link: the body is checked first (WP-18's Normalise, nothing spent on
// a bad body), then the link is verified and spent once (by the
// database clock, the spend and its events row in one transaction), then
// WP-18's intake stores the report as operator:<public part> on the
// mandatory channel. A link spent already or expired is 401 link_spent.
// A failure of the intake after the spend leaves the link spent: the
// operator asks for another.
func (s *Service) ReportOccurrence(ctx context.Context, tok string, body *gen.OccurrenceReport) (occurrences.Receipt, error) {
	if err := s.needOperatorReports(); err != nil {
		return occurrences.Receipt{}, err
	}
	c, err := s.Signer.Verify(tok, PurposeOperator)
	if err != nil || c.Link == "" || c.Number == "" {
		s.count(CounterTokenRefused)
		return occurrences.Receipt{}, httpx.Refuse(http.StatusUnauthorized, httpx.SlugUnauthn, "the link token does not verify")
	}
	in, err := occurrences.Normalise(body, s.PublicPart)
	if err != nil {
		return occurrences.Receipt{}, err
	}
	actor := applicantActor()
	origin, err := occurrences.OperatorOrigin(actor, c.Number, s.PublicPart)
	if err != nil {
		return occurrences.Receipt{}, err
	}
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		spent, err := q.SpendPortalLink(ctx, pggen.SpendPortalLinkParams{LinkID: c.Link, ExpiresAt: c.Expires()})
		if err != nil {
			return err
		}
		if !spent {
			s.count(CounterLinkSpent)
			return linkRefused("this link was used already or has expired; ask for another")
		}
		return s.record(ctx, q, audit.Event{Actor: actor, EntityType: "uas_operator", EntityID: c.Subject,
			EventType: audit.EventRegistryOperatorLinkUsed, Payload: map[string]any{
				"registration_number": c.Number, "link_id": c.Link, "report_ref": in.ReportRef,
			}})
	})
	if err != nil {
		return occurrences.Receipt{}, err
	}
	rc, err := s.Occurrences.Intake(ctx, origin, in)
	if err != nil {
		return occurrences.Receipt{}, err
	}
	s.count(CounterOperatorReported)
	return rc, nil
}
