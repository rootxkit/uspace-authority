package regportal

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// maxRetry caps the backoff of a failed delivery.
const maxRetry = time.Hour

// purgeBatch bounds one purge run (E-10); the next run takes the rest.
const purgeBatch = 500

// Sent is what one run of the sender did.
type Sent struct {
	Sent, Retried, Failed int
}

// lastError is err's text cut to 300 bytes on a character boundary
// (the column's bound).
func lastError(err error) string {
	s := err.Error()
	if len(s) <= 300 {
		return strings.ToValidUTF8(s, "?")
	}
	s = s[:300]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// retryIn is the backoff after the attempts-th failed attempt (1-based).
func retryIn(base time.Duration, attempts int) time.Duration {
	d := base
	for i := 1; i < attempts && d < maxRetry; i++ {
		d *= 2
	}
	return min(d, maxRetry)
}

// SendDue delivers the messages due now (database clock), at most a
// batch, one at a time and with nothing slow inside a transaction: each
// message is claimed by a statement that commits on its own and leases
// it (another replica skips it meanwhile), delivered outside any
// transaction, and its outcome committed in a transaction of its own
// with its events row. A delivered message is marked sent and its
// content cleared; a failed one waits for its retry, doubling, until its
// attempts are spent or the relay refuses it for good (5xx), when it is
// failed and its content cleared. A message is sent at least once: a
// crash between the delivery and the commit sends it again when its
// lease ends.
func (s *Service) SendDue(ctx context.Context) (Sent, error) {
	var out Sent
	lease := 2 * s.mailTimeout()
	for range max(1, s.Config.MailBatch) {
		r, err := s.DB.Queries().ClaimPortalMail(ctx, lease.Seconds())
		if store.IsNoRows(err) {
			break
		}
		if err != nil {
			return out, err
		}
		sendErr := s.deliver(ctx, &r)
		if err := s.DB.WithTx(ctx, func(q *gen.Queries) error { return s.settle(ctx, q, &r, sendErr, &out) }); err != nil {
			return out, err
		}
	}
	return out, nil
}

// settle records one delivery's outcome, counting it in out.
func (s *Service) settle(ctx context.Context, q *gen.Queries, r *gen.RegistryPortalMail, sendErr error, out *Sent) error {
	if sendErr == nil {
		if err := q.PortalMailSent(ctx, r.ID); err != nil {
			return err
		}
		if err := s.mailEvent(ctx, q, r, audit.EventRegistryPortalMailSent, nil); err != nil {
			return err
		}
		out.Sent++
		s.count(CounterMailSent)
		return nil
	}
	attempts := int(r.Attempts) + 1
	var perm *PermanentError
	if errors.As(sendErr, &perm) || attempts >= s.Config.MailMaxAttempts {
		if err := q.PortalMailFailed(ctx, gen.PortalMailFailedParams{ID: r.ID, LastError: ptr(lastError(sendErr))}); err != nil {
			return err
		}
		if err := s.mailEvent(ctx, q, r, audit.EventRegistryPortalMailFailed, sendErr); err != nil {
			return err
		}
		out.Failed++
		s.count(CounterMailFailed)
		s.limited("regportal_mail_failed").Error("a portal e-mail was given up; its content is cleared",
			slog.Int64("mail_id", r.ID), slog.String("kind", r.Kind), slog.Int("attempts", attempts), slog.String("error", lastError(sendErr)))
		return nil
	}
	if err := q.PortalMailRetry(ctx, gen.PortalMailRetryParams{ID: r.ID, LastError: ptr(lastError(sendErr)),
		RetryInS: retryIn(s.Config.MailRetry, attempts).Seconds()}); err != nil {
		return err
	}
	out.Retried++
	s.count(CounterMailRetried)
	s.limited("regportal_mail_retry").Warn("a portal e-mail was not delivered; it is retried",
		slog.Int64("mail_id", r.ID), slog.String("kind", r.Kind), slog.Int("attempts", attempts), slog.String("error", lastError(sendErr)))
	return nil
}

// mailTimeout bounds one delivery.
func (s *Service) mailTimeout() time.Duration { return max(time.Second, s.Config.MailTimeout) }

func ptr[T any](v T) *T { return &v }

func (s *Service) deliver(ctx context.Context, r *gen.RegistryPortalMail) error {
	if s.Mailer == nil {
		return errors.New("no mailer configured")
	}
	var m Message
	if err := s.open(r.PiiKeyID, mailAAD(r.Kind, deref(r.ApplicationID)), r.MessageEnc, &m); err != nil {
		return &PermanentError{Err: err}
	}
	subject, body, err := s.Catalogue.Render(r.Kind, r.Lang, m)
	if err != nil {
		return &PermanentError{Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, s.mailTimeout())
	defer cancel()
	return s.Mailer.Send(ctx, m.To, subject, body)
}

func (s *Service) mailEvent(ctx context.Context, q *gen.Queries, r *gen.RegistryPortalMail, eventType string, cause error) error {
	payload := map[string]any{"mail_id": r.ID, "kind": r.Kind, "attempts": int(r.Attempts) + 1}
	if cause != nil {
		payload["error"] = lastError(cause)
	}
	entityType, entityID := "registry_portal_mail", ""
	if r.ApplicationID != nil {
		entityType, entityID = applicationTableName, *r.ApplicationID
	}
	return s.record(ctx, q, audit.Event{Actor: audit.SystemActor("registry_portal_mail"), EntityType: entityType, EntityID: entityID,
		EventType: eventType, Payload: payload})
}

// Purged is what one purge did.
type Purged struct {
	Applications, Hits, Links, Mail int64
}

// Purge deletes the applications past their retention (decided ones
// REGISTRY_APPLICATIONS_RETAIN_S after the decision, unverified ones a
// link lifetime after their link expired; their mail goes with them), the
// spent links past their expiry, the budget rows older than the window
// and the delivered link mail past the retention, in one transaction
// with one events row when anything went. The operator an approval
// registered stays in the registry.
func (s *Service) Purge(ctx context.Context) (Purged, error) {
	var out Purged
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		apps, err := q.PurgeApplications(ctx, gen.PurgeApplicationsParams{RetainS: s.Config.Retain.Seconds(),
			UnverifiedGraceS: s.Config.VerifyTTL.Seconds(), Batch: purgeBatch})
		if err != nil {
			return err
		}
		out.Applications = int64(len(apps))
		if out.Hits, err = q.PurgePortalHits(ctx, s.Config.Window.Seconds()); err != nil {
			return err
		}
		if out.Links, err = q.PurgePortalLinks(ctx, 0); err != nil {
			return err
		}
		if out.Mail, err = q.PurgePortalMail(ctx, s.Config.Retain.Seconds()); err != nil {
			return err
		}
		if out.Applications == 0 && out.Links == 0 && out.Mail == 0 {
			return nil
		}
		states := map[string]int{}
		ids := make([]string, 0, len(apps))
		for _, a := range apps {
			states[a.State]++
			ids = append(ids, a.ID)
		}
		return s.record(ctx, q, audit.Event{Actor: audit.SystemActor("registry_portal_purge"), EntityType: applicationTableName,
			EventType: audit.EventRegistryApplicationsPurged, Payload: map[string]any{
				"applications": out.Applications, "by_state": states, "application_ids": ids, "links": out.Links,
				"mail": out.Mail, "retain_s": int64(s.Config.Retain.Seconds()),
			}})
	})
	if err != nil {
		return Purged{}, err
	}
	for range out.Applications {
		s.count(CounterPurged)
	}
	return out, nil
}

// Run runs the sender every mailEvery and the purge every purgeEvery
// until ctx ends, each a failure logged and retried on its next period.
func (s *Service) Run(ctx context.Context, mailEvery, purgeEvery time.Duration) {
	mail := time.NewTicker(mailEvery)
	defer mail.Stop()
	purge := time.NewTicker(purgeEvery)
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-mail.C:
			if _, err := s.SendDue(ctx); err != nil && ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "portal mail sender failed; it runs again next period", err)
			}
		case <-purge.C:
			if _, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "portal purge failed; it runs again next period", err)
			}
		}
	}
}
