package cisp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Defaults of the sender (CIS_SEND_*).
const (
	DefaultBackoffMin = 2 * time.Second
	DefaultBackoffMax = 5 * time.Minute
	DefaultGiveUp     = 24 * time.Hour
	// DefaultSendPoll is how often the sender looks for due rows besides
	// the wake-up of a new row.
	DefaultSendPoll = time.Second
)

// Publisher is the part of the CISP client the sender calls.
type Publisher interface {
	Publish(ctx context.Context, ds Dataset, payload []byte, contentType, ifMatch, signature string) (PublishAnswer, error)
	LatestVersion(ctx context.Context, ds Dataset) (version int64, bodySHA256 string, ok bool, err error)
}

// Locker takes the job's session advisory lock without waiting;
// acquired is false when another replica holds it.
type Locker func(ctx context.Context) (release func(), acquired bool, err error)

// NoLock is the Locker of a single process (tests).
func NoLock(context.Context) (func(), bool, error) { return func() {}, true, nil }

// Sender delivers the outbox to the CISP (spec 02 F1): in order per
// dataset, one row at a time, under the job lock, re-signing the exact
// bytes at every attempt (the CISP holds iat to five minutes):
//
//   - 2xx: acknowledged with the CISP's version;
//   - 412: the CISP's current version is read back; when its bytes are
//     this row's (an earlier attempt landed but its answer was lost) the
//     row is acknowledged, otherwise it is a conflict and the dataset
//     stops for an operator (never overwritten blindly);
//   - 5xx, 408, 429, 401, 403 or no answer: retried after an
//     exponential backoff (BackoffMin doubling, capped at BackoffMax)
//     until GiveUp after the row was written, then failed;
//   - any other refusal (400, 404, 413, 415, 428): failed at once, with
//     the CISP's problems.
//
// Every state change is an events row (OutboxStore).
type Sender struct {
	Store    OutboxStore
	CISP     Publisher
	Signer   Signer
	Lock     Locker
	Counters *core.Counters
	Logger   *slog.Logger
	Now      func() time.Time

	BackoffMin time.Duration
	BackoffMax time.Duration
	GiveUp     time.Duration

	mu        sync.Mutex
	oldest    map[Dataset]time.Time // created_at of the due row
	lastError string
}

func (s *Sender) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *Sender) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Sender) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

// Backoff is the wait after attempt n (1 for the first): BackoffMin
// doubling, at most BackoffMax.
func (s *Sender) Backoff(attempt int) time.Duration {
	lo, hi := s.BackoffMin, s.BackoffMax
	if lo <= 0 {
		lo = DefaultBackoffMin
	}
	if hi <= 0 {
		hi = DefaultBackoffMax
	}
	d := lo
	for i := 1; i < attempt && d < hi; i++ {
		d *= 2
	}
	return min(d, hi)
}

func (s *Sender) giveUp() time.Duration {
	if s.GiveUp <= 0 {
		return DefaultGiveUp
	}
	return s.GiveUp
}

// RunOnce sends every due row once, under the lock; it reports whether
// it ran (false when another replica held the lock).
func (s *Sender) RunOnce(ctx context.Context) (bool, error) {
	lock := s.Lock
	if lock == nil {
		lock = NoLock
	}
	release, ok, err := lock(ctx)
	if err != nil {
		s.count(CounterSenderErrors)
		return false, err
	}
	if !ok {
		s.count(CounterSenderSkipped)
		return false, nil
	}
	defer release()
	rows, err := s.Store.Due(ctx)
	if err != nil {
		s.count(CounterSenderErrors)
		s.setError(err)
		return true, err
	}
	oldest := map[Dataset]time.Time{}
	var errs []error
	for i := range rows {
		r := &rows[i]
		oldest[r.Dataset] = r.CreatedAt
		if r.NextRetryAt != nil && r.NextRetryAt.After(s.now()) {
			continue
		}
		if err := s.send(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	s.mu.Lock()
	s.oldest = oldest
	s.mu.Unlock()
	err = errors.Join(errs...)
	if err != nil {
		s.count(CounterSenderErrors)
	}
	s.setError(err)
	return true, err
}

func (s *Sender) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastError = ""
		return
	}
	s.lastError = short(err.Error())
}

// send makes one attempt at r. A returned error is the outbox's own
// (the database), never the CISP's answer, which is recorded on the row.
func (s *Sender) send(ctx context.Context, r *DueRow) error {
	log := s.logger().With(slog.String("dataset", string(r.Dataset)), slog.Int64("publication_id", r.ID),
		slog.Int64("version", r.Version))
	now := s.now()
	if now.Sub(r.CreatedAt) > s.giveUp() {
		s.count(CounterPublicationsFailed)
		log.Error("publication failed: not acknowledged within the retry period", slog.Float64("give_up_s", s.giveUp().Seconds()))
		return s.Store.MarkFailed(ctx, r, Outcome{Reason: fmt.Sprintf("not acknowledged within %s of being queued", s.giveUp())})
	}
	if s.Signer == nil {
		// No key: the row cannot be sent, and says so on every run.
		return s.Store.MarkFailed(ctx, r, Outcome{Reason: "no publication key is configured (PUBLICATION_KEY_FILE)"})
	}
	sig, err := s.Signer.SignDetached(r.Payload, now)
	if err != nil {
		s.count(CounterPublicationsFailed)
		return s.Store.MarkFailed(ctx, r, Outcome{Reason: "the payload could not be signed: " + short(err.Error())})
	}
	v, ok, err := s.Store.IfMatch(ctx, r.Dataset, r.ID)
	if err != nil {
		return err
	}
	if !ok {
		v = 0
	}
	ifMatch := ETagOf(r.Dataset, v)
	sending, err := s.Store.MarkSending(ctx, r, sig, s.Signer.ActiveKID(), now)
	if err != nil || !sending {
		return err
	}
	r.Attempts++
	s.count(CounterPublicationsSent)
	a, err := s.CISP.Publish(ctx, r.Dataset, r.Payload, r.ContentType, ifMatch, sig)
	if err != nil {
		return s.retry(ctx, r, Outcome{Reason: "no answer from the CISP: " + short(err.Error())}, log)
	}
	switch {
	case a.Status == http.StatusOK || a.Status == http.StatusCreated:
		s.count(CounterPublicationsAcknowledged)
		log.Info("publication acknowledged by the CISP", slog.Int64("cisp_version", a.Version), slog.Bool("unchanged", a.Unchanged))
		return s.Store.MarkAcknowledged(ctx, r, a.Version, Outcome{Status: a.Status})
	case a.Status == http.StatusPreconditionFailed:
		return s.conflict(ctx, r, a, ifMatch, log)
	case retryable(a.Status):
		return s.retry(ctx, r, Outcome{Status: a.Status, Reason: a.Problem.Error()}, log)
	}
	s.count(CounterPublicationsFailed)
	log.Error("publication refused by the CISP", slog.Int("status", a.Status), slog.String("problem", a.Problem.Error()))
	return s.Store.MarkFailed(ctx, r, Outcome{Status: a.Status, Reason: a.Problem.Error()})
}

// retryable are the answers worth sending again: the CISP or the path
// to it failing, the rate limit, and an authentication refusal (a token
// or a JWKS cache that has not caught up yet).
func retryable(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return status >= http.StatusInternalServerError
}

func (s *Sender) retry(ctx context.Context, r *DueRow, o Outcome, log *slog.Logger) error {
	wait := s.Backoff(r.Attempts)
	next := s.now().Add(wait)
	if next.Sub(r.CreatedAt) > s.giveUp() {
		next = r.CreatedAt.Add(s.giveUp()).Add(time.Second)
	}
	s.count(CounterPublicationsRetried)
	log.Warn("publication not acknowledged; retrying", slog.Int("status", o.Status), slog.String("reason", o.Reason),
		slog.Int("attempts", r.Attempts), slog.Float64("retry_in_s", next.Sub(s.now()).Seconds()))
	return s.Store.MarkRetry(ctx, r, next, o)
}

// conflict handles a 412: the CISP's current version is read back; the
// row's own bytes there mean an earlier attempt landed.
func (s *Sender) conflict(ctx context.Context, r *DueRow, a PublishAnswer, ifMatch string, log *slog.Logger) error {
	var current *int64
	if v, ok := ParseETag(r.Dataset, a.ETag); ok {
		current = &v
	}
	v, sum, ok, err := s.CISP.LatestVersion(ctx, r.Dataset)
	if err != nil {
		// The current version could not be read back: retry rather than
		// decide a conflict on half the facts.
		return s.retry(ctx, r, Outcome{Status: a.Status, Reason: "412, and the CISP's current version could not be read: " + short(err.Error())}, log)
	}
	if ok && sum == r.PayloadHash {
		s.count(CounterPublicationsAckAfter412)
		log.Info("publication acknowledged: the CISP's current version holds its bytes", slog.Int64("cisp_version", v))
		return s.Store.MarkAcknowledged(ctx, r, v, Outcome{Status: a.Status})
	}
	if ok {
		current = &v
	}
	reason := "the CISP holds another version than " + ifMatch
	if current != nil {
		reason += ": " + ETagOf(r.Dataset, *current)
	}
	s.count(CounterPublicationsConflict)
	log.Error("publication conflict: an operator decides; nothing is overwritten", slog.String("reason", reason))
	return s.Store.MarkConflict(ctx, r, current, Outcome{Status: a.Status, Reason: reason})
}

// Run sends at once, on every wake-up and every poll until ctx ends.
// A failure is counted and logged once per interval by the caller's
// limiter.
func (s *Sender) Run(ctx context.Context, wake <-chan struct{}, poll time.Duration, limiter *logging.Limiter) {
	if poll <= 0 {
		poll = DefaultSendPoll
	}
	run := func() {
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			l := s.logger()
			if limiter != nil {
				l = limiter.Limited("cisp-sender")
			}
			logging.Error(ctx, l, "publication outbox not processed", err)
		}
	}
	run()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			run()
		case <-t.C:
			run()
		}
	}
}

// PendingAges are the "not yet published" ages per dataset at now, from
// the sender's last run.
func (s *Sender) PendingAges(now time.Time) map[Dataset]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[Dataset]float64, len(s.oldest))
	for d, t := range s.oldest {
		out[d] = now.Sub(t).Seconds()
	}
	return out
}

// LastError is the sender's last own failure ("" after a clean run).
func (s *Sender) LastError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastError
}
