package regimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

// KindPlaceholder is replaced in REGISTRY_IMPORT_URL by the kind of the
// export fetched (operators, then uas).
const KindPlaceholder = "{kind}"

// JobActor is the actor of a fetched import.
const JobActor = "registry_import_job"

// LockFetchJob keeps two api replicas from fetching at once.
const LockFetchJob = "registry_import_fetch_job"

// CheckURL refuses a REGISTRY_IMPORT_URL that is not https (http only
// to a loopback address, for a test double) or lacks the {kind}
// placeholder. G-11: the URL is the access method agreed with GCAA;
// nothing is scraped and no redirect is followed.
func CheckURL(raw string) error {
	if !strings.Contains(raw, KindPlaceholder) {
		return core.Fieldf("REGISTRY_IMPORT_URL", "must contain %s, replaced by operators and uas", KindPlaceholder)
	}
	u, err := url.Parse(strings.ReplaceAll(raw, KindPlaceholder, "operators"))
	if err != nil || u.Host == "" {
		return core.Fieldf("REGISTRY_IMPORT_URL", "not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() || u.Hostname() == "localhost" {
			return nil
		}
	}
	return core.Fieldf("REGISTRY_IMPORT_URL", "must be https (http only to a loopback address)")
}

// Fetcher reads an export from the agreed URL, bounded in time and
// size.
type Fetcher struct {
	URL      string
	Token    string
	Client   *http.Client
	MaxBytes int
}

// LoadToken reads a bearer token file (one line); "" when path is "".
func LoadToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return "", core.Fieldf("REGISTRY_IMPORT_TOKEN_FILE", "%q cannot be read: %v", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil {
		return "", core.Fieldf("REGISTRY_IMPORT_TOKEN_FILE", "%q cannot be read", path)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.ContainsAny(tok, "\r\n") {
		return "", core.Fieldf("REGISTRY_IMPORT_TOKEN_FILE", "%q must hold one line", path)
	}
	return tok, nil
}

// NewClient is the fetch's HTTP client: the timeout bounds the whole
// request, and no redirect is followed (the agreed URL or nothing).
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused: only the agreed REGISTRY_IMPORT_URL is read")
		},
	}
}

// Fetch reads the export of kind.
func (f Fetcher) Fetch(ctx context.Context, kind string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.ReplaceAll(f.URL, KindPlaceholder, kind), nil)
	if err != nil {
		return nil, err
	}
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("the export answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(f.MaxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > f.MaxBytes {
		return nil, fmt.Errorf("the export is larger than %d bytes (REGISTRY_IMPORT_MAX_BYTES)", f.MaxBytes)
	}
	return b, nil
}

// Locker takes a job lock without waiting; ok is false when another
// replica holds it.
type Locker interface {
	TryLock(ctx context.Context, name string) (release func(), ok bool, err error)
}

// PGLocker is Locker on the relational database's session advisory
// locks.
type PGLocker struct{ DB *pg.DB }

// TryLock implements Locker.
func (l PGLocker) TryLock(ctx context.Context, name string) (func(), bool, error) {
	lock, ok, err := l.DB.AdvisoryLock(ctx, pg.LockKey(name))
	if err != nil || !ok {
		return nil, ok, err
	}
	return func() { _ = lock.Release(context.WithoutCancel(ctx)) }, true, nil
}

// Job is the periodic re-import from REGISTRY_IMPORT_URL (agreed access
// only, G-11).
type Job struct {
	Service *Service
	Fetcher Fetcher
	Locker  Locker
	Limiter *logging.Limiter
}

// FetchOutcome is what one run did with one kind.
type FetchOutcome struct {
	Kind      string
	Fetched   bool
	Unchanged bool
	Applied   bool
	Problems  int
	Err       error
}

// RunOnce fetches and imports both kinds, operators first. Content the
// ledger shows was run to an outcome before under the same rules (the
// newest fetched row of the kind) is not run again: an applied export
// would change nothing and a refused one is refused until the source
// changes it (a refusal is permanent, never retried in a loop). Each
// failure is counted and logged and leaves the registry as it was; the
// next period is the only retry.
func (j *Job) RunOnce(ctx context.Context) ([]FetchOutcome, error) {
	release, ok, err := j.Locker.TryLock(ctx, LockFetchJob)
	if err != nil {
		return nil, err
	}
	if !ok {
		j.Service.count(CounterFetchSkipped)
		return nil, nil
	}
	defer release()
	actor := audit.SystemActor(JobActor)
	var out []FetchOutcome
	for _, kind := range []string{registry.ImportKindOperators, registry.ImportKindUAS} {
		o := FetchOutcome{Kind: kind}
		o.Err = j.one(ctx, kind, actor, &o)
		if o.Err != nil {
			j.Service.count(CounterFetchFailed)
			j.warn(kind).Error("registry re-import of the fetched export failed; the registry is as it was",
				slog.String("kind", kind), slog.String("error", o.Err.Error()))
		}
		out = append(out, o)
	}
	return out, nil
}

func (j *Job) warn(kind string) *slog.Logger {
	if j.Limiter != nil {
		return j.Limiter.Limited("registry_import_fetch:" + kind)
	}
	return j.Service.logger()
}

func (j *Job) one(ctx context.Context, kind string, actor audit.Actor, o *FetchOutcome) error {
	body, err := j.Fetcher.Fetch(ctx, kind)
	if err != nil {
		return err
	}
	o.Fetched = true
	j.Service.count(CounterFetched)
	sum := sha256.Sum256(body)
	last, found, err := j.Service.Ledger.Last(ctx, kind, OriginFetch)
	if err != nil {
		return err
	}
	if found && last.SHA256 == hex.EncodeToString(sum[:]) && last.RulesVersion == j.Service.Rules.RulesVersion {
		o.Unchanged = true
		j.Service.count(CounterFetchUnchanged)
		return nil
	}
	rep, err := j.Service.Run(ctx, Request{Kind: kind, Format: j.Service.Rules.Format, Body: body, Origin: OriginFetch}, actor)
	if err != nil {
		return err
	}
	o.Applied, o.Problems = rep.Applied(), len(rep.Problems)
	if !o.Applied {
		j.warn(kind).Error("the fetched registry export was refused whole; it is not run again until it changes",
			slog.String("kind", kind), slog.Int("problems", len(rep.Problems)), slog.String("content_sha256", rep.SHA256))
	}
	return nil
}

// Run runs RunOnce at once and then every period until ctx ends.
func (j *Job) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
			j.Service.count(CounterFetchFailed)
			logging.Error(ctx, j.Service.logger(), "registry re-import job failed", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
