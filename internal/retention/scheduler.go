package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Job names in job_runs.
const (
	JobRetention      = "retention"
	JobAuditVerify    = "audit_verify"
	JobEvidenceVerify = "evidence_verify"
	JobUSSPRecords    = "ussp_records"
)

// Counters of the scheduler.
const (
	CounterJobRuns    = "retention_job_runs"
	CounterJobFailed  = "retention_job_failed"
	CounterJobSkipped = "retention_job_skipped" // due, but another replica holds the job's lock
)

// Job is one periodic job.
type Job struct {
	Name string
	// Every is the period; Monthly instead makes the job due once per
	// UTC calendar month.
	Every   time.Duration
	Monthly bool
	// Run does the work and returns its summary (numbers, never only
	// "done", LESSONS E-02).
	Run func(ctx context.Context) (map[string]any, error)
}

// Scheduler runs the jobs when they are due on the database clock
// (job_runs), each under its own session advisory lock so several api
// replicas never run one job twice, and records every run's start, end,
// outcome and summary. A restart neither skips a due run nor repeats a
// finished one; a run interrupted by a restart stays unfinished in the
// ledger and the job is due again after Retry.
type Scheduler struct {
	DB    *pg.DB
	Jobs  []Job
	Tick  time.Duration
	Retry time.Duration
	// Locker takes a job's lock without waiting; nil is the relational
	// database's session advisory lock.
	Locker   func(ctx context.Context, name string) (release func(), ok bool, err error)
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter

	mu   sync.Mutex
	last map[string]RunResult
}

// RunResult is a finished run as the status line shows it.
type RunResult struct {
	RunID    int64
	Started  time.Time
	Outcome  string
	Summary  map[string]any
	Err      string
	Duration time.Duration
}

func (s *Scheduler) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Scheduler) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Scheduler) lock(ctx context.Context, name string) (func(), bool, error) {
	if s.Locker != nil {
		return s.Locker(ctx, name)
	}
	l, ok, err := s.DB.AdvisoryLock(ctx, pg.LockKey("job:"+name))
	if err != nil || !ok {
		return func() {}, ok, err
	}
	return func() { _ = l.Release(context.WithoutCancel(ctx)) }, true, nil
}

// due asks the ledger whether job is due now.
func (s *Scheduler) due(ctx context.Context, j *Job) (bool, error) {
	retry := s.Retry
	if retry <= 0 {
		retry = time.Hour
	}
	if !j.Monthly && j.Every < retry {
		retry = j.Every
	}
	return s.DB.Queries().JobDue(ctx, gen.JobDueParams{Job: j.Name, Monthly: j.Monthly, EveryS: j.Every.Seconds(), RetryS: retry.Seconds()})
}

// ErrNotDue is RunJob's answer for a job that is not due.
var ErrNotDue = errors.New("retention: the job is not due")

// ErrLocked is RunJob's answer when another replica holds the job.
var ErrLocked = errors.New("retention: another replica runs the job")

// RunJob runs the job named name now if it is due (or always when
// force), under its lock, and records the run.
func (s *Scheduler) RunJob(ctx context.Context, name string, force bool) (RunResult, error) {
	var j *Job
	for i := range s.Jobs {
		if s.Jobs[i].Name == name {
			j = &s.Jobs[i]
		}
	}
	if j == nil {
		return RunResult{}, fmt.Errorf("retention: no job %q", name)
	}
	release, ok, err := s.lock(ctx, j.Name)
	if err != nil {
		return RunResult{}, err
	}
	if !ok {
		s.inc(CounterJobSkipped)
		return RunResult{}, ErrLocked
	}
	defer release()
	if !force {
		// Asked again under the lock: another replica may have just
		// finished it.
		due, err := s.due(ctx, j)
		if err != nil {
			return RunResult{}, err
		}
		if !due {
			return RunResult{}, ErrNotDue
		}
	}
	start, err := s.DB.Queries().StartJobRun(ctx, j.Name)
	if err != nil {
		return RunResult{}, fmt.Errorf("retention: start %s: %w", j.Name, err)
	}
	t0 := time.Now()
	sum, runErr := j.Run(ctx)
	if sum == nil {
		sum = map[string]any{}
	}
	res := RunResult{RunID: start.RunID, Started: start.StartedAt, Outcome: "ok", Summary: sum, Duration: time.Since(t0)}
	if runErr != nil {
		res.Outcome, res.Err = "failed", runErr.Error()
		sum["error"] = runErr.Error()
	}
	b, err := json.Marshal(sum)
	if err != nil {
		b = []byte(`{"error":"the summary could not be encoded"}`)
	}
	if err := s.DB.Queries().FinishJobRun(context.WithoutCancel(ctx), gen.FinishJobRunParams{RunID: start.RunID, Outcome: &res.Outcome, Summary: b}); err != nil {
		return res, fmt.Errorf("retention: finish %s: %w", j.Name, err)
	}
	s.inc(CounterJobRuns)
	s.mu.Lock()
	if s.last == nil {
		s.last = map[string]RunResult{}
	}
	s.last[j.Name] = res
	s.mu.Unlock()
	if runErr != nil {
		s.inc(CounterJobFailed)
		s.logger().Error("job run failed; it is tried again after the retry wait", slog.String("job", j.Name),
			slog.Int64("run_id", res.RunID), slog.Duration("took", res.Duration), slog.String("error", runErr.Error()),
			slog.Any("summary", sum))
		return res, runErr
	}
	s.logger().Info("job run finished", slog.String("job", j.Name), slog.Int64("run_id", res.RunID),
		slog.Duration("took", res.Duration), slog.Any("summary", sum))
	return res, nil
}

// Run checks every Tick which jobs are due and runs them, one at a
// time, until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		for i := range s.Jobs {
			if ctx.Err() != nil {
				return
			}
			j := &s.Jobs[i]
			due, err := s.due(ctx, j)
			if err != nil {
				s.warn(j.Name).Error("could not tell whether the job is due", slog.String("job", j.Name), slog.String("error", err.Error()))
				continue
			}
			if !due {
				continue
			}
			if _, err := s.RunJob(ctx, j.Name, false); err != nil && !errors.Is(err, ErrNotDue) && !errors.Is(err, ErrLocked) && ctx.Err() == nil {
				s.warn(j.Name).Warn("job run did not succeed", slog.String("job", j.Name), slog.String("error", err.Error()))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scheduler) warn(job string) *slog.Logger {
	if s.Limiter != nil {
		return s.Limiter.Limited("retention_job:" + job)
	}
	return s.logger()
}

// StatusAttrs name every job's last run in this process.
func (s *Scheduler) StatusAttrs() []slog.Attr {
	s.mu.Lock()
	defer s.mu.Unlock()
	attrs := make([]slog.Attr, 0, len(s.Jobs))
	for _, j := range s.Jobs {
		r, ok := s.last[j.Name]
		if !ok {
			attrs = append(attrs, slog.String("job_"+j.Name, "no run in this process (GET /v1/retention/status has the ledger)"))
			continue
		}
		attrs = append(attrs, slog.Group("job_"+j.Name, slog.String("outcome", r.Outcome),
			slog.String("started", r.Started.UTC().Format(time.RFC3339)), slog.Int64("run_id", r.RunID)))
	}
	return attrs
}
