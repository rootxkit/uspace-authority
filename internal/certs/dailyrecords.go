package certs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the USSP daily records pull (WP-27, spec 02 F7, plan
// Q-A18).
const (
	CounterRecordsDaysFetched = "ussp_records_days_fetched"
	CounterRecordsDaysFailed  = "ussp_records_fetch_failed"  // one attempt that did not get the day (retried next run)
	CounterRecordsDaysMissing = "ussp_records_days_missing"  // the alarm: a day still missing after the grace period
	CounterRecordsStoreFailed = "ussp_records_store_failed"  // fetched but not stored and verified (retried next run)
	CounterRecordsUSSPsBound  = "ussp_records_ussps_bounded" // operating USSPs past USSP_RECORDS_MAX_USSPS, not pulled (E-10)
)

// RecordsActor is the actor of the daily pull.
const RecordsActor = "ussp-records"

// EntityRecords is the entity type of the pull's events rows.
const EntityRecords = "ussp_daily_records"

// DailyFetcher reads one USSP's daily bundle (incidents.Records).
type DailyFetcher interface {
	FetchDaily(ctx context.Context, baseURL string, day time.Time, timeout time.Duration, maxBytes int64) ([]byte, error)
}

// DailyRecords pulls every operating USSP's daily records bundle
// (GET {base_url}/v1/records/daily/{date}, scope ussp.records) into the
// archive store: each fetched bundle is stored under a key holding its
// hash, read back and checked, and recorded (ussp_daily_records and an
// ussp_records_fetched events row). A day not fetched is retried every
// run while it is within BackfillDays; once GraceDays have passed since
// it ended it is an alarm, once per day: counted, logged at error
// level, an ussp_records_day_missing events row, and listed on the
// status line and GET /v1/retention/status until it is fetched.
type DailyRecords struct {
	DB           *pg.DB
	Audit        *audit.Writer
	Fetcher      DailyFetcher
	Store        archive.Store // nil: every day is missing with that reason
	GraceDays    int
	BackfillDays int
	Timeout      time.Duration
	MaxBytes     int64
	MaxUSSPs     int
	Counters     *core.Counters
	Logger       *slog.Logger

	mu      sync.Mutex
	missing []string
}

func (d *DailyRecords) logger() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Logger
}

func (d *DailyRecords) inc(name string) {
	if d.Counters != nil {
		d.Counters.Inc(name)
	}
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func pgDay(t time.Time) time.Time { return dayOf(t) }

// RecordsKey is the archive key of a bundle: by USSP and day, with the
// first bytes of its hash, so a USSP that serves a day again with other
// content gets a second object instead of an overwrite.
func RecordsKey(code string, day time.Time, sha string) string {
	h := strings.TrimPrefix(sha, "sha256:")
	if len(h) > 16 {
		h = h[:16]
	}
	return fmt.Sprintf("ussp-records/%s/%s/%s-%s.json", code, day.UTC().Format("2006/01"), day.UTC().Format(time.DateOnly), h)
}

// RunOnce pulls the days of the backfill window for every operating
// USSP and returns the run's summary for the job ledger.
func (d *DailyRecords) RunOnce(ctx context.Context) (map[string]any, error) {
	q := d.DB.Queries()
	now, err := q.DBClock(ctx)
	if err != nil {
		return nil, fmt.Errorf("ussp records: clock: %w", err)
	}
	maxUSSPs := max(d.MaxUSSPs, 1)
	ussps, err := q.OperatingUSSPs(ctx, int32(maxUSSPs+1))
	if err != nil {
		return nil, fmt.Errorf("ussp records: operating USSPs: %w", err)
	}
	if len(ussps) > maxUSSPs {
		d.inc(CounterRecordsUSSPsBound)
		d.logger().Error("more operating USSPs than USSP_RECORDS_MAX_USSPS: the rest are not pulled this run",
			slog.Int("max", maxUSSPs))
		ussps = ussps[:maxUSSPs]
	}
	today := dayOf(now)
	var fetched, failed, alarmed int
	for _, u := range ussps {
		start := today.AddDate(0, 0, -max(d.BackfillDays, 1))
		if u.OperationsStartedAt != nil && dayOf(*u.OperationsStartedAt).After(start) {
			start = dayOf(*u.OperationsStartedAt)
		}
		for day := start; day.Before(today); day = day.AddDate(0, 0, 1) {
			rec, err := q.USSPDay(ctx, gen.USSPDayParams{UsspCode: u.Code, Day: pgDay(day)})
			if err == nil && rec.State == "fetched" {
				continue
			}
			if err != nil && !store.IsNoRows(err) {
				return nil, fmt.Errorf("ussp records: %s %s: %w", u.Code, day.Format(time.DateOnly), err)
			}
			ok, alarm, err := d.one(ctx, u.Code, u.BaseUrl, day, today)
			if err != nil {
				return nil, err
			}
			if ok {
				fetched++
			} else {
				failed++
			}
			if alarm {
				alarmed++
			}
		}
	}
	missing, err := d.refreshMissing(ctx)
	if err != nil {
		return nil, err
	}
	sum := map[string]any{"ussps": len(ussps), "days_fetched": fetched, "days_failed": failed, "days_alarmed": alarmed,
		"missing_days": missing}
	d.logger().Info("USSP daily records pulled", slog.Int("ussps", len(ussps)), slog.Int("days_fetched", fetched),
		slog.Int("days_failed", failed), slog.Int("days_newly_missing", alarmed), slog.Int("days_missing", len(missing)))
	return sum, nil
}

// one tries one day; ok when it is fetched, stored and recorded (by
// this run, or by another one meanwhile); alarm
// when this attempt raised the day's missing alarm.
func (d *DailyRecords) one(ctx context.Context, code, baseURL string, day, today time.Time) (ok, alarm bool, err error) {
	why := ""
	var key, sha string
	var size int64
	switch {
	case d.Store == nil:
		why = archive.ErrNotConfigured.Error()
	case d.Fetcher == nil:
		why = "no records client (RECORDS_CLIENT_SECRET_FILE)"
	default:
		body, ferr := d.Fetcher.FetchDaily(ctx, baseURL, day, d.Timeout, d.MaxBytes)
		if ferr != nil {
			why = ferr.Error()
			d.inc(CounterRecordsDaysFailed)
			break
		}
		sha, size = archive.Hash(body), int64(len(body))
		key = RecordsKey(code, day, sha)
		if serr := d.store(key, body, sha); serr != nil {
			why = "fetched but not stored: " + serr.Error()
			d.inc(CounterRecordsStoreFailed)
		}
	}
	if why == "" {
		err := d.DB.WithTx(ctx, func(q *gen.Queries) error {
			if err := q.RecordUSSPDayFetched(ctx, gen.RecordUSSPDayFetchedParams{UsspCode: code, Day: pgDay(day),
				Sha256: &sha, SizeBytes: &size, ArchiveKey: &key}); err != nil {
				return err
			}
			_, err := d.Audit.Record(ctx, q, audit.Event{Actor: audit.SystemActor(RecordsActor), EntityType: EntityRecords,
				EntityID: code + "/" + day.Format(time.DateOnly), EventType: audit.EventUSSPRecordsFetched,
				Payload: map[string]any{"ussp_code": code, "day": day.Format(time.DateOnly), "sha256": sha, "bytes": size, "archive_key": key}})
			return err
		})
		if err != nil {
			return false, false, fmt.Errorf("ussp records: record %s %s: %w", code, day.Format(time.DateOnly), err)
		}
		d.inc(CounterRecordsDaysFetched)
		return true, false, nil
	}
	if len(why) > 2000 {
		why = why[:2000]
	}
	due := !today.Before(day.AddDate(0, 0, 1+d.GraceDays))
	raced := false
	err = d.DB.WithTx(ctx, func(q *gen.Queries) error {
		rec, err := q.RecordUSSPDayMissing(ctx, gen.RecordUSSPDayMissingParams{UsspCode: code, Day: pgDay(day), LastError: &why})
		if err != nil {
			return err
		}
		if rec.State == "fetched" {
			// Another run (a second api instance) fetched and recorded
			// the day while this one was failing to: the row is theirs.
			raced = true
			return nil
		}
		if !due || rec.Alarmed {
			return nil
		}
		if err := q.MarkUSSPDayAlarmed(ctx, gen.MarkUSSPDayAlarmedParams{UsspCode: code, Day: pgDay(day)}); err != nil {
			return err
		}
		alarm = true
		_, err = d.Audit.Record(ctx, q, audit.Event{Actor: audit.SystemActor(RecordsActor), EntityType: EntityRecords,
			EntityID: code + "/" + day.Format(time.DateOnly), EventType: audit.EventUSSPRecordsDayMissing,
			Payload: map[string]any{"ussp_code": code, "day": day.Format(time.DateOnly), "attempts": rec.Attempts, "reason": why}})
		return err
	})
	if err != nil {
		return false, false, fmt.Errorf("ussp records: record missing %s %s: %w", code, day.Format(time.DateOnly), err)
	}
	if raced {
		d.logger().Info("USSP daily records not fetched by this run; another run recorded the day meanwhile",
			slog.String("ussp_code", code), slog.String("day", day.Format(time.DateOnly)), slog.String("reason", why))
		return true, false, nil
	}
	if alarm {
		d.inc(CounterRecordsDaysMissing)
		d.logger().Error("USSP daily records missing after the grace period (spec 02 F7): an alarm on both sides",
			slog.String("ussp_code", code), slog.String("day", day.Format(time.DateOnly)), slog.String("reason", why))
	} else {
		d.logger().Warn("USSP daily records not fetched; retried next run", slog.String("ussp_code", code),
			slog.String("day", day.Format(time.DateOnly)), slog.String("reason", why))
	}
	return false, alarm, nil
}

// store writes the bundle and reads it back: the hash of what the store
// holds must be the hash of what was fetched. An object already at the
// key (an earlier attempt stored it and then failed to record it) is
// accepted when its hash is the same.
func (d *DailyRecords) store(key string, body []byte, sha string) error {
	err := archive.Put(d.Store, key, body)
	if err != nil && !errors.Is(err, archive.ErrExists) {
		return err
	}
	back, err := archive.Get(d.Store, key, d.MaxBytes)
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if got := archive.Hash(back); got != sha {
		return fmt.Errorf("the stored object's hash %s is not the fetched %s", got, sha)
	}
	return nil
}

// refreshMissing reads the alarmed days still missing.
func (d *DailyRecords) refreshMissing(ctx context.Context) ([]string, error) {
	rows, err := d.DB.Queries().MissingUSSPDays(ctx, 1000)
	if err != nil {
		return nil, fmt.Errorf("ussp records: missing days: %w", err)
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].UsspCode+"/"+rows[i].Day.UTC().Format(time.DateOnly))
	}
	d.mu.Lock()
	d.missing = out
	d.mu.Unlock()
	return out, nil
}

// Load reads the missing days at start, so the alarm survives a restart.
func (d *DailyRecords) Load(ctx context.Context) error {
	_, err := d.refreshMissing(ctx)
	return err
}

// StatusAttrs name the USSP days missing after the grace period.
func (d *DailyRecords) StatusAttrs() []slog.Attr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return []slog.Attr{slog.Int("ussp_records_missing_days", len(d.missing)), slog.Any("ussp_records_missing", d.missing)}
}
