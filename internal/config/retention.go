package config

import (
	"strings"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/archive"
)

// Retention is api's retention and archive (WP-27; spec 05 §4, 06 §5,
// 08 Q8; plan Q-A15, Q-A18). Every period is the spec's default and is
// pending GCAA and the DPO (spec Q8): the regulatory floor is 30 days for
// operational records (2021/664 Art. 15(1)(g)), and the database refuses
// a deletion inside it whatever these say (relational 00024, timeseries
// 00013). The status line and GET /v1/retention/status carry them with
// pending_gcaa: true.
type Retention struct {
	RetentionOnlineDays      int    `env:"RETENTION_ONLINE_DAYS" default:"90" min:"30" max:"3650" help:"days the telemetry hypertables (rid_observations, tracks, manned_tracks) stay online; older chunks are archived to ARCHIVE_URL, verified, then dropped (spec 05 §4, Q8: 90 days, pending GCAA)"`
	RetentionArchiveYears    int    `env:"RETENTION_ARCHIVE_YEARS" default:"2" min:"1" max:"30" help:"years an archived chunk and a USSP daily records bundle are kept, counted from the end of the data's day; then deleted unless held (Q8: 2 years, pending GCAA)"`
	RetentionViolationsYears int    `env:"RETENTION_VIOLATIONS_YEARS" default:"5" min:"1" max:"50" help:"years a closed violation (the authority's alerts) is kept after it closed; then deleted in batches unless held or an incident names it (Q8: 5 years for alerts and intents, pending GCAA; this system stores no intents)"`
	RetentionIncidents       string `env:"RETENTION_INCIDENTS" default:"indefinite" enum:"indefinite" help:"incidents and evidence packs are kept indefinitely (Q8, pending GCAA); no other value is implemented"`
	RetentionAuditYears      int    `env:"RETENTION_AUDIT_YEARS" default:"10" min:"1" max:"100" help:"years a month of the audit log is kept after it ended; the oldest month is then dropped whole, its last hash kept as the chain's anchor, unless held (Q8: 10 years, pending GCAA)"`

	ArchiveURL string `env:"ARCHIVE_URL" help:"the archive store: file:///<absolute directory> (an S3-compatible store is not implemented); unset: nothing is archived and so no telemetry chunk is dropped (said at error level every run)"`

	RetentionTickS          int `env:"RETENTION_TICK_S" default:"60" min:"1" max:"3600" help:"how often api checks whether a retention, archive or verification job is due (each job's own period is on the database clock in job_runs, so a restart neither skips nor repeats a run)"`
	RetentionEveryS         int `env:"RETENTION_EVERY_S" default:"86400" min:"60" max:"604800" help:"period of the retention job (archive, drops, deletions; daily) and of the USSP daily records pull"`
	RetentionRetryS         int `env:"RETENTION_RETRY_S" default:"3600" min:"60" max:"86400" help:"wait after a failed or interrupted run of a job before it is tried again"`
	RetentionBatchRows      int `env:"RETENTION_BATCH_ROWS" default:"1000" min:"1" max:"10000" help:"rows one deletion transaction removes at most (each batch commits with its events row)"`
	RetentionMaxBatches     int `env:"RETENTION_MAX_BATCHES" default:"100" min:"1" max:"100000" help:"deletion batches one run makes at most per table; the rest waits for the next run (counted)"`
	RetentionChunksPerRun   int `env:"RETENTION_CHUNKS_PER_RUN" default:"60" min:"1" max:"10000" help:"telemetry chunks one run archives and drops at most; the rest waits for the next run"`
	RetentionExportTimeoutS int `env:"RETENTION_EXPORT_TIMEOUT_S" default:"3600" min:"10" max:"86400" help:"bound on the export of one chunk (one COPY statement on its own connection)"`
	RetentionMarginS        int `env:"RETENTION_INCIDENT_MARGIN_S" default:"86400" min:"0" max:"2592000" help:"an incident references an archived chunk when it occurred within this margin of the chunk's range: the remote pilot positions of its aircraft are then kept in the archive (06 §5), and an open incident keeps the object past its archive period"`
	RetentionMaxHolds       int `env:"RETENTION_MAX_HOLDS" default:"1000" min:"1" max:"100000" help:"active legal holds a retention check reads at most; past it every chunk and object is treated as held (fail closed, counted)"`
	ArchiveMaxObjectBytes   int `env:"ARCHIVE_MAX_OBJECT_BYTES" default:"67108864" min:"1024" max:"1073741824" help:"largest USSP daily records bundle read and stored; a larger one is a missing day with that reason"`

	TSArchiverRole string `env:"TS_ARCHIVER_ROLE" default:"authority_ts_archiver" help:"role SET on api's telemetry connections of the archive job (timeseries 00013_archive)"`

	USSPRecordsGraceDays int `env:"USSP_RECORDS_GRACE_DAYS" default:"2" min:"1" max:"30" help:"days after a day ended before a USSP's daily records bundle still not fetched is an alarm (02 F7)"`
	USSPRecordsBackfill  int `env:"USSP_RECORDS_BACKFILL_DAYS" default:"7" min:"1" max:"90" help:"days back the daily records pull tries each run (a missing day is retried until it leaves this window, then stays an alarm)"`
	USSPRecordsTimeoutS  int `env:"USSP_RECORDS_TIMEOUT_S" default:"60" min:"1" max:"600" help:"bound on one daily records fetch"`
	USSPRecordsMaxUSSPs  int `env:"USSP_RECORDS_MAX_USSPS" default:"100" min:"1" max:"1000" help:"operating USSPs the pull reads at most per run"`

	EvidenceVerifyMax int `env:"EVIDENCE_REVERIFY_MAX" default:"100000" min:"1" max:"10000000" help:"evidence packs the monthly re-verification checks at most; past it the run is failed and says so"`
}

// validateRetention checks what the tags cannot.
func (r *Retention) validateRetention() []error {
	var errs []error
	if r.ArchiveURL != "" {
		if _, err := archive.DirOf(r.ArchiveURL); err != nil {
			errs = append(errs, &core.FieldError{Field: "ARCHIVE_URL", Reason: strings.TrimPrefix(err.Error(), "ARCHIVE_URL: ")})
		}
	}
	if r.RetentionArchiveYears*365 <= r.RetentionOnlineDays {
		errs = append(errs, core.Fieldf("RETENTION_ARCHIVE_YEARS", "must reach beyond RETENTION_ONLINE_DAYS"))
	}
	return errs
}
