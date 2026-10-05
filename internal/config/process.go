package config

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// Common is what every process reads.
type Common struct {
	LogLevel         string `env:"LOG_LEVEL" default:"info" enum:"debug|info|warn|error" help:"minimum level of the JSON log on stdout"`
	AdminAddr        string `env:"ADMIN_ADDR" default:":9090" help:"listen address of /healthz, /readyz and /metrics; private network only, never routed by Caddy"`
	StatusIntervalS  int    `env:"STATUS_INTERVAL_S" default:"60" min:"1" max:"3600" help:"seconds between status lines carrying every counter (E-09)"`
	ShutdownTimeoutS int    `env:"SHUTDOWN_TIMEOUT_S" default:"15" min:"1" max:"300" help:"bound on the drain after SIGTERM; the process exits non-zero when it is exceeded"`
	OTLPEndpoint     string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" kind:"url" help:"OTLP/HTTP trace endpoint; tracing is a no-op when unset"`
}

// CommonConfig is implemented by every process struct, so the shared
// process runtime can reach the common block.
type CommonConfig interface {
	CommonBlock() *Common
}

// CommonBlock returns c.
func (c *Common) CommonBlock() *Common { return c }

// HTTP is the public listener of a process that serves HTTP.
type HTTP struct {
	MaxBodyBytes        int      `env:"HTTP_MAX_BODY_BYTES" default:"1048576" min:"1024" max:"67108864" help:"default request body cap; routes may override it"`
	ReadHeaderTimeoutS  int      `env:"HTTP_READ_HEADER_TIMEOUT_S" default:"5" min:"1" max:"60" help:"time allowed to read request headers"`
	RateLimitRPS        float64  `env:"HTTP_RATE_LIMIT_RPS" default:"20" min:"0.1" help:"sustained requests per second per client"`
	RateLimitBurst      int      `env:"HTTP_RATE_LIMIT_BURST" default:"40" min:"1" help:"burst size per client"`
	RateLimitMaxClients int      `env:"HTTP_RATE_LIMIT_MAX_CLIENTS" default:"10000" min:"1" help:"clients tracked by the rate limiter; the least recently seen is evicted beyond it"`
	TrustedProxies      []string `env:"AUTHORITY_TRUSTED_PROXIES" help:"CIDRs or addresses of the reverse proxies (Caddy) whose X-Forwarded-For names the client; the rightmost hop that is not one of them is the client address of every limiter and audit row"`
}

// Bus is every process's NATS (internal/bus, WP-10): per-process
// credentials, the start retry of LESSONS B-08, the topology bounds api
// provisions and every process opens with, and the source-control
// bucket and push subject every follower reads.
type Bus struct {
	NATSCreds                  string `env:"NATS_CREDS" help:"this process's NATS credentials file (.creds); per-process credentials (plan §6); empty in the development stack"`
	NATSStartAttempts          int    `env:"NATS_START_ATTEMPTS" default:"3" min:"1" max:"20" help:"connection attempts at start before the process starts degraded and keeps connecting in the background (B-08)"`
	NATSStartBackoffMS         int    `env:"NATS_START_BACKOFF_MS" default:"500" min:"10" max:"60000" help:"wait after the first failed attempt at start; doubled after each"`
	NATSTimeoutMS              int    `env:"NATS_TIMEOUT_MS" default:"2000" min:"50" max:"60000" help:"bound on one connection attempt and on one KV read or write of the source-control state"`
	BusTRKStorage              string `env:"BUS_TRK_STORAGE" default:"file" enum:"file|memory" help:"storage of the TRK stream (the 1 h track mirror)"`
	BusIngestMaxMsgs           int    `env:"BUS_INGEST_MAX_MSGS" default:"120512" min:"2" max:"100000000" help:"hard bound of the INGEST work queue (discard new: a receiver is told 503); twice rid-ingest's shedding bound plus its batches in flight"`
	SourceControlBucket        string `env:"SOURCE_CONTROL_BUCKET" default:"source_control" help:"KV bucket of the source-control state (one key, the whole state)"`
	SourceControlSubject       string `env:"SOURCE_CONTROL_SUBJECT" default:"ctl.sources" help:"push subject of every source-control state"`
	SourceControlMaxValueBytes int    `env:"SOURCE_CONTROL_MAX_VALUE_BYTES" default:"262144" min:"1024" max:"1048576" help:"largest source-control state the bucket holds; a switch that would exceed it is refused naming the limit (E-10)"`
	SourceControlRereadS       int    `env:"SOURCE_CONTROL_REREAD_S" default:"5" min:"1" max:"3600" help:"seconds between re-reads of the source-control state by every follower, besides the watch and the push"`
}

// Geoid is the geoid grid of a process that converts heights above the
// ellipsoid to AMSL (internal/ground, WP-11). Unset, the process has no
// AMSL altitude from a geodetic one and says so (R-07); a grid that
// cannot be read is the same, said as unavailable.
type Geoid struct {
	GeoidFile string `env:"GEOID_FILE" help:"GeographicLib geoid grid (egm2008-2_5.pgm, fetched by deploy/fetch-ground.sh); unset: no AMSL altitude from HAE, said at start and on every status line (R-07)"`
}

// Ground is the terrain and the geoid of a process that judges heights
// over the ground (internal/ground, WP-11). Both are optional: without
// GROUND_DIR no AGL limit and no height limit is judged (D-04, Z-09).
type Ground struct {
	GroundDir         string `env:"GROUND_DIR" help:"directory of the terrain tiles (<cell>.pgm) and their index.json, fetched by deploy/fetch-ground.sh; unset: AGL limits are not judged (limit_not_judged) and the height limit is not evaluated"`
	GroundTileCache   int    `env:"GROUND_TILE_CACHE" default:"16" min:"1" max:"256" help:"terrain tiles held in memory (about 26 MB each for GLO-30), least recently used out first"`
	GroundRetryAfterS int    `env:"GROUND_RETRY_AFTER_S" default:"60" min:"1" max:"3600" help:"a tile that could not be read is answered as unknown ground this long before it is read again (D-04)"`
	Geoid
}

// API is the control plane.
type API struct {
	Common
	Bus
	HTTP
	Addr      string   `env:"API_ADDR" default:":8080" help:"public listen address (behind Caddy)"`
	PGURL     string   `env:"PG_URL" required:"true" secret:"true" kind:"url" help:"relational database (PostgreSQL + PostGIS); only api opens it"`
	TSURL     string   `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (TimescaleDB): api writes the registry projection there (WP-3)"`
	NATSURL   string   `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream; may carry credentials"`
	PublicURL string   `env:"AUTHORITY_PUBLIC_URL" required:"true" kind:"url" help:"this system's published base URL; its host is the token audience and the issuer"`
	Audiences []string `env:"AUTHORITY_AUDIENCES" help:"accepted JWT audiences (hosts), comma-separated: own host plus a lab alias"`
	MTLSMode  string   `env:"AUTHORITY_MTLS_MODE" default:"required" enum:"required|off" help:"mTLS on machine routes; off only in the lab and on staging"`
	PGPool
	PolicyRefreshS int `env:"POLICY_REFRESH_S" default:"60" min:"1" max:"3600" help:"seconds between re-reads of the active policy by its followers (the push is repaired by the re-read, G-08)"`
	Tokens
	Argon2
	Auth
	Peers
	Registry
	Receivers
	Sources
	Zones
	CISP
	Violations
	Incidents
	Occurrences
	DPAdmin
	Certificates
	Police
	RegistryPortal
	Retention
}

// RegistryPortal is api's uas.gov.ge import, public check and
// registration portal (WP-20, plan Q-A10, Q-A11, Q-A17). Every default
// that is a policy answer (retention, validity, budgets, the number's
// shape) is the spec's demo default, pending GCAA.
type RegistryPortal struct {
	RegistryImportRulesFile string `env:"REGISTRY_IMPORT_RULES_FILE" help:"the rules file mapping a uas.gov.ge export onto the registry (docs/runbooks/registry-import.md; agreed with GCAA, outside the repository); unset: POST /v1/registry/import is refused 503 import_not_configured; a file that does not check stops the start"`
	RegistryImportURL       string `env:"REGISTRY_IMPORT_URL" help:"the export URL agreed with GCAA (G-11: nothing is scraped), https, with {kind} replaced by operators and uas; unset: no periodic re-import"`
	RegistryImportTokenFile string `env:"REGISTRY_IMPORT_TOKEN_FILE" help:"file holding the bearer token of REGISTRY_IMPORT_URL, if the agreement names one"`
	RegistryImportEveryS    int    `env:"REGISTRY_IMPORT_EVERY_S" default:"86400" min:"300" max:"604800" help:"period of the re-import from REGISTRY_IMPORT_URL (pending GCAA: the agreed cadence); a failed fetch waits for the next period"`
	RegistryImportTimeoutS  int    `env:"REGISTRY_IMPORT_TIMEOUT_S" default:"60" min:"1" max:"600" help:"bound on one fetch of an export"`
	RegistryImportMaxBytes  int    `env:"REGISTRY_IMPORT_MAX_BYTES" default:"8388608" min:"1024" max:"67108864" help:"largest export read (upload or fetch); larger is refused 413 (E-10)"`
	RegistryImportMaxRows   int    `env:"REGISTRY_IMPORT_MAX_ROWS" default:"2000" min:"1" max:"50000" help:"records one export holds at most; more is refused 400, never cut (E-10); the default leaves room inside REGISTRY_IMPORT_WRITE_TIMEOUT_S (a first import of 5000 records took about 18 s), so split a larger export (pending GCAA: the export's size)"`
	RegistryImportWriteS    int    `env:"REGISTRY_IMPORT_WRITE_TIMEOUT_S" default:"25" min:"1" max:"25" help:"bound on one import's transaction, inside the listener's 30 s write timeout: past it the import is rolled back (503 import_timeout), never committed after its caller was cut off; split a larger export"`

	RegistryCheckPerMin int `env:"REGISTRY_CHECK_PER_MIN" default:"30" min:"1" max:"100000" help:"public GET /v1/registry/check requests per minute per client address (behind the trusted proxies); past it 429 with Retry-After"`
	RegistryCheckBurst  int `env:"REGISTRY_CHECK_BURST" default:"10" min:"1" max:"100000" help:"burst of the public check's per-address budget"`
	RegistryCheckMaxIPs int `env:"REGISTRY_CHECK_MAX_IPS" default:"10000" min:"1" max:"10000000" help:"client addresses the check's limiter remembers; past it the one seen longest ago is forgotten and counted (E-10)"`

	RegistryApplications    string `env:"REGISTRY_APPLICATIONS" default:"off" enum:"on|off" help:"the public portal's registration applications (Q-A11: only if the authority is the registry of record, spec Q4, pending GCAA); off: every application operation is 404"`
	RegistryOperatorReports string `env:"REGISTRY_OPERATOR_REPORTS" default:"off" enum:"on|off" help:"operators' occurrence reports through an e-mailed link (2019/947 Art. 19(2)); off: POST /v1/registry/operator-links and /v1/occurrences/operator are 404"`
	RegistryPortalKeyFile   string `env:"REGISTRY_PORTAL_KEY_FILE" help:"key (one line of base64, openssl rand -base64 32) signing the portal's links and keying the address hashes of its budgets; required when either portal flag is on, and different from PII_KEY_FILE and REGISTRY_HASH_KEY_FILE"`
	RegistryPortalURL       string `env:"REGISTRY_PORTAL_URL" kind:"url" help:"base URL of the public portal pages the e-mailed links open (the token travels in the fragment); required when either portal flag is on"`

	RegistryApplicationVerifyTTLS int    `env:"REGISTRY_APPLICATION_VERIFY_TTL_S" default:"86400" min:"600" max:"604800" help:"lifetime of an application's verification link (pending GCAA)"`
	RegistryApplicationsRetainS   int    `env:"REGISTRY_APPLICATIONS_RETAIN_S" default:"7776000" min:"86400" max:"315360000" help:"decided applications are deleted this long after the decision (90 days; pending GCAA and the DPO), unverified ones a link lifetime after their link expired; the operator a decision registered stays in the registry"`
	RegistryApplicationValidityS  int    `env:"REGISTRY_APPLICATION_VALIDITY_S" default:"157680000" min:"86400" max:"631152000" help:"validity of a registration approved without a valid_until (5 years; pending GCAA)"`
	RegistryApplicationsPerIP     int    `env:"REGISTRY_APPLICATIONS_PER_IP" default:"5" min:"1" max:"100000" help:"applications one client address may submit per REGISTRY_APPLICATIONS_WINDOW_S, counted in the database across replicas and restarts; past it 429 (pending GCAA)"`
	RegistryApplicationsWindowS   int    `env:"REGISTRY_APPLICATIONS_WINDOW_S" default:"3600" min:"60" max:"604800" help:"the window of the application and link budgets"`
	RegistryIssuePrefix           string `env:"REGISTRY_ISSUE_PREFIX" default:"GEO" help:"the leading letters of a number the portal issues (Q-A10, spec Q5: the EU country code by default, pending GCAA); the issued number must match the policy's registration_number_pattern"`
	RegistryIssueRandomLen        int    `env:"REGISTRY_ISSUE_RANDOM_LEN" default:"12" min:"6" max:"32" help:"random lower-case letters and digits after REGISTRY_ISSUE_PREFIX (the EU AMC form's 12, unverified; pending GCAA)"`

	RegistryOperatorLinkTTLS      int `env:"REGISTRY_OPERATOR_LINK_TTL_S" default:"86400" min:"600" max:"604800" help:"lifetime of an operator's occurrence-report link, spent by one report"`
	RegistryOperatorLinksPerIP    int `env:"REGISTRY_OPERATOR_LINKS_PER_IP" default:"10" min:"1" max:"100000" help:"link requests per client address per REGISTRY_APPLICATIONS_WINDOW_S; past it 429"`
	RegistryOperatorLinksPerOwner int `env:"REGISTRY_OPERATOR_LINKS_PER_OPERATOR" default:"5" min:"1" max:"1000" help:"links mailed to one operator per window; requests beyond it are answered 202 and mail nothing (counted)"`

	RegistryMailSMTPAddr      string `env:"REGISTRY_MAIL_SMTP_ADDR" help:"host:port of the SMTP relay the portal's e-mails leave by; required when either portal flag is on"`
	RegistryMailTLS           string `env:"REGISTRY_MAIL_TLS" default:"starttls" enum:"starttls|tls|none" help:"how the SMTP connection is protected; none only to a loopback relay"`
	RegistryMailFrom          string `env:"REGISTRY_MAIL_FROM" help:"the From address of the portal's e-mails"`
	RegistryMailUser          string `env:"REGISTRY_MAIL_USER" help:"SMTP user (PLAIN auth over TLS); unset: no auth"`
	RegistryMailPasswordFile  string `env:"REGISTRY_MAIL_PASSWORD_FILE" help:"file holding the SMTP password"`
	RegistryMailEveryS        int    `env:"REGISTRY_MAIL_EVERY_S" default:"10" min:"1" max:"3600" help:"period of the outbox sender"`
	RegistryMailBatch         int    `env:"REGISTRY_MAIL_BATCH" default:"20" min:"1" max:"1000" help:"messages one run of the sender takes at most"`
	RegistryMailMaxAttempts   int    `env:"REGISTRY_MAIL_MAX_ATTEMPTS" default:"8" min:"1" max:"100" help:"delivery attempts of one message; past them it is failed for good (counted, an events row) and its content cleared; a permanent SMTP refusal (5xx) fails at once"`
	RegistryMailRetryS        int    `env:"REGISTRY_MAIL_RETRY_S" default:"60" min:"1" max:"86400" help:"first retry of a failed delivery; each failure doubles it up to an hour"`
	RegistryMailTimeoutS      int    `env:"REGISTRY_MAIL_TIMEOUT_S" default:"30" min:"1" max:"600" help:"bound on one delivery"`
	RegistryPortalPurgeEveryS int    `env:"REGISTRY_PORTAL_PURGE_EVERY_S" default:"3600" min:"60" max:"86400" help:"period of the purge of applications past their retention, spent links and old budget rows"`
}

// PortalOn reports whether a portal flag is on.
func (r *RegistryPortal) PortalOn() bool {
	return r.RegistryApplications == "on" || r.RegistryOperatorReports == "on"
}

func (r *RegistryPortal) validatePortal() []error {
	var errs []error
	if r.RegistryImportURL != "" && r.RegistryImportRulesFile == "" {
		errs = append(errs, core.Fieldf("REGISTRY_IMPORT_URL", "needs REGISTRY_IMPORT_RULES_FILE: an export is read only under the agreed rules"))
	}
	if r.PortalOn() {
		for _, v := range [][2]string{
			{"REGISTRY_PORTAL_KEY_FILE", r.RegistryPortalKeyFile}, {"REGISTRY_PORTAL_URL", r.RegistryPortalURL},
			{"REGISTRY_MAIL_SMTP_ADDR", r.RegistryMailSMTPAddr}, {"REGISTRY_MAIL_FROM", r.RegistryMailFrom},
		} {
			if v[1] == "" {
				errs = append(errs, core.Fieldf(v[0], "required when REGISTRY_APPLICATIONS or REGISTRY_OPERATOR_REPORTS is on"))
			}
		}
	}
	if (r.RegistryMailUser == "") != (r.RegistryMailPasswordFile == "") {
		errs = append(errs, core.Fieldf("REGISTRY_MAIL_USER", "set it together with REGISTRY_MAIL_PASSWORD_FILE, or neither"))
	}
	if r.RegistryMailUser != "" && r.RegistryMailTLS == "none" {
		errs = append(errs, core.Fieldf("REGISTRY_MAIL_TLS", "none would send the SMTP password in clear"))
	}
	if !issuePrefix.MatchString(r.RegistryIssuePrefix) {
		errs = append(errs, core.Fieldf("REGISTRY_ISSUE_PREFIX", "1 to 8 upper-case ASCII letters"))
	}
	return errs
}

var issuePrefix = regexp.MustCompile(`^[A-Z]{1,8}$`)

// Police is api's police realm (WP-19, spec 02 F10, Q-A14): the purposes
// a police query may name and which of them release personal data (the
// owner's choice under national law, spec Q8: configuration, never
// code), the per-user and per-agency budgets, and the bounds of every
// answer (E-10).
type Police struct {
	PolicePurposes       []string `env:"POLICE_PURPOSES" default:"public_order,traffic_enforcement,criminal_investigation,security_threat" help:"the purposes a police query may name, comma-separated (1 to 64 of [a-z0-9_], starting with a letter); any other is refused 400 naming purpose (Q-A14, the spec default, pending GCAA; national law and the DPO decide)"`
	PolicePIIPurposes    []string `env:"POLICE_PII_PURPOSES" default:"criminal_investigation,security_threat" help:"the purposes of POLICE_PURPOSES that release the operator's identity and allow a legal export; every other purpose answers status only (Q-A14, the spec default, pending GCAA)"`
	PoliceUserQueries    int      `env:"POLICE_USER_QUERIES" default:"30" min:"1" max:"100000" help:"queries one police account may make per POLICE_RATE_WINDOW_S; past it 429 with Retry-After, counted on the database clock across replicas and restarts (E-10; the default is pending GCAA)"`
	PoliceAgencyQueries  int      `env:"POLICE_AGENCY_QUERIES" default:"300" min:"1" max:"1000000" help:"queries all accounts of one agency may make per POLICE_RATE_WINDOW_S; past it 429 with Retry-After (the default is pending GCAA)"`
	PoliceRateWindowS    int      `env:"POLICE_RATE_WINDOW_S" default:"60" min:"1" max:"86400" help:"the window of the police budgets (the default is pending GCAA)"`
	PoliceLiveWindowS    int      `env:"POLICE_LIVE_WINDOW_S" default:"30" min:"1" max:"3600" help:"a track last seen within this many seconds of now is flying now (GET /v1/police/aircraft without at); a picture older than this is said degraded"`
	PoliceAtWindowS      int      `env:"POLICE_AT_WINDOW_S" default:"60" min:"1" max:"3600" help:"GET /v1/police/aircraft?at= answers the tracks seen within this many seconds either side of at"`
	PoliceHistoryMaxAgeS int      `env:"POLICE_HISTORY_MAX_AGE_S" default:"7776000" min:"3600" max:"315360000" help:"the oldest at a police query may name (the online retention of tracks, 90 days, 05 §4); older is refused 400"`
	PoliceMaxBBoxDeg     float64  `env:"POLICE_MAX_BBOX_DEG" default:"1" min:"0.001" max:"10" help:"the longest side, in degrees of latitude or longitude, of a police query's box"`
	PoliceMaxAircraft    int      `env:"POLICE_MAX_AIRCRAFT" default:"200" min:"1" max:"10000" help:"aircraft one answer holds at most; beyond, truncated: true (narrow the box)"`
	PoliceMaxPositions   int      `env:"POLICE_MAX_POSITIONS" default:"60" min:"1" max:"10000" help:"positions per aircraft one answer holds at most (the newest); beyond, positions_truncated: true"`
	PoliceMaxFleet       int      `env:"POLICE_MAX_FLEET" default:"200" min:"1" max:"500" help:"aircraft of an operator's fleet one answer holds at most; beyond, fleet_truncated: true"`
	PoliceWriteTimeoutS  int      `env:"POLICE_WRITE_TIMEOUT_S" default:"10" min:"1" max:"600" help:"bound on one police query's reads and its record"`
	DPOReportMaxRows     int      `env:"DPO_REPORT_MAX_ROWS" default:"50000" min:"1" max:"1000000" help:"rows per list of GET /v1/audit/dpo-report; beyond, truncated: true"`
}

// Certificates are api's USSP and CISP certificates (WP-16): the lapse
// job, the repair of the USSP list and of the KV register dp-poller
// follows, and the public register's rate limit.
type Certificates struct {
	CertificatesLapseEveryS    int    `env:"CERTIFICATES_LAPSE_EVERY_S" default:"86400" min:"60" max:"604800" help:"period of the Art. 16(2) lapse job (daily; one replica at a time under an advisory lock, idempotent); the lapse periods themselves are authority_policy columns"`
	CertificatesRepairS        int    `env:"CERTIFICATES_REPAIR_S" default:"60" min:"1" max:"3600" help:"period of the repair of the USSP list (queued again when a change could not queue it or a certificate left it by expiry) and of the KV register dp-poller follows"`
	CertificatesBucket         string `env:"CERTIFICATES_BUCKET" default:"certificates" help:"KV bucket of the certified USSPs dp-poller follows (the same variable there)"`
	CertificatesRegisterPerMin int    `env:"CERTIFICATES_REGISTER_PER_MIN" default:"60" min:"1" max:"100000" help:"public register requests per minute per client address (behind the trusted proxies); past it 429 with Retry-After"`
	CertificatesRegisterBurst  int    `env:"CERTIFICATES_REGISTER_BURST" default:"20" min:"1" max:"100000" help:"burst of the public register's per-address budget"`
	CertificatesRegisterMaxIPs int    `env:"CERTIFICATES_REGISTER_MAX_IPS" default:"10000" min:"1" max:"10000000" help:"client addresses the register's limiter remembers; past it the one seen longest ago is forgotten and counted (E-10)"`
}

// Incidents are api's case files and evidence packs (WP-17).
type Incidents struct {
	EvidenceDir                  string `env:"EVIDENCE_DIR" help:"directory the sealed evidence packs are stored under (<incident>/<pack>.zip, never overwritten); unset: building, downloading and verifying a pack is refused with 503 evidence_storage_unavailable"`
	IncidentsPackMaxWindowS      int    `env:"INCIDENTS_PACK_MAX_WINDOW_S" default:"21600" min:"60" max:"604800" help:"longest window of one evidence pack; a longer one is refused (window_too_large), never thinned (B-13)"`
	IncidentsPackMaxRows         int    `env:"INCIDENTS_PACK_MAX_ROWS" default:"200000" min:"100" max:"10000000" help:"rows one section of a pack holds at most (tracks, frames, violations, events, ...); a section holding more refuses the pack (pack_too_large), never thinned"`
	IncidentsPackMaxBytes        int    `env:"INCIDENTS_PACK_MAX_BYTES" default:"268435456" min:"1048576" max:"4294967296" help:"largest archive of one pack; a larger one is refused (pack_too_large)"`
	IncidentsPackMaxZones        int    `env:"INCIDENTS_PACK_MAX_ZONES" default:"500" min:"1" max:"100000" help:"zone versions one pack names and finds in force at most; past it the pack is refused"`
	IncidentsMannedMarginM       int    `env:"INCIDENTS_MANNED_MARGIN_M" default:"10000" min:"100" max:"200000" help:"margin around the extent of the evidence's positions within which a pack includes the ANSP's manned traffic of the window (WP-15)"`
	IncidentsPackConcurrency     int    `env:"INCIDENTS_PACK_CONCURRENCY" default:"2" min:"1" max:"64" help:"packs built at once per replica; past it a build is refused with 503 pack_busy and counted (E-10)"`
	IncidentsPackReadConcurrency int    `env:"INCIDENTS_PACK_READ_CONCURRENCY" default:"4" min:"1" max:"64" help:"pack downloads and verifications at once per replica (each holds a whole archive in memory); past it 503 pack_busy, counted"`
	IncidentsBuildTimeoutS       int    `env:"INCIDENTS_BUILD_TIMEOUT_S" default:"120" min:"5" max:"3600" help:"bound on one pack build, its source reads and USSP record fetches included"`
	IncidentsWriteTimeoutS       int    `env:"INCIDENTS_WRITE_TIMEOUT_S" default:"10" min:"1" max:"600" help:"bound on one incident transaction"`
	IncidentsBackfillS           int    `env:"INCIDENTS_BACKFILL_S" default:"300" min:"10" max:"86400" help:"period of the job opening the incident of an escalation recorded without one (WP-12's incident_requested)"`
	IncidentsBackfillBatch       int    `env:"INCIDENTS_BACKFILL_BATCH" default:"100" min:"1" max:"10000" help:"incidents that job opens at most per run"`
	RecordsClientID              string `env:"RECORDS_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for the USSP service-record reads (scope ussp.records, 02 F7; M24)"`
	RecordsClientSecretFile      string `env:"RECORDS_CLIENT_SECRET_FILE" help:"file holding that client's secret; unset: every USSP record of a pack is unavailable with that reason"`
	RecordsTimeoutMS             int    `env:"RECORDS_TIMEOUT_MS" default:"5000" min:"100" max:"60000" help:"deadline of one USSP service-record fetch"`
	RecordsMaxBytes              int    `env:"RECORDS_MAX_BYTES" default:"1048576" min:"1024" max:"16777216" help:"largest USSP service record read; a larger one is unavailable with that reason"`
	RecordsMaxPerPack            int    `env:"RECORDS_MAX_PER_PACK" default:"16" min:"1" max:"1000" help:"USSP service records fetched per pack at most; the rest are unavailable with that reason"`
	RecordsConcurrency           int    `env:"RECORDS_CONCURRENCY" default:"4" min:"1" max:"64" help:"USSP service records of a legal pack read at once"`
	RecordsStepTimeoutS          int    `env:"RECORDS_STEP_TIMEOUT_S" default:"30" min:"1" max:"600" help:"deadline of a legal pack's whole records step; the records not read by then are unavailable with that reason (oversight packs read none)"`
}

// Occurrences are api's occurrence reports under Reg. (EU) 376/2014
// (WP-18): their own role and pool, their own key, the reporting
// deadline, the classification scheme and the export.
type Occurrences struct {
	OccurrenceKeyFile          string   `env:"OCCURRENCE_KEY_FILE" help:"AES-256 key (one line of base64, openssl rand -base64 32) sealing the occurrence reporter's person reference, separate from PII_KEY_FILE (a key equal to it stops the start); unset: a report carrying a person reference is refused 503 occurrence_key_unavailable and the reporter identity cannot be opened"`
	OccurrenceKeyID            string   `env:"OCCURRENCE_KEY_ID" default:"occ-1" help:"id stored beside every value sealed with OCCURRENCE_KEY_FILE"`
	OccurrencesPGRole          string   `env:"PG_OCCURRENCES_ROLE" default:"authority_occurrences" help:"role SET on every connection of the occurrences pool (migration 00020_occurrences creates it); the login user must be a member, and PG_ROLE has no grant on the occurrences schema"`
	OccurrencesPGMaxConns      int      `env:"PG_OCCURRENCES_MAX_CONNS" default:"4" min:"1" max:"50" help:"maximum connections of the occurrences pool"`
	OccurrencesDeadlineS       int      `env:"OCCURRENCES_REPORT_DEADLINE_S" default:"259200" min:"3600" max:"2592000" help:"reporting deadline after became_aware_at (376/2014 Art. 4(7)-(8): 72 h); a report received later is stored with within_72h false, never refused"`
	OccurrencesClockSkewS      int      `env:"OCCURRENCES_CLOCK_SKEW_S" default:"300" min:"0" max:"3600" help:"how far became_aware_at may be ahead of the database clock before a report is refused (400 naming became_aware_at)"`
	OccurrencesRiskClasses     []string `env:"OCCURRENCES_RISK_CLASSES" default:"accident,serious_incident,incident,occurrence_without_safety_effect,not_determined" help:"the safety risk classification scheme of POST /v1/occurrences/{id}/classify (376/2014 Art. 7(2)), comma-separated; the default is the ECCAIRS occurrence class list (unverified against the taxonomy, Q-A12)"`
	OccurrencesExportFormat    string   `env:"OCCURRENCES_EXPORT_FORMAT" default:"eccairs-compatible-draft" help:"the de-identified export's default format (Q-A12, owner-only: E5X is a later writer); the formats this build knows are listed at start"`
	OccurrencesExportMaxRecord int      `env:"OCCURRENCES_EXPORT_MAX_RECORDS" default:"5000" min:"1" max:"1000000" help:"reports one export holds at most; a window holding more is refused (export_too_large), never thinned"`
	OccurrencesExportMaxBytes  int      `env:"OCCURRENCES_EXPORT_MAX_BYTES" default:"33554432" min:"1024" max:"1073741824" help:"bytes one export document holds at most (32 MiB); a larger one is refused (export_too_large), never truncated"`
	OccurrencesWriteTimeoutS   int      `env:"OCCURRENCES_WRITE_TIMEOUT_S" default:"10" min:"1" max:"600" help:"bound on one occurrences transaction"`
}

// DPAdmin is api's administration of the F3411 Display Provider
// (WP-14): oversight areas, the Service Providers seen, USS availability
// arbitration at the DSS.
type DPAdmin struct {
	DSSBaseURL         string `env:"DSS_BASE_URL" kind:"url" help:"InterUSS DSS base URL (F3548 under /dss/v1); its host is the audience of the arbitration token (M18); unset: arbitration is refused with 503 dss_unconfigured"`
	DPClientID         string `env:"DP_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for the arbitration call to the DSS (M24)"`
	DPClientSecretFile string `env:"DP_CLIENT_SECRET_FILE" help:"file holding that client's secret; unset: arbitration is refused with 503"`
	DPOversightBucket  string `env:"DP_OVERSIGHT_BUCKET" default:"dp_oversight" help:"KV bucket of the oversight areas dp-poller reads (the same variable there)"`
	DPViewsRepublishS  int    `env:"DP_VIEWS_REPUBLISH_S" default:"60" min:"1" max:"3600" help:"seconds between republishes of the oversight areas from the database (repairs a lost bucket)"`
	DPProvidersMax     int    `env:"DP_PROVIDERS_MAX" default:"256" min:"1" max:"100000" help:"Service Providers whose last dp-poller status api keeps; past it the one heard longest ago is dropped and counted (E-10)"`
}

// Violations is api's consumer of alrt.v1 and its silent job (WP-12).
type Violations struct {
	ViolationsMaxAckPending     int `env:"VIOLATIONS_MAX_ACK_PENDING" default:"256" min:"1" max:"100000" help:"alrt.v1 messages delivered to api and not yet stored (max_ack_pending)"`
	ViolationsAckWaitS          int `env:"VIOLATIONS_ACK_WAIT_S" default:"30" min:"1" max:"3600" help:"ack wait of the alrt.v1 consumer"`
	ViolationsFetchMax          int `env:"VIOLATIONS_FETCH_MAX" default:"64" min:"1" max:"1000" help:"alrt.v1 messages one pull asks for"`
	ViolationsRetryMS           int `env:"VIOLATIONS_RETRY_MS" default:"1000" min:"10" max:"600000" help:"delay before a message whose write failed is delivered again"`
	ViolationsWriteTimeoutS     int `env:"VIOLATIONS_WRITE_TIMEOUT_S" default:"10" min:"1" max:"600" help:"bound on one violation transaction"`
	ViolationsExcerptMaxSamples int `env:"VIOLATIONS_EXCERPT_MAX_SAMPLES" default:"600" min:"1" max:"100000" help:"track samples stored per violation; past it later samples are left out, flagged excerpt_truncated and counted (E-10)"`
	ViolationsSilentAfterS      int `env:"VIOLATIONS_SILENT_AFTER_S" default:"30" min:"5" max:"86400" help:"an open violation detect has not republished for this long (database clock) is closed detector_silent; detect republishes every second"`
	ViolationsSilentCheckS      int `env:"VIOLATIONS_SILENT_CHECK_S" default:"10" min:"1" max:"3600" help:"period of the detector_silent check"`
	ViolationsSilentBatch       int `env:"VIOLATIONS_SILENT_BATCH" default:"500" min:"1" max:"100000" help:"violations one detector_silent check closes at most"`
}

// Sources is source control in api (WP-10, U-15).
type Sources struct {
	SourcesDefaultDeny      bool `env:"SOURCES_DEFAULT_DENY" default:"false" help:"an instance with no switch of its own is disabled (by default deny) unless its type is switched on; the flag travels in the published state"`
	SourceControlRepublishS int  `env:"SOURCE_CONTROL_REPUBLISH_S" default:"60" min:"1" max:"3600" help:"seconds between republishes of the source-control state from the database (repairs a lost bucket)"`
	SourceStatusStaleS      int  `env:"SOURCE_STATUS_STALE_S" default:"10" min:"1" max:"3600" help:"an adapter whose last src.v1 status is older is silent: its sources are shown stale"`
	SourceStatusMax         int  `env:"SOURCE_STATUS_MAX" default:"10000" min:"1" max:"1000000" help:"sources whose last status api keeps; past it the one heard longest ago is dropped and counted (E-10)"`
}

// Receivers is the Remote ID receiver registry of api (WP-7). The
// defaults are what a receiver is told when its own config leaves a
// member out (INV-03: no default is a literal in a row).
type Receivers struct {
	RIDDefaultBatchIntervalMS    int     `env:"RID_DEFAULT_BATCH_INTERVAL_MS" default:"1000" min:"100" max:"1000" help:"how often a receiver posts a batch unless its config says otherwise (F9: batches of at most 1 s)"`
	RIDDefaultBacklogCap         int     `env:"RID_DEFAULT_BACKLOG_CAP" default:"50000" min:"1" max:"10000000" help:"observations a receiver buffers while the ingest is unreachable unless its config says otherwise"`
	RIDDefaultHeartbeatIntervalS int     `env:"RID_DEFAULT_HEARTBEAT_INTERVAL_S" default:"10" min:"1" max:"300" help:"receiver heartbeat interval unless its config says otherwise (F9: 10 s)"`
	RIDDefaultPositionToleranceM float64 `env:"RID_DEFAULT_POSITION_TOLERANCE_M" default:"100" min:"1" max:"100000" help:"distance of a heartbeat's position from the pinned one beyond which it is counted as a deviation (T2) unless the receiver's config says otherwise"`
	RIDKeyRotationGraceS         int     `env:"RID_KEY_ROTATION_GRACE_S" default:"3600" min:"0" max:"604800" help:"how long a rotated receiver key keeps working unless the rotation says otherwise"`
	RIDKeysetReprojectS          int     `env:"RID_KEYSET_REPROJECT_S" default:"60" min:"5" max:"3600" help:"seconds between full re-projections of the receiver key set into KV rid_receiver_keys (repair of a lost bucket)"`
	RIDFramesMaxWindowS          int     `env:"RID_FRAMES_MAX_WINDOW_S" default:"86400" min:"60" max:"86400" help:"longest window of GET /v1/rid/frames; a longer one is refused, never thinned (B-13)"`
	RIDKVTimeoutMS               int     `env:"RID_KV_TIMEOUT_MS" default:"2000" min:"50" max:"60000" help:"bound on one write of the receiver key set; a change whose write fails is refused with 503"`
	RIDKeysetBucket              string  `env:"RID_KEYSET_BUCKET" default:"rid_receiver_keys" help:"KV bucket of the receiver key set that rid-ingest reads (the same variable there)"`
	TSReaderRole                 string  `env:"TS_READER_ROLE" default:"authority_ts_reader" help:"role SET on api's telemetry connections that read the raw Remote ID frames (SELECT only)"`
}

// Zones is the zone and U-space airspace service of api (WP-5).
type Zones struct {
	ZonesReprojectS   int    `env:"ZONES_REPROJECT_S" default:"300" min:"10" max:"3600" help:"seconds between full re-projections of the published zones into the telemetry database (G-08: 300)"`
	ZonesRepairRetryS int    `env:"ZONES_REPAIR_RETRY_S" default:"2" min:"1" max:"300" help:"first retry of a failed zones re-projection; each failure doubles it up to ZONES_REPROJECT_S"`
	ZonesProviderName string `env:"ZONES_PROVIDER_NAME" help:"the provider named in the metadata of every ED-318 export and publication (the authority's name, spec 06 §4); absent when empty"`
	ZonesProviderLang string `env:"ZONES_PROVIDER_LANG" default:"en-GB" help:"language tag of ZONES_PROVIDER_NAME (at most five characters)"`
}

// CISP is the CISP client of api (WP-6, spec 02 F1, F3). Without
// CISP_BASE_URL publications are still validated, signed and queued
// (their age grows on the console) and nothing is sent or pulled.
type CISP struct {
	CISPBaseURL            string   `env:"CISP_BASE_URL" kind:"url" help:"the CISP's published base URL (https; http only to a loopback host): F1 publications, the heartbeat and every F3 pull go there and nowhere else; its host is the audience of the authority's tokens for it (M18); unset: nothing is sent or pulled, said on the status line"`
	CISPClientID           string   `env:"CISP_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for calls to the CISP (M24)"`
	CISPClientSecretFile   string   `env:"CISP_CLIENT_SECRET_FILE" help:"file holding that client's secret (client_secret_post at CISP_TOKEN_URL); unset: every call to the CISP is refused locally and counted"`
	CISPTokenURL           string   `env:"CISP_TOKEN_URL" kind:"url" help:"the token endpoint the CISP client asks; default ISSUER_URL + /oauth/token"`
	CISCallbackURL         string   `env:"CIS_CALLBACK_URL" kind:"url" help:"the URL the CISP posts change notifications to (this system's POST /v1/cis/notifications, M1); unset: no subscription, the 60 s reconciliation alone"`
	CISNotifyIssuers       []string `env:"AUTHORITY_CIS_NOTIFY_ISSUERS" help:"allow-list of POST /v1/cis/notifications, at most two <iss>=<jwks_url> entries: the CISP's (iss = CISP_ISSUER_URL) and the ANSP's direct delivery (iss = ANSP_ISSUER_URL, M5); unset: the configured CISP and ANSP peers"`
	CISSubscriptionBBox    []string `env:"CIS_SUBSCRIPTION_BBOX" help:"the subscription's box: min lng, min lat, max lng, max lat (WGS84 degrees, comma-separated); unset: every change"`
	CISANSPJWKSURL         string   `env:"CIS_ANSP_PUBLISHER_JWKS_URL" kind:"url" help:"the ANSP's keys that verify the publisher signature of pulled restrictions versions; default ANSP_JWKS_URL"`
	CISReconcileS          int      `env:"CIS_RECONCILE_S" default:"60" min:"1" max:"60" help:"seconds between reconciliations of every CIS dataset (HEAD on the ETag, GET on a change); 02 F3 makes 60 s mandatory, whether or not notifications arrive"`
	CISHeartbeatS          int      `env:"CIS_HEARTBEAT_S" default:"15" min:"1" max:"15" help:"seconds between publisher heartbeats (M3: 15; the CISP marks a publisher stale after 60 s of silence)"`
	CISSendBackoffMinS     int      `env:"CIS_SEND_BACKOFF_MIN_S" default:"2" min:"1" max:"300" help:"first wait before a publication is sent again after a 5xx or no answer; each failure doubles it"`
	CISSendBackoffMaxS     int      `env:"CIS_SEND_BACKOFF_MAX_S" default:"300" min:"1" max:"300" help:"longest wait between two attempts of a publication (02 F1: capped at 5 min)"`
	CISSendGiveUpS         int      `env:"CIS_SEND_GIVE_UP_S" default:"86400" min:"60" max:"86400" help:"a publication not acknowledged this long after it was queued is failed with its last reason (02 F1: 24 h)"`
	CISPublisherSigMaxAgeS int      `env:"CIS_PUBLISHER_SIG_MAX_AGE_S" default:"31622400" min:"300" max:"315360000" help:"how old the publisher signature of a pulled version may be: the signature is as old as its version (366 days by default); an older one is held, visibly"`
	CISDirectMax           int      `env:"CIS_DIRECT_MAX" default:"500" min:"1" max:"100000" help:"restrictions held from the ANSP's degraded direct delivery (02 F2 failure rule, M5) and pulls waiting for it; past it a direct notification is answered 503 and the ANSP retries (E-10)"`
	CISDirectKeepS         int      `env:"CIS_DIRECT_KEEP_S" default:"86400" min:"60" max:"2592000" help:"seconds a direct restriction that is over (ended, cancelled, past ends_at) is kept, and a pull that fails is retried; pending GCAA: the spec names no figure, the default is spec 02 F3's 24 h notification retry window"`
	CISJTIMaxLive          int      `env:"CIS_JTI_MAX_LIVE" default:"100000" min:"1" max:"10000000" help:"delivery ids remembered by the notification receiver; beyond it a notification is answered 503 and counted (E-10)"`
}

// NotifyIssuer is one entry of AUTHORITY_CIS_NOTIFY_ISSUERS.
type NotifyIssuer struct {
	Issuer  string
	JWKSURL string
	ANSP    bool
}

// NotifyIssuerList parses AUTHORITY_CIS_NOTIFY_ISSUERS against the peers:
// each issuer must be the CISP's or the ANSP's, once; unset, the
// configured CISP and ANSP peers are the list.
func (c *API) NotifyIssuerList() ([]NotifyIssuer, error) {
	const name = "AUTHORITY_CIS_NOTIFY_ISSUERS"
	if len(c.CISNotifyIssuers) == 0 {
		var out []NotifyIssuer
		if c.CISPIssuerURL != "" {
			out = append(out, NotifyIssuer{Issuer: c.CISPIssuerURL, JWKSURL: c.CISPJWKSURL})
		}
		if c.ANSPIssuerURL != "" {
			out = append(out, NotifyIssuer{Issuer: c.ANSPIssuerURL, JWKSURL: c.ANSPJWKSURL, ANSP: true})
		}
		return out, nil
	}
	if len(c.CISNotifyIssuers) > 2 {
		return nil, core.Fieldf(name, "at most two issuers: the CISP and the ANSP")
	}
	var out []NotifyIssuer
	seen := map[string]bool{}
	for _, e := range c.CISNotifyIssuers {
		iss, jwks, ok := strings.Cut(e, "=")
		iss, jwks = strings.TrimSpace(iss), strings.TrimSpace(jwks)
		if !ok || iss == "" || jwks == "" {
			return nil, core.Fieldf(name, "%q is not <iss>=<jwks_url>", e)
		}
		if u, err := url.Parse(jwks); err != nil || !u.IsAbs() || u.Host == "" {
			return nil, core.Fieldf(name, "the JWKS URL of %q is not an absolute URL", iss)
		}
		var ansp bool
		switch iss {
		case c.CISPIssuerURL:
		case c.ANSPIssuerURL:
			ansp = true
		default:
			return nil, core.Fieldf(name, "%q is neither CISP_ISSUER_URL nor ANSP_ISSUER_URL", iss)
		}
		if seen[iss] {
			return nil, core.Fieldf(name, "%q is listed twice", iss)
		}
		seen[iss] = true
		out = append(out, NotifyIssuer{Issuer: iss, JWKSURL: jwks, ANSP: ansp})
	}
	return out, nil
}

// SubscriptionBBox parses CIS_SUBSCRIPTION_BBOX (nil when unset).
func (c *API) SubscriptionBBox() ([]float64, error) {
	const name = "CIS_SUBSCRIPTION_BBOX"
	if len(c.CISSubscriptionBBox) == 0 {
		return nil, nil
	}
	if len(c.CISSubscriptionBBox) != 4 {
		return nil, core.Fieldf(name, "must be four numbers: min lng, min lat, max lng, max lat")
	}
	out := make([]float64, 4)
	for i, s := range c.CISSubscriptionBBox {
		x, err := strconv.ParseFloat(s, 64)
		if err != nil || !core.IsFinite(x) {
			return nil, core.Fieldf(name, "%q is not a number", s)
		}
		out[i] = x
	}
	if out[0] < -180 || out[2] > 180 || out[1] < -90 || out[3] > 90 || out[0] > out[2] || out[1] > out[3] {
		return nil, core.Fieldf(name, "must be min lng, min lat, max lng, max lat within WGS84, not across the antimeridian")
	}
	return out, nil
}

// TokenURL is CISP_TOKEN_URL, or this issuer's /oauth/token.
func (c *API) TokenURL() string {
	if c.CISPTokenURL != "" {
		return c.CISPTokenURL
	}
	return c.Issuer() + "/oauth/token"
}

// Registry is the registry of api (WP-3).
type Registry struct {
	RegistryHashKeyFile string   `env:"REGISTRY_HASH_KEY_FILE" required:"true" help:"key (one line of base64, openssl rand -base64 32) of the keyed hashes of a registration number's secret part and a pilot's national id (spec 06 §5); outside the repository, never rotated without re-registering"`
	TSProjectorRole     string   `env:"TS_PROJECTOR_ROLE" default:"authority_ts_projector" help:"role SET on api's telemetry connections that write the registry projection (migration 00003_registry_projection)"`
	TSMaxConns          int      `env:"TS_MAX_CONNS" default:"4" min:"1" max:"100" help:"maximum connections of api's telemetry pool"`
	ReprojectS          int      `env:"REGISTRY_REPROJECT_S" default:"300" min:"10" max:"3600" help:"seconds between full re-projections of the registry into the telemetry database (G-08: 300)"`
	RepairRetryS        int      `env:"REGISTRY_REPAIR_RETRY_S" default:"2" min:"1" max:"300" help:"first retry of a failed re-projection; each failure doubles it up to REGISTRY_REPROJECT_S"`
	ExpiryS             int      `env:"REGISTRY_EXPIRY_S" default:"300" min:"10" max:"86400" help:"seconds between runs of the job that marks registrations past valid_until expired"`
	MTOMBandsG          []string `env:"REGISTRY_MTOM_BANDS_G" default:"250,900,4000,25000" help:"ascending upper bounds in grams of the MTOM bands F8 answers (under_<g>g, from_<last>g); the defaults are the 2019/945 class limits"`
}

// MTOMBounds parses REGISTRY_MTOM_BANDS_G.
func (r *Registry) MTOMBounds() ([]int, error) {
	out := make([]int, 0, len(r.MTOMBandsG))
	for _, v := range r.MTOMBandsG {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || (len(out) > 0 && n <= out[len(out)-1]) {
			return nil, core.Fieldf("REGISTRY_MTOM_BANDS_G", "must be ascending positive whole grams, comma-separated")
		}
		out = append(out, n)
	}
	return out, nil
}

// Auth is console sign-in and sessions of api (WP-2).
type Auth struct {
	PIIKeyFile        string  `env:"PII_KEY_FILE" required:"true" help:"AES-256 key (one line of base64, openssl rand -base64 32) sealing TOTP secrets and other PII columns; outside the repository"`
	PIIKeyID          string  `env:"PII_KEY_ID" default:"pii-1" help:"id stored beside every value sealed with PII_KEY_FILE"`
	SessionTTLS       int     `env:"SESSION_TTL_S" default:"43200" min:"300" max:"43200" help:"console session lifetime (table A: at most 12 h)"`
	SessionIdleS      int     `env:"SESSION_IDLE_S" default:"1800" min:"60" max:"1800" help:"a session unused this long ends (table A: idle 30 min)"`
	SessionMaxPerUser int     `env:"SESSION_MAX_PER_USER" default:"5" min:"1" max:"100" help:"live sessions per account; a new sign-in beyond it revokes the oldest"`
	SessionSweepS     int     `env:"SESSION_SWEEP_S" default:"300" min:"10" max:"86400" help:"seconds between deletions of sessions and challenges expired a day ago"`
	MFAChallengeTTLS  int     `env:"MFA_CHALLENGE_TTL_S" default:"300" min:"30" max:"600" help:"lifetime of the challenge between the password and the TOTP step"`
	MFAMaxAttempts    int     `env:"MFA_MAX_ATTEMPTS" default:"5" min:"1" max:"10" help:"wrong codes a challenge allows before it is spent"`
	MFALockoutAfter   int     `env:"MFA_LOCKOUT_AFTER" default:"5" min:"1" max:"100" help:"MFA failures of one account, across challenges and addresses, before it is locked for MFA_LOCKOUT_BASE_S"`
	MFALockoutBaseS   int     `env:"MFA_LOCKOUT_BASE_S" default:"60" min:"1" max:"86400" help:"first MFA lock; each further failure doubles it up to MFA_LOCKOUT_MAX_S"`
	MFALockoutMaxS    int     `env:"MFA_LOCKOUT_MAX_S" default:"3600" min:"1" max:"604800" help:"longest timed MFA lock"`
	MFAHardLockAfter  int     `env:"MFA_HARD_LOCK_AFTER" default:"100" min:"2" max:"100" help:"consecutive MFA failures after which only an admin unlocks the account (NIST SP 800-63B: at most 100)"`
	LoginIPPerMin     float64 `env:"LOGIN_RATE_IP_PER_MIN" default:"10" min:"1" help:"sign-in attempts per minute per client address (S-15)"`
	LoginIPBurst      int     `env:"LOGIN_RATE_IP_BURST" default:"10" min:"1" help:"sign-in burst per client address"`
	LoginUserPerMin   float64 `env:"LOGIN_RATE_USER_PER_MIN" default:"5" min:"1" help:"sign-in attempts per minute per username, known or not (S-15)"`
	LoginUserBurst    int     `env:"LOGIN_RATE_USER_BURST" default:"5" min:"1" help:"sign-in burst per username"`
	LoginRateMaxKeys  int     `env:"LOGIN_RATE_MAX_KEYS" default:"10000" min:"1" help:"addresses and usernames tracked by the sign-in limiters; the least recently seen is evicted beyond it"`
	PasswordMinLength int     `env:"PASSWORD_MIN_LENGTH" default:"12" min:"8" max:"128" help:"shortest password an admin may set"`
	TOTPIssuer        string  `env:"TOTP_ISSUER" default:"uspace-authority" help:"issuer label shown by authenticator apps (branding is configuration)"`
	BootstrapAdmin    string  `env:"BOOTSTRAP_ADMIN_USERNAME" help:"creates this first admin when the users table is empty (one-shot, logged, refused when users exist)"`
	BootstrapPassword string  `env:"BOOTSTRAP_ADMIN_PASSWORD_FILE" help:"file holding the first admin's password; required with BOOTSTRAP_ADMIN_USERNAME"`
}

// Peers are the other issuers this system accepts tokens from (WP-2
// verifier wiring): each is an iss and its JWKS URL, both or neither.
type Peers struct {
	CISPIssuerURL string `env:"CISP_ISSUER_URL" kind:"url" help:"the CISP's issuer (CIS notifications, WP-6)"`
	CISPJWKSURL   string `env:"CISP_JWKS_URL" kind:"url" help:"the CISP's JWKS URL (https)"`
	ANSPIssuerURL string `env:"ANSP_ISSUER_URL" kind:"url" help:"the ANSP's issuer (direct delivery, WP-6)"`
	ANSPJWKSURL   string `env:"ANSP_JWKS_URL" kind:"url" help:"the ANSP's JWKS URL (https)"`
	LabIssuerURL  string `env:"LAB_ISSUER_URL" kind:"url" help:"the lab issuer, in the lab only (lab-01 stands in until A-M4)"`
	LabJWKSURL    string `env:"LAB_JWKS_URL" kind:"url" help:"the lab issuer's JWKS URL"`
}

// List returns the configured peers as iss -> JWKS URL.
func (p Peers) List() map[string]string {
	out := map[string]string{}
	for _, pr := range [][2]string{{p.CISPIssuerURL, p.CISPJWKSURL}, {p.ANSPIssuerURL, p.ANSPJWKSURL}, {p.LabIssuerURL, p.LabJWKSURL}} {
		if pr[0] != "" && pr[1] != "" {
			out[pr[0]] = pr[1]
		}
	}
	return out
}

// Tokens is the ecosystem token service of api (WP-2, normative tables
// A and B of docs/WORKPACKAGES/WP-2.md).
type Tokens struct {
	IssuerURL            string   `env:"ISSUER_URL" kind:"url" help:"iss of every token this issuer signs and the base of its jwks_uri and token_endpoint; default AUTHORITY_PUBLIC_URL"`
	SigningKeyFiles      []string `env:"SIGNING_KEY_FILES" required:"true" help:"token-signing RSA keys (PEM, at least 2048 bits), comma-separated paths outside the repository; the first is activated on an empty key table, later ones are rotation candidates (kms: references are refused by this build)"`
	PublicationKeyFile   string   `env:"PUBLICATION_KEY_FILE" help:"RSA key (PEM) of the detached publication JWS (M26), listed in the JWKS under its own kid; optional until WP-6"`
	TokenTTLS            int      `env:"TOKEN_TTL_S" default:"3600" min:"60" max:"3600" help:"lifetime of an ecosystem machine token (table A: at most 1 h)"`
	TokenRatePerMin      float64  `env:"TOKEN_RATE_LIMIT_PER_MIN" default:"60" min:"1" help:"tokens per minute per authenticated client"`
	TokenRateBurst       int      `env:"TOKEN_RATE_LIMIT_BURST" default:"20" min:"1" help:"token burst per client"`
	TokenRateMaxClients  int      `env:"TOKEN_RATE_LIMIT_MAX_CLIENTS" default:"1000" min:"1" help:"clients tracked by the token rate limiter; the least recently seen is evicted beyond it"`
	KeyRetireGraceS      int      `env:"KEY_RETIRE_GRACE_S" default:"86400" min:"3600" max:"604800" help:"a retired signing key stays in the JWKS this long (the verifiers' JWKS cache TTL)"`
	KeyRotationTwoPerson bool     `env:"KEY_ROTATION_TWO_PERSON" default:"true" help:"a key rotation needs a second admin's confirmation (T4)"`
	KeyRotationConfirmS  int      `env:"KEY_ROTATION_CONFIRM_S" default:"600" min:"60" max:"3600" help:"window for the second admin's confirmation of a rotation"`
	KeyRefreshS          int      `env:"KEY_REFRESH_S" default:"60" min:"5" max:"3600" help:"seconds between re-reads of the signing-key table, so every api replica follows a rotation"`
}

// Argon2 holds the argon2id parameters of passwords and client secrets.
// The defaults and lower bounds are the OWASP Password Storage Cheat
// Sheet's argon2id minimum (19 MiB, 2 iterations, 1 lane).
type Argon2 struct {
	Argon2MemoryKiB int `env:"ARGON2_MEMORY_KIB" default:"19456" min:"19456" max:"4194304" help:"argon2id memory in KiB (OWASP minimum 19456)"`
	Argon2Time      int `env:"ARGON2_TIME" default:"2" min:"2" max:"100" help:"argon2id iterations (OWASP minimum 2)"`
	Argon2Threads   int `env:"ARGON2_THREADS" default:"1" min:"1" max:"64" help:"argon2id parallelism"`
}

// PGPool is the relational pool of api (internal/store/pg).
type PGPool struct {
	PGMaxConns          int    `env:"PG_MAX_CONNS" default:"10" min:"1" max:"200" help:"maximum connections of the relational pool"`
	PGStatementTimeoutS int    `env:"PG_STATEMENT_TIMEOUT_S" default:"15" min:"1" max:"600" help:"statement_timeout of every relational connection"`
	PGRole              string `env:"PG_ROLE" default:"authority_app" help:"role SET on every relational connection; the login user must be a member (migration 00002_events creates it)"`
}

// String redacts secrets.
func (c *API) String() string { return Describe(c) }

// RIDIngest is the F9 receiver ingest.
type RIDIngest struct {
	Common
	Bus
	HTTP
	Addr    string `env:"RID_INGEST_ADDR" default:":8081" help:"public listen address of /v1/rid/observations (behind Caddy); used with or without receiver keys: with none every batch is refused and /readyz says so"`
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	Geoid
	RIDIngestTuning
}

// RIDIngestTuning are rid-ingest's bounds (WP-7). The receiver protocol's
// own bounds (batch size, observations, sent_at_ms window) are the
// contract and live in internal/receivers.
type RIDIngestTuning struct {
	QueueMaxBatches     int    `env:"RID_INGEST_QUEUE_MAX_BATCHES" default:"60000" min:"1" max:"10000000" help:"work-queue depth beyond which the oldest undelivered batch is shed with a writer_gaps record (05 §5); about 10 min of 50 receivers posting every second, doubled"`
	QueueMaxAgeS        int    `env:"RID_INGEST_QUEUE_MAX_AGE_S" default:"600" min:"1" max:"86400" help:"a queued batch older than this is shed with a writer_gaps record (the 10-minute bound of ingest.v1)"`
	QueueMaxAckPending  int    `env:"RID_INGEST_QUEUE_MAX_ACK_PENDING" default:"256" min:"1" max:"100000" help:"batches delivered to this process and not yet settled"`
	StorageRetryMS      int    `env:"RID_INGEST_STORAGE_RETRY_MS" default:"1000" min:"10" max:"60000" help:"delay before a batch whose rows were not handed to tsdb-writer is delivered again"`
	NonceMemory         int    `env:"RID_INGEST_NONCE_MEMORY" default:"4096" min:"16" max:"1000000" help:"nonces remembered per receiver key generation (core auth.WithNonceMemory); beyond it the oldest is forgotten and counted (nonces_evicted)"`
	DedupeWindowS       int    `env:"RID_INGEST_DEDUPE_WINDOW_S" default:"60" min:"1" max:"3600" help:"window per receiver in which an observation (transmitter, rx_ts, payload hash) is queued once (B-05)"`
	DedupeMaxPerRx      int    `env:"RID_INGEST_DEDUPE_MAX_PER_RECEIVER" default:"20000" min:"1" max:"10000000" help:"observations remembered per receiver in the dedupe window; beyond it the oldest is forgotten and counted"`
	MaxReceivers        int    `env:"RID_INGEST_MAX_RECEIVERS" default:"10000" min:"1" max:"1000000" help:"receivers whose dedupe window and status counters are kept (E-10)"`
	KeysetRereadS       int    `env:"RID_INGEST_KEYSET_REREAD_S" default:"60" min:"1" max:"3600" help:"seconds between full re-reads of the key set besides the KV watch"`
	StatusIntervalMS    int    `env:"RID_INGEST_STATUS_INTERVAL_MS" default:"2000" min:"100" max:"60000" help:"interval of src.v1.direct_rid.<receiver> status messages (04 §3.6: every 2 s)"`
	StaleAfterS         int    `env:"RID_INGEST_STALE_AFTER_S" default:"15" min:"1" max:"3600" help:"a receiver silent for longer is stale (silent since T)"`
	LagAfterS           int    `env:"RID_INGEST_LAG_AFTER_S" default:"15" min:"1" max:"3600" help:"a receiver replaying backlog older than this is lagging with lag_s (B-03)"`
	DisabledRetryAfterS int    `env:"RID_INGEST_DISABLED_RETRY_AFTER_S" default:"30" min:"1" max:"3600" help:"Retry-After of a disabled receiver's refusal (B-10)"`
	QueueRetryAfterS    int    `env:"RID_INGEST_QUEUE_RETRY_AFTER_S" default:"2" min:"1" max:"3600" help:"Retry-After of a work-queue refusal"`
	NATSTimeoutMS       int    `env:"RID_INGEST_NATS_TIMEOUT_MS" default:"2000" min:"50" max:"60000" help:"bound on one queue write, row hand-over or key-set read"`
	KeysetBucket        string `env:"RID_KEYSET_BUCKET" default:"rid_receiver_keys" help:"KV bucket of the receiver key set, written by api (the same variable there)"`
	LabHeadersAllowed   bool   `env:"LAB_HEADERS_ALLOWED" default:"false" help:"admit batches carrying X-Lab-Scenario (the scenario harness's simulated receiver, WP-25); false refuses them with 400 lab_header (spec 06 T11); true only in the lab"`
	KeyCheckSlots       int    `env:"RID_INGEST_KEY_CHECK_SLOTS" default:"2" min:"1" max:"64" help:"concurrent argon2id checks of bearer keys not yet seen (T8); beyond it a request waits briefly and is refused with 503"`
	RIDPipelineTuning
}

// RIDPipelineTuning are the Remote ID pipeline's thresholds (WP-8). The
// identity and time values are authority_policy columns (INV-03); no
// policy is published to the hot path yet (KV policy, plan §6), so
// rid-ingest takes them from here, with the policy's version-1 defaults,
// and prints them at start.
type RIDPipelineTuning struct {
	IdentityTTLS        float64 `env:"RID_IDENTITY_TTL_S" default:"15" min:"0.1" max:"3600" help:"a Basic ID is usable this long after it was heard (I-01; policy identity_ttl_s)"`
	MaxGapS             float64 `env:"RID_MAX_GAP_S" default:"3" min:"0.1" max:"3600" help:"a transmitter silent longer is forgotten (I-01; policy max_gap_s)"`
	IdentifyWithinS     float64 `env:"RID_IDENTIFY_WITHIN_S" default:"4" min:"0.1" max:"3600" help:"a Location without a fresh identity waits this long before it is published unidentified (I-02; policy identify_within_s)"`
	BroadcastToleranceS float64 `env:"RID_BROADCAST_TOLERANCE_S" default:"1" min:"0.001" max:"600" help:"how far ahead of the receipt a broadcast time may be and be believed (T-07; policy broadcast_tolerance_s)"`
	MaxLatencyS         float64 `env:"RID_MAX_LATENCY_S" default:"5" min:"0.001" max:"3600" help:"how old a broadcast time may be at receipt and be believed (T-08; policy max_latency_s)"`
	MinVerticalAccuracy int     `env:"RID_MIN_VERTICAL_ACCURACY" default:"2" min:"1" max:"6" help:"lowest known ODID vertical accuracy code at which the geodetic altitude is used; below it the pressure altitude stands in (R-08)"`
	PressureHoldS       float64 `env:"RID_PRESSURE_HOLD_S" default:"10" min:"0.1" max:"3600" help:"a track stays on its pressure altitude this long after the last poor geodetic fix (R-08)"`
	MaxBatchSpacingS    float64 `env:"RID_MAX_BATCH_SPACING_S" default:"120" min:"1" max:"3600" help:"longest spacing a row keeps within its batch before it is clamped and counted (T-02)"`
	MaxTransmitters     int     `env:"RID_MAX_TRANSMITTERS" default:"50000" min:"1" max:"10000000" help:"transmitter addresses each identity tracker holds; beyond it the one heard longest ago is evicted and counted (E-10)"`
	MaxTracks           int     `env:"RID_MAX_TRACKS" default:"50000" min:"1" max:"10000000" help:"tracks whose altitude hold and last identification are remembered; beyond it the least recently seen is forgotten and counted (E-10)"`
	ProjectionRefreshS  int     `env:"RID_PROJECTION_REFRESH_S" default:"5" min:"1" max:"3600" help:"period of the registry projection re-read besides registry.v1.changed (G-08)"`
	TickMS              int     `env:"RID_TICK_MS" default:"1000" min:"10" max:"60000" help:"period of the identity trackers' forgetting of silent transmitters (I-01)"`
}

// String redacts secrets.
func (c *RIDIngest) String() string { return Describe(c) }

// Validate checks what the tags cannot.
func (c *RIDIngest) Validate() error {
	var errs []error
	if c.Addr == c.AdminAddr && !strings.HasSuffix(c.Addr, ":0") {
		errs = append(errs, &core.FieldError{Field: "ADMIN_ADDR", Reason: "must differ from RID_INGEST_ADDR"})
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				errs = append(errs, core.Fieldf("AUTHORITY_TRUSTED_PROXIES", "%q is neither a CIDR nor an address", p))
			}
		}
	}
	return errors.Join(errs...)
}

// DPPoller is the F3411 Display Provider (WP-14).
type DPPoller struct {
	Common
	Bus
	HTTP
	Addr       string   `env:"DP_ADDR" default:":8082" help:"public listen address of /uss/* and /v1/dp/observations/* (behind Caddy)"`
	TSURL      string   `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (registry projection, read only)"`
	NATSURL    string   `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	PublicURL  string   `env:"AUTHORITY_PUBLIC_URL" required:"true" kind:"url" help:"this system's published base URL; its host is the audience a Service Provider's notification and the conformance hook must carry (M18)"`
	Audiences  []string `env:"AUTHORITY_AUDIENCES" help:"accepted JWT audiences (hosts), comma-separated: own host plus a lab alias; default the host of AUTHORITY_PUBLIC_URL"`
	IssuerURL  string   `env:"ISSUER_URL" kind:"url" help:"this system's issuer (iss of the tokens it accepts and the base of its token endpoint); default AUTHORITY_PUBLIC_URL"`
	JWKSURL    string   `env:"DP_JWKS_URL" kind:"url" help:"this issuer's JWKS (https; http only to a loopback host); default ISSUER_URL + /.well-known/jwks.json"`
	DSSBaseURL string   `env:"DSS_BASE_URL" kind:"url" help:"InterUSS DSS base URL (F3411 under /rid/v2); its host is the audience of the tokens towards it (M18); unset: nothing is discovered and the status says dss_unconfigured"`
	USSBaseURL string   `env:"DP_USS_BASE_URL" kind:"url" help:"uss_base_url of this Display Provider's DSS subscriptions, where a Service Provider posts ISA changes (POST {uss_base_url}/uss/identification_service_areas/{id}); default AUTHORITY_PUBLIC_URL"`
	Peers
	DPClient
	Geoid
	DPPollerTuning
}

// DPClient is this system's client at its own token service for the
// Display Provider's outbound calls (M24).
type DPClient struct {
	DPClientID         string `env:"DP_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for calls to the DSS and to Service Providers (M24)"`
	DPClientSecretFile string `env:"DP_CLIENT_SECRET_FILE" help:"file holding that client's secret (client_secret_post at DP_TOKEN_URL); unset: every outbound call is refused locally and counted, and nothing is discovered or polled"`
	DPTokenURL         string `env:"DP_TOKEN_URL" kind:"url" help:"the token endpoint the Display Provider asks; default ISSUER_URL + /oauth/token"`
}

// DPPollerTuning are the Display Provider's limits (LESSONS R-14, spec
// 02 F7, 05 §5, 06 T9). The F3411 constants themselves (the 7 km and
// 2 km diagonals, 24 h subscriptions, p99 3 s) are uspace-core's f3411
// constants; dp_poll_hz and dp_view_diagonal_km are authority_policy
// columns followed from KV policy (INV-03).
type DPPollerTuning struct {
	RequestTimeoutMS     int     `env:"DP_REQUEST_TIMEOUT_MS" default:"5000" min:"100" max:"60000" help:"deadline of one poll of a Service Provider; a poll past it keeps the flights already shown, which age on the picture (R-14)"`
	MaxBodyBytes         int     `env:"DP_MAX_BODY_BYTES" default:"1048576" min:"1024" max:"4194304" help:"largest response read from a Service Provider or the DSS; a larger one is refused and counted (R-14: 1 MiB)"`
	MaxFlights           int     `env:"DP_MAX_FLIGHTS_PER_RESPONSE" default:"500" min:"1" max:"100000" help:"flights taken from one response; the rest are counted and logged (R-14: 500)"`
	MaxTilesPerSP        int     `env:"DP_MAX_TILES_PER_SP" default:"64" min:"1" max:"10000" help:"tiles one Service Provider is polled for; past it the tiles are counted and not polled (R-14: 64)"`
	MaxDetailsPerPoll    int     `env:"DP_MAX_DETAILS_PER_POLL" default:"20" min:"0" max:"1000" help:"details fetches after one poll at most (R-14: 20)"`
	DetailsConcurrency   int     `env:"DP_DETAILS_CONCURRENCY" default:"4" min:"1" max:"64" help:"details fetches in flight at once per poll (R-14: 4)"`
	UnavailableAfterS    int     `env:"DP_UNAVAILABLE_AFTER_S" default:"10" min:"1" max:"3600" help:"a Service Provider whose polls fail for this long is shown unavailable since T, never removed (R-14: 10 s)"`
	SlowPollHz           float64 `env:"DP_SLOW_POLL_HZ" default:"0.5" min:"0.01" max:"10" help:"poll rate of a Service Provider slower than the F3411 p99 of 3 s (05 §5: 0.5 Hz)"`
	MaxSplitDepth        int     `env:"DP_MAX_SPLIT_DEPTH" default:"3" min:"0" max:"8" help:"a 413 from a Service Provider splits the tile into four, at most this many times (R-14: 3)"`
	MaxViews             int     `env:"DP_MAX_VIEWS" default:"64" min:"1" max:"10000" help:"views (oversight areas and console viewports) followed; past it the rest are counted and logged"`
	MaxTiles             int     `env:"DP_MAX_TILES" default:"512" min:"1" max:"100000" help:"tiles discovered and subscribed in all; past it the rest are counted and logged"`
	MaxISAs              int     `env:"DP_MAX_ISAS" default:"10000" min:"1" max:"1000000" help:"identification service areas held; past it a new one is refused and counted"`
	MaxProviders         int     `env:"DP_MAX_PROVIDERS" default:"256" min:"1" max:"100000" help:"Service Providers held; past it a new one is counted and not polled, unless a DSS-listed ISA names it and a provider only notifications named can give way"`
	ProviderForgetAfterS int     `env:"DP_PROVIDER_FORGET_AFTER_S" default:"600" min:"10" max:"86400" help:"a Service Provider no held ISA names for this long is forgotten (its status goes)"`
	NotifiedISAMaxS      int     `env:"DP_NOTIFIED_ISA_MAX_LIFETIME_S" default:"86400" min:"60" max:"86400" help:"an ISA learned from a notification is trusted until its time_end, capped at now plus this (F3411: 24 h); a DSS search that does not list it drops it earlier"`
	MaxFlightsHeld       int     `env:"DP_MAX_FLIGHTS_HELD" default:"50000" min:"1" max:"10000000" help:"flights whose last published state, details and identification are remembered; past it the one seen longest ago is forgotten and counted (E-10)"`
	DiscoveryRereadS     int     `env:"DP_DISCOVERY_REREAD_S" default:"30" min:"1" max:"3600" help:"seconds between ISA searches per tile besides the notifications (repair, G-08)"`
	ViewsRereadS         int     `env:"DP_VIEWS_REREAD_S" default:"5" min:"1" max:"3600" help:"seconds between reads of the oversight areas and the console viewports"`
	StatusIntervalMS     int     `env:"DP_STATUS_INTERVAL_MS" default:"2000" min:"100" max:"60000" help:"interval of src.v1.network_rid.<uss_id> status messages (04 §3.6: every 2 s)"`
	MaxNotificationBytes int     `env:"DP_MAX_NOTIFICATION_BYTES" default:"262144" min:"1024" max:"4194304" help:"largest ISA change notification accepted"`
	CertificatesBucket   string  `env:"CERTIFICATES_BUCKET" default:"certificates" help:"KV bucket of the certified USSPs api publishes (WP-16); a Service Provider whose ISA owner is not on it is still polled and shown provider_unknown"`
	CertificatesRereadS  int     `env:"DP_CERTIFICATES_REREAD_S" default:"10" min:"1" max:"3600" help:"seconds between reads of the certified USSPs"`
	OversightBucket      string  `env:"DP_OVERSIGHT_BUCKET" default:"dp_oversight" help:"KV bucket of the oversight areas api publishes (POST /v1/dp/views)"`
	ViewsBucket          string  `env:"DP_VIEWS_BUCKET" default:"dp_views" help:"KV bucket of the console viewports picture-ws reports, with a TTL so an idle console stops polling"`
	ProjectionRefreshS   int     `env:"DP_PROJECTION_REFRESH_S" default:"5" min:"1" max:"3600" help:"period of the registry projection re-read besides registry.v1.changed (G-08)"`
	PolicyRereadS        int     `env:"DP_POLICY_REREAD_S" default:"60" min:"1" max:"3600" help:"period of the KV policy re-read besides its watch and ctl.policy (G-08)"`
	NATSTimeoutMS        int     `env:"DP_NATS_TIMEOUT_MS" default:"2000" min:"50" max:"60000" help:"bound on one row hand-over to tsdb-writer or one KV read"`
}

// String redacts secrets.
func (c *DPPoller) String() string { return Describe(c) }

// Validate checks what the tags cannot.
func (c *DPPoller) Validate() error {
	var errs []error
	if c.Addr == c.AdminAddr && !strings.HasSuffix(c.Addr, ":0") {
		errs = append(errs, &core.FieldError{Field: "ADMIN_ADDR", Reason: "must differ from DP_ADDR"})
	}
	if own := c.OwnHost(); own != "" && len(c.Audiences) > 0 && !slices.Contains(c.Audiences, own) {
		errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "must contain this system's own host %q (the host of AUTHORITY_PUBLIC_URL)", own))
	}
	for _, a := range c.Audiences {
		if strings.ContainsAny(a, "/:@ ") || a != strings.ToLower(a) {
			errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "%q is not a lower-case host name", a))
		}
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				errs = append(errs, core.Fieldf("AUTHORITY_TRUSTED_PROXIES", "%q is neither a CIDR nor an address", p))
			}
		}
	}
	return errors.Join(errs...)
}

// OwnHost is the host of AUTHORITY_PUBLIC_URL, lower-case and without a
// port (M18).
func (c *DPPoller) OwnHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// AudienceList is AUTHORITY_AUDIENCES, or the own host alone when unset.
func (c *DPPoller) AudienceList() []string {
	if len(c.Audiences) > 0 {
		return slices.Clone(c.Audiences)
	}
	return []string{c.OwnHost()}
}

// Issuer is ISSUER_URL, or AUTHORITY_PUBLIC_URL, without a trailing
// slash.
func (c *DPPoller) Issuer() string {
	iss := c.IssuerURL
	if iss == "" {
		iss = c.PublicURL
	}
	return strings.TrimSuffix(iss, "/")
}

// JWKS is DP_JWKS_URL, or the issuer's /.well-known/jwks.json.
func (c *DPPoller) JWKS() string {
	if c.JWKSURL != "" {
		return c.JWKSURL
	}
	return c.Issuer() + "/.well-known/jwks.json"
}

// TokenURL is DP_TOKEN_URL, or the issuer's /oauth/token.
func (c *DPPoller) TokenURL() string {
	if c.DPTokenURL != "" {
		return c.DPTokenURL
	}
	return c.Issuer() + "/oauth/token"
}

// SubscriberURL is DP_USS_BASE_URL, or AUTHORITY_PUBLIC_URL, without a
// trailing slash.
func (c *DPPoller) SubscriberURL() string {
	u := c.USSBaseURL
	if u == "" {
		u = c.PublicURL
	}
	return strings.TrimSuffix(u, "/")
}

// MannedIngest is the F4 client of the ANSP manned feed (WP-15).
type MannedIngest struct {
	Common
	Bus
	NATSURL     string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	ANSPBaseURL string `env:"ANSP_BASE_URL" kind:"url" help:"the ANSP's published base URL (GET /v1/manned-traffic/snapshot and WS /v1/manned-traffic/stream under it); its host is the token audience (M18); unset: nothing is connected and the feed is shown unavailable (ansp_unconfigured)"`
	MannedBBox  string `env:"MANNED_BBOX" help:"bbox of the stream and the snapshot, west,south,east,north in WGS84 degrees (Georgia or the designated areas); unset: the ANSP's relevance filter alone decides"`
	MTLSMode    string `env:"AUTHORITY_MTLS_MODE" default:"required" enum:"required|off" help:"client certificate towards the ANSP; off only in the lab and on staging, said at error level on every status line (M25)"`
	ClientCert  string `env:"MANNED_CLIENT_CERT" help:"PEM file of this system's client certificate towards the ANSP; required with AUTHORITY_MTLS_MODE=required"`
	ClientKey   string `env:"MANNED_CLIENT_KEY" help:"PEM file of that certificate's private key; required with AUTHORITY_MTLS_MODE=required"`
	IssuerURL   string `env:"ISSUER_URL" kind:"url" help:"this system's issuer; its /oauth/token issues the ansp.traffic token unless MANNED_TOKEN_URL says otherwise"`
	MannedClient
	MannedTuning
}

// MannedClient is this system's client at its own token service for the
// ANSP's routes (scope ansp.traffic, M24).
type MannedClient struct {
	MannedClientID         string `env:"MANNED_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for the ANSP's manned traffic routes (scope ansp.traffic; M24)"`
	MannedClientSecretFile string `env:"MANNED_CLIENT_SECRET_FILE" help:"file holding that client's secret (client_secret_post); unset: every connection to the ANSP is refused locally and the feed is shown unavailable (no_token)"`
	MannedTokenURL         string `env:"MANNED_TOKEN_URL" kind:"url" help:"the token endpoint; default ISSUER_URL + /oauth/token"`
}

// MannedTuning are the feed's thresholds and bounds (INV-03, E-10).
type MannedTuning struct {
	FeedInstance     string `env:"MANNED_FEED_INSTANCE" default:"ansp" help:"source instance of the feed itself: its status on src.v1.ansp_feed.<instance> and its source switch (switching it off, or the type ansp_feed, closes the stream)"`
	StaleAfterS      int    `env:"MANNED_STALE_AFTER_S" default:"5" min:"1" max:"3600" help:"no frame for this long, console/status/v1 included, and the feed is stale (02 F4: 5 s)"`
	LagAfterS        int    `env:"MANNED_LAG_AFTER_S" default:"15" min:"1" max:"3600" help:"the freshest live aircraft older than this when it arrived and the feed is lagging, with lag_s (B-03: 15 s)"`
	StatusIntervalMS int    `env:"MANNED_STATUS_INTERVAL_MS" default:"2000" min:"100" max:"60000" help:"interval of src.v1.ansp_feed.<instance> (04 §3.6: every 2 s)"`
	SilentReconnectS int    `env:"MANNED_SILENT_RECONNECT_S" default:"15" min:"1" max:"3600" help:"a connection that carried no frame for this long is closed and opened again"`
	RequestTimeoutMS int    `env:"MANNED_REQUEST_TIMEOUT_MS" default:"5000" min:"100" max:"60000" help:"bound on the token, the snapshot and the WebSocket upgrade"`
	BackoffMinMS     int    `env:"MANNED_BACKOFF_MIN_MS" default:"500" min:"10" max:"600000" help:"first reconnection delay, doubled up to MANNED_BACKOFF_MAX_MS, jittered; reconnection never stops (B-08)"`
	BackoffMaxMS     int    `env:"MANNED_BACKOFF_MAX_MS" default:"30000" min:"10" max:"600000" help:"longest reconnection delay"`
	MaxAircraft      int    `env:"MANNED_MAX_AIRCRAFT" default:"10000" min:"1" max:"10000000" help:"aircraft whose last published state is remembered; past it the one updated longest ago is forgotten and counted (E-10)"`
	MaxSourceAheadMS int    `env:"MANNED_MAX_SOURCE_AHEAD_MS" default:"5000" min:"100" max:"600000" help:"a sample stamped more than this after it arrived is ordered at its arrival plus this, counted source_time_in_future, so an ANSP clock jump cannot freeze an aircraft"`
	MaxFrameBytes    int    `env:"MANNED_MAX_FRAME_BYTES" default:"4194304" min:"1024" max:"67108864" help:"largest frame read from the stream; a larger one closes the connection, which is opened again"`
	MaxSnapshotBytes int    `env:"MANNED_MAX_SNAPSHOT_BYTES" default:"16777216" min:"1024" max:"268435456" help:"largest snapshot read"`
	MaxSnapshotItems int    `env:"MANNED_MAX_SNAPSHOT_ITEMS" default:"10000" min:"1" max:"10000000" help:"aircraft taken from one snapshot; the rest are counted"`
	MaxAdapters      int    `env:"MANNED_MAX_ADAPTERS" default:"64" min:"1" max:"10000" help:"ANSP adapters followed; the rest are counted"`
	RowsQueue        int    `env:"MANNED_ROWS_QUEUE" default:"1024" min:"1" max:"1000000" help:"row batches waiting for tsdb-writer; past it a batch is shed, counted and recorded as a writer gap"`
	NATSTimeoutMS    int    `env:"MANNED_NATS_TIMEOUT_MS" default:"2000" min:"50" max:"60000" help:"bound on one row hand-over to tsdb-writer"`
	SwitchesReapplyS int    `env:"MANNED_SWITCHES_REAPPLY_S" default:"5" min:"1" max:"3600" help:"period of the re-application of source control to the aircraft held besides the follower's changes"`
}

// String redacts secrets.
func (c *MannedIngest) String() string { return Describe(c) }

// Validate checks what the tags cannot.
func (c *MannedIngest) Validate() error {
	var errs []error
	if c.MTLSMode == "required" && (c.ClientCert == "" || c.ClientKey == "") {
		errs = append(errs, &core.FieldError{Field: "MANNED_CLIENT_CERT", Reason: "MANNED_CLIENT_CERT and MANNED_CLIENT_KEY are required with AUTHORITY_MTLS_MODE=required"})
	}
	if c.MannedBBox != "" {
		if _, err := ParseBBox(c.MannedBBox); err != nil {
			errs = append(errs, core.Fieldf("MANNED_BBOX", "%s", err.Error()))
		}
	}
	if !validInstance(c.FeedInstance) {
		errs = append(errs, &core.FieldError{Field: "MANNED_FEED_INSTANCE", Reason: "lower-case letters, digits and single hyphens, starting with a letter"})
	}
	if c.BackoffMaxMS < c.BackoffMinMS {
		errs = append(errs, &core.FieldError{Field: "MANNED_BACKOFF_MAX_MS", Reason: "less than MANNED_BACKOFF_MIN_MS"})
	}
	if c.ANSPBaseURL != "" {
		u, err := url.Parse(c.ANSPBaseURL)
		switch {
		case err != nil || (u.Scheme != "https" && u.Scheme != "http"):
			errs = append(errs, &core.FieldError{Field: "ANSP_BASE_URL", Reason: "must be an https (or, in the lab, http) URL"})
		case u.Scheme == "http" && c.MTLSMode == "required" && !loopbackHost(u.Hostname()):
			// Plain http presents no client certificate and sends the
			// ansp.traffic bearer in clear (audit B-S8).
			errs = append(errs, &core.FieldError{Field: "ANSP_BASE_URL",
				Reason: "plain http only to a loopback host with AUTHORITY_MTLS_MODE=required: use https, or mTLS off in the lab"})
		}
	}
	return errors.Join(errs...)
}

// loopbackHost reports whether host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// TokenURL is MANNED_TOKEN_URL, or ISSUER_URL's /oauth/token, or empty.
func (c *MannedIngest) TokenURL() string {
	if c.MannedTokenURL != "" {
		return c.MannedTokenURL
	}
	if c.IssuerURL != "" {
		return strings.TrimSuffix(c.IssuerURL, "/") + "/oauth/token"
	}
	return ""
}

// ParseBBox reads west,south,east,north in WGS84 degrees (west > east
// crosses the antimeridian).
func ParseBBox(s string) ([4]float64, error) {
	var b [4]float64
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return b, errors.New("four numbers west,south,east,north")
	}
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return b, fmt.Errorf("%q is not a number", p)
		}
		b[i] = v
	}
	switch {
	case b[0] < -180 || b[0] > 180 || b[2] < -180 || b[2] > 180:
		return b, errors.New("longitudes within [-180, 180]")
	case b[1] < -90 || b[1] > 90 || b[3] < -90 || b[3] > 90:
		return b, errors.New("latitudes within [-90, 90]")
	case b[1] >= b[3]:
		return b, errors.New("south below north")
	}
	return b, nil
}

func validInstance(s string) bool {
	if s == "" || len(s) > 64 || s[0] < 'a' || s[0] > 'z' || strings.HasSuffix(s, "-") || strings.Contains(s, "--") {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Detect runs the violation detectors per cell.
type Detect struct {
	Common
	Bus
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	Ground
	WorkerID string `env:"DETECT_WORKER_ID" default:"detect-1" help:"this worker's id in the cell ownership map (KV cells, PUT /v1/cells)"`
	Cells    string `env:"CELLS" enum:"all" help:"all: judge every cell whatever the ownership map says (the demo); empty: the cells the map gives DETECT_WORKER_ID, and refuse to start with none"`
	DetectTuning
	DetectIntents
}

// DetectIntents is the no_authorisation detector's access to the DSS
// (WP-26; spec 04 §3.3, 02 F6; docs/PLAN.md Q-A5): POST
// /dss/v1/operational_intent_references/query with a token for the DSS's
// host granting utm.conformance_monitoring_sa, from this system's client
// at its own token service. Without DSS_BASE_URL and a client secret
// nothing is read, and while a U-space airspace is in force every status
// line says no_authorisation is not judged (E-02). The thresholds of the
// judgement (no_authorisation_grace_s, no_authorisation_severity,
// height_limit_in_uspace) are authority_policy columns (INV-03); these
// are the bounds and periods of the reads.
type DetectIntents struct {
	DSSBaseURL         string  `env:"DSS_BASE_URL" kind:"url" help:"InterUSS DSS base URL (F3548 under /dss/v1); its host is the audience of the tokens towards it (M18); unset: no_authorisation is not judged"`
	IssuerURL          string  `env:"ISSUER_URL" kind:"url" help:"this system's issuer, whose /oauth/token the detector asks for its DSS token (unless DETECT_TOKEN_URL)"`
	ClientID           string  `env:"DETECT_CLIENT_ID" default:"authority-01" help:"this system's client id at its own token service for the detector's DSS reads (M24)"`
	ClientSecretFile   string  `env:"DETECT_CLIENT_SECRET_FILE" help:"file holding that client's secret (client_secret_post); unset: no DSS read is made and no_authorisation is not judged"`
	DetectTokenURL     string  `env:"DETECT_TOKEN_URL" kind:"url" help:"the token endpoint the detector asks; default ISSUER_URL + /oauth/token"`
	IntentRequeryS     int     `env:"DETECT_INTENT_REQUERY_S" default:"5" min:"1" max:"3600" help:"period of the read of every U-space airspace in force (F3548 subscriptions need utm.strategic_coordination, which the authority does not hold, Q-A5: the period stands in for them)"`
	IntentHorizonS     int     `env:"DETECT_INTENT_HORIZON_S" default:"3600" min:"60" max:"86400" help:"how far ahead an airspace is read (the next hour)"`
	IntentRecheckMS    int     `env:"DETECT_INTENT_RECHECK_MS" default:"2000" min:"100" max:"60000" help:"least time between two reads of one aircraft's position"`
	IntentChecksPerS   int     `env:"DETECT_INTENT_CHECKS_PER_S" default:"20" min:"1" max:"1000" help:"aircraft positions read from the DSS per second at most; the rest wait (counted intent_checks_deferred)"`
	IntentRadiusM      float64 `env:"DETECT_INTENT_CHECK_RADIUS_M" default:"10" min:"1" max:"1000" help:"radius of the area asked around an aircraft's position"`
	IntentVMarginM     float64 `env:"DETECT_INTENT_VERTICAL_MARGIN_M" default:"10" min:"0" max:"1000" help:"each way around an aircraft's WGS84 height in the area asked"`
	IntentOutcomeMaxS  int     `env:"DETECT_INTENT_OUTCOME_MAX_AGE_S" default:"10" min:"1" max:"600" help:"how long an aircraft's last judgement stands; past it the aircraft is suspended (neither raised nor cleared)"`
	IntentMaxAircraft  int     `env:"DETECT_INTENT_MAX_AIRCRAFT" default:"10000" min:"1" max:"1000000" help:"aircraft inside U-space airspace held for no_authorisation; past it a new one is refused and counted (E-10)"`
	IntentMaxZones     int     `env:"DETECT_INTENT_MAX_ZONES" default:"64" min:"1" max:"10000" help:"U-space airspaces read; past it the rest are counted and not judged"`
	IntentMaxCached    int     `env:"DETECT_INTENT_MAX_CACHED" default:"10000" min:"1" max:"1000000" help:"operational intent references held; past it the oldest withdrawn, else the one seen longest ago, is dropped and counted (E-10); none is kept past 24 h"`
	IntentMaxRefs      int     `env:"DETECT_INTENT_MAX_REFS" default:"1000" min:"1" max:"100000" help:"references taken from one DSS answer; a larger answer is refused whole and the detector suspended"`
	IntentMaxBodyBytes int     `env:"DETECT_INTENT_MAX_BODY_BYTES" default:"1048576" min:"1024" max:"4194304" help:"largest DSS answer read"`
	IntentTimeoutMS    int     `env:"DETECT_INTENT_REQUEST_TIMEOUT_MS" default:"5000" min:"100" max:"60000" help:"deadline of one DSS read"`
}

// TokenURL is DETECT_TOKEN_URL, or ISSUER_URL's /oauth/token, or "".
func (c *DetectIntents) TokenURL() string {
	if c.DetectTokenURL != "" {
		return c.DetectTokenURL
	}
	if c.IssuerURL == "" {
		return ""
	}
	return strings.TrimSuffix(c.IssuerURL, "/") + "/oauth/token"
}

// Validate checks what the tags cannot: a client secret needs a token
// endpoint.
func (c *Detect) Validate() error {
	if c.ClientSecretFile != "" && c.TokenURL() == "" {
		return core.Fieldf("DETECT_TOKEN_URL", "required with DETECT_CLIENT_SECRET_FILE when ISSUER_URL is unset")
	}
	return nil
}

// DetectTuning are detect's bounds and periods (WP-12). The judgement's
// thresholds are not here: they are the active authority_policy, followed
// from KV policy (INV-03).
type DetectTuning struct {
	MaxAckPending       int `env:"DETECT_MAX_ACK_PENDING" default:"1000" min:"1" max:"100000" help:"tracks delivered to a worker and not yet acknowledged (max_ack_pending, 05 §5)"`
	AckWaitS            int `env:"DETECT_ACK_WAIT_S" default:"30" min:"1" max:"3600" help:"ack wait of the track consumers"`
	FetchMax            int `env:"DETECT_FETCH_MAX" default:"256" min:"1" max:"10000" help:"tracks one pull asks for"`
	MaxAircraft         int `env:"DETECT_MAX_AIRCRAFT" default:"50000" min:"1" max:"10000000" help:"aircraft one monitor holds (alerting.Config.MaxAircraft, C-18); past it an aircraft without an open violation is evicted, and with none a new one is refused, counted and logged at error level (E-10)"`
	ExcerptWindowS      int `env:"DETECT_EXCERPT_WINDOW_S" default:"10" min:"1" max:"600" help:"seconds of track samples a violation copies at its raise (evidence_excerpt, 03 §1)"`
	ExcerptMaxSamples   int `env:"DETECT_EXCERPT_MAX_SAMPLES" default:"64" min:"1" max:"10000" help:"samples kept per aircraft for the excerpt; past it the oldest is dropped and counted (E-10)"`
	OutboxMax           int `env:"DETECT_OUTBOX_MAX" default:"10000" min:"1" max:"10000000" help:"raises and clears waiting for the ALRT stream; past it the oldest is dropped, counted and logged at error level"`
	PublishTimeoutMS    int `env:"DETECT_PUBLISH_TIMEOUT_MS" default:"2000" min:"10" max:"60000" help:"bound on one violation write to ALRT"`
	TickBudgetMS        int `env:"DETECT_TICK_BUDGET_MS" default:"500" min:"10" max:"60000" help:"bound on the publishing of one tick (outbox and republication of active violations); what is left is deferred to the next tick"`
	ZonesRefreshS       int `env:"DETECT_ZONES_REFRESH_S" default:"60" min:"1" max:"3600" help:"period of the zones projection re-read besides zones.v1.changed (G-08)"`
	RestrictionsRefresh int `env:"DETECT_RESTRICTIONS_REFRESH_S" default:"60" min:"1" max:"3600" help:"period of the restrictions projection re-read besides cis.v1.restrictions (G-08, Z-12)"`
	PolicyRereadS       int `env:"DETECT_POLICY_REREAD_S" default:"60" min:"1" max:"3600" help:"period of the KV policy re-read besides its watch and ctl.policy (G-08)"`
	TSMaxConns          int `env:"TS_MAX_CONNS" default:"2" min:"1" max:"100" help:"connections of the read-only projection pool"`
}

// String redacts secrets.
func (c *Detect) String() string { return Describe(c) }

// TSDBWriter is the only writer of the hypertables.
type TSDBWriter struct {
	Common
	Bus
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	TSDBWriterTuning
}

// TSDBWriterTuning are tsdb-writer's bounds (WP-9, spec 05 §5).
type TSDBWriterTuning struct {
	BatchMaxRows        int `env:"TSDB_WRITER_BATCH_MAX_ROWS" default:"1000" min:"1" max:"1000" help:"rows per COPY transaction at most; a batch is written at this many rows or at TSDB_WRITER_BATCH_MAX_WAIT_MS"`
	BatchMaxWaitMS      int `env:"TSDB_WRITER_BATCH_MAX_WAIT_MS" default:"500" min:"10" max:"10000" help:"a batch is written when its oldest row has waited this long"`
	QueueMaxAgeS        int `env:"TSDB_WRITER_QUEUE_MAX_AGE_S" default:"10" min:"1" max:"600" help:"the in-memory queue per table holds at most this much: when its oldest row has waited this long the consumer stops pulling and the rows wait in JetStream (spilling)"`
	QueueMaxRows        int `env:"TSDB_WRITER_QUEUE_MAX_ROWS" default:"30000" min:"1" max:"10000000" help:"the in-memory queue per table holds at most this many rows (10 s at 3000 rows/s); at it the consumer stops pulling (spilling)"`
	MaxAckPending       int `env:"TSDB_WRITER_MAX_ACK_PENDING" default:"1000" min:"1" max:"100000" help:"TSW messages per table delivered and not yet acknowledged (max_ack_pending)"`
	FetchMax            int `env:"TSDB_WRITER_FETCH_MAX" default:"64" min:"1" max:"1000" help:"TSW messages one pull asks for; the queue may pass its row bound by at most one pull"`
	AckWaitS            int `env:"TSDB_WRITER_ACK_WAIT_S" default:"60" min:"5" max:"3600" help:"ack wait of the TSW consumers; a message held longer than half of it is kept with in-progress"`
	WriteTimeoutS       int `env:"TSDB_WRITER_WRITE_TIMEOUT_S" default:"15" min:"1" max:"600" help:"bound on one COPY transaction"`
	RetryMinMS          int `env:"TSDB_WRITER_RETRY_MIN_MS" default:"250" min:"10" max:"60000" help:"first wait after a failed write; doubled up to TSDB_WRITER_RETRY_MAX_MS"`
	RetryMaxMS          int `env:"TSDB_WRITER_RETRY_MAX_MS" default:"5000" min:"10" max:"600000" help:"longest wait between failed writes"`
	RetentionCheckS     int `env:"TSDB_WRITER_RETENTION_CHECK_S" default:"3600" min:"1" max:"86400" help:"interval of the check that a table with a retention period (ussp_flights, 24 h) holds nothing older"`
	TSMaxConns          int `env:"TS_MAX_CONNS" default:"4" min:"1" max:"100" help:"maximum connections of the writer pool"`
	TSStatementTimeoutS int `env:"TS_STATEMENT_TIMEOUT_S" default:"15" min:"1" max:"600" help:"statement_timeout of every writer connection"`
}

// String redacts secrets.
func (c *TSDBWriter) String() string { return Describe(c) }

// Validate checks what the tags cannot.
func (c *TSDBWriter) Validate() error {
	var errs []error
	if c.RetryMaxMS < c.RetryMinMS {
		errs = append(errs, &core.FieldError{Field: "TSDB_WRITER_RETRY_MAX_MS", Reason: "must be at least TSDB_WRITER_RETRY_MIN_MS"})
	}
	if 2*c.QueueMaxAgeS >= c.AckWaitS {
		// A queued message is kept alive (in progress) only on the
		// failure paths: a healthy queue older than half the ack wait
		// is redelivered while held (audit B-N3).
		errs = append(errs, &core.FieldError{Field: "TSDB_WRITER_QUEUE_MAX_AGE_S",
			Reason: "must be under half of TSDB_WRITER_ACK_WAIT_S, or queued messages are redelivered while held"})
	}
	return errors.Join(errs...)
}

// PictureWS is the console feed (WP-13).
type PictureWS struct {
	Common
	Bus
	HTTP
	Addr      string   `env:"PICTURE_ADDR" default:":8083" help:"public listen address of /v1/picture/* (behind Caddy)"`
	TSURL     string   `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL   string   `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	PublicURL string   `env:"AUTHORITY_PUBLIC_URL" required:"true" kind:"url" help:"this system's published base URL; its host is the audience of the sessions the picture accepts, its origin the default allowed origin"`
	Audiences []string `env:"AUTHORITY_AUDIENCES" help:"accepted session audiences (hosts), comma-separated: own host plus a lab alias; default the host of AUTHORITY_PUBLIC_URL"`
	IssuerURL string   `env:"ISSUER_URL" kind:"url" help:"iss of the sessions the picture accepts (this system's issuer); default AUTHORITY_PUBLIC_URL"`
	PictureTuning
}

// PictureTuning are picture-ws's bounds and periods (WP-13). The display
// thresholds a console renders with (stale_after_s, live_max_age_s) are
// not here: they are the active authority_policy, followed from KV
// policy and carried in every console/status/v1 frame (INV-03).
type PictureTuning struct {
	AllowedOrigins         []string `env:"PICTURE_ALLOWED_ORIGINS" help:"origins (scheme://host[:port]) a console may open the WebSocket from, comma-separated, exact match (M22); default the origin of AUTHORITY_PUBLIC_URL"`
	SessionURL             string   `env:"PICTURE_SESSION_URL" required:"true" kind:"url" help:"api's GET /v1/auth/session on the private network (http://api:8080/v1/auth/session in compose): every session is checked there against the sessions table, so a logout or a revocation ends the stream"`
	JWKSURL                string   `env:"PICTURE_JWKS_URL" kind:"url" help:"this issuer's JWKS (https; http only to a loopback host); default ISSUER_URL + /.well-known/jwks.json"`
	SessionRecheckS        int      `env:"PICTURE_SESSION_RECHECK_S" default:"15" min:"1" max:"300" help:"seconds between re-checks of a connection's session against the sessions table; a revoked session is closed with 4401 within this"`
	SessionGraceS          int      `env:"PICTURE_SESSION_GRACE_S" default:"60" min:"1" max:"3600" help:"a connection whose session cannot be re-checked (api unreachable) is kept this long after its last good check, then closed with 1013"`
	SessionTimeoutMS       int      `env:"PICTURE_SESSION_TIMEOUT_MS" default:"2000" min:"100" max:"60000" help:"bound on one session check against api"`
	MaxClients             int      `env:"PICTURE_MAX_CLIENTS" default:"500" min:"1" max:"100000" help:"WebSocket connections this instance serves; the next upgrade is refused with 503"`
	SendBuffer             int      `env:"PICTURE_SEND_BUFFER" default:"1024" min:"8" max:"1000000" help:"live frames queued per connection; a frame that does not fit is dropped and counted in that connection's dropped_frames"`
	WriteTimeoutS          int      `env:"PICTURE_WRITE_TIMEOUT_S" default:"5" min:"1" max:"60" help:"bound on one frame write; a connection that does not take a frame within it is closed"`
	StatusIntervalMS       int      `env:"PICTURE_STATUS_INTERVAL_MS" default:"2000" min:"200" max:"10000" help:"interval of console/status/v1 frames and of the source and alert checks (M29: 2 s)"`
	MaxCells               int      `env:"PICTURE_MAX_CELLS" default:"2000" min:"1" max:"100000" help:"c5 cells one viewport may cover with its one-cell margin; a larger viewport is refused and the connection keeps its previous one (E-10)"`
	MaxTracks              int      `env:"PICTURE_MAX_TRACKS" default:"50000" min:"1" max:"10000000" help:"tracks the cache holds; past it the one updated longest ago is evicted and counted (E-10)"`
	MaxManned              int      `env:"PICTURE_MAX_MANNED" default:"10000" min:"1" max:"10000000" help:"manned aircraft the cache holds; past it the one updated longest ago is evicted and counted"`
	MaxAlerts              int      `env:"PICTURE_MAX_ALERTS" default:"10000" min:"1" max:"1000000" help:"active violations held for replay to a connecting console (C-08); past it the one heard longest ago is evicted and counted"`
	ThrottleAboveTracks    int      `env:"PICTURE_THROTTLE_ABOVE_TRACKS" default:"200" min:"1" max:"1000000" help:"a viewport holding more tracks than this is throttled per track (05 §3: 200)"`
	ThrottleHz             float64  `env:"PICTURE_THROTTLE_HZ" default:"2" min:"0.1" max:"100" help:"frames per track per second to a throttled viewport (05 §3: 2 Hz)"`
	AlertSilentS           int      `env:"PICTURE_ALERT_SILENT_S" default:"5" min:"2" max:"3600" help:"an active violation detect has not republished for this long is shown unconfirmed (detect republishes every second, C-08)"`
	AlertForgetS           int      `env:"PICTURE_ALERT_FORGET_S" default:"120" min:"10" max:"86400" help:"an active violation neither republished nor cleared for this long leaves the picture, counted and logged; a later republish brings it back"`
	AlertReplayS           int      `env:"PICTURE_ALERT_REPLAY_S" default:"10" min:"2" max:"3600" help:"seconds of ALRT read back at start, so active violations are replayed at once (C-08)"`
	AlertReplayMax         int      `env:"PICTURE_ALERT_REPLAY_MAX" default:"100000" min:"1" max:"10000000" help:"ALRT messages one read-back takes at most (at start, and after the bus comes back from the instant it was lost); past it the rest is counted and logged"`
	ProjectionRefreshS     int      `env:"PICTURE_PROJECTION_REFRESH_S" default:"5" min:"1" max:"3600" help:"seconds between reads of the projection ages and versions (database clock)"`
	TSMaxConns             int      `env:"TS_MAX_CONNS" default:"2" min:"1" max:"100" help:"connections of the read-only projection pool"`
	PolicyRereadS          int      `env:"PICTURE_POLICY_REREAD_S" default:"60" min:"1" max:"3600" help:"period of the KV policy re-read besides its watch and ctl.policy (G-08)"`
	DPViewsBucket          string   `env:"DP_VIEWS_BUCKET" default:"dp_views" help:"KV bucket the consoles' viewports are reported to for the Display Provider (WP-14; the same variable in dp-poller)"`
	SubscribeMaxBytes      int      `env:"PICTURE_SUBSCRIBE_MAX_BYTES" default:"4096" min:"256" max:"65536" help:"largest frame a console may send (console/subscribe/v1); a larger one closes the connection with 1009"`
	SubscribeMinIntervalMS int      `env:"PICTURE_SUBSCRIBE_MIN_INTERVAL_MS" default:"100" min:"0" max:"10000" help:"subscriptions of one connection are applied at most this often; one arriving sooner waits, and those it supersedes meanwhile are never applied (subscribes_coalesced)"`
	SnapshotMaxBytes       int      `env:"PICTURE_SNAPSHOT_MAX_BYTES" default:"8388608" min:"65536" max:"268435456" help:"bound on the items of one console/snapshot/v1 (violations first, then tracks, then manned); past it the rest is left out and the snapshot says truncated (E-10)"`
	SourceStatusStaleS     int      `env:"SOURCE_STATUS_STALE_S" default:"10" min:"1" max:"3600" help:"an adapter whose last src.v1 status is older is silent: its sources are shown stale"`
	SourceStatusMax        int      `env:"SOURCE_STATUS_MAX" default:"10000" min:"1" max:"1000000" help:"sources whose last status the picture keeps; past it the one heard longest ago is dropped and counted (E-10)"`
}

// Validate checks what the tags cannot.
func (c *PictureWS) Validate() error {
	var errs []error
	if c.Addr == c.AdminAddr && !strings.HasSuffix(c.Addr, ":0") {
		errs = append(errs, &core.FieldError{Field: "ADMIN_ADDR", Reason: "must differ from PICTURE_ADDR"})
	}
	if own := c.OwnHost(); own != "" && len(c.Audiences) > 0 && !slices.Contains(c.Audiences, own) {
		errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "must contain this system's own host %q (the host of AUTHORITY_PUBLIC_URL)", own))
	}
	for _, a := range c.Audiences {
		if strings.ContainsAny(a, "/:@ ") || a != strings.ToLower(a) {
			errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "%q is not a lower-case host name", a))
		}
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				errs = append(errs, core.Fieldf("AUTHORITY_TRUSTED_PROXIES", "%q is neither a CIDR nor an address", p))
			}
		}
	}
	for _, o := range c.AllowedOrigins {
		u, err := url.Parse(strings.TrimSpace(o))
		if _, ok := OriginOf(o); !ok || err != nil || (u.Path != "" && u.Path != "/") {
			errs = append(errs, core.Fieldf("PICTURE_ALLOWED_ORIGINS", "%q is not an origin (scheme://host[:port])", o))
		}
	}
	if u, err := url.Parse(c.Issuer()); err == nil && (u.RawQuery != "" || u.Fragment != "") {
		errs = append(errs, core.Fieldf("ISSUER_URL", "must have no query or fragment"))
	}
	if c.AlertForgetS <= c.AlertSilentS {
		errs = append(errs, core.Fieldf("PICTURE_ALERT_FORGET_S", "must exceed PICTURE_ALERT_SILENT_S"))
	}
	return errors.Join(errs...)
}

// OwnHost is the host of AUTHORITY_PUBLIC_URL, lower-case and without a
// port: the aud of this system's sessions (M18, M20).
func (c *PictureWS) OwnHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// AudienceList is AUTHORITY_AUDIENCES, or the own host alone when unset.
func (c *PictureWS) AudienceList() []string {
	if len(c.Audiences) > 0 {
		return slices.Clone(c.Audiences)
	}
	return []string{c.OwnHost()}
}

// Issuer is ISSUER_URL, or AUTHORITY_PUBLIC_URL when unset, without a
// trailing slash.
func (c *PictureWS) Issuer() string {
	iss := c.IssuerURL
	if iss == "" {
		iss = c.PublicURL
	}
	return strings.TrimSuffix(iss, "/")
}

// JWKS is PICTURE_JWKS_URL, or the issuer's /.well-known/jwks.json.
func (c *PictureWS) JWKS() string {
	if c.JWKSURL != "" {
		return c.JWKSURL
	}
	return c.Issuer() + "/.well-known/jwks.json"
}

// Origins is PICTURE_ALLOWED_ORIGINS normalised, or the origin of
// AUTHORITY_PUBLIC_URL when unset.
func (c *PictureWS) Origins() []string {
	raw := c.AllowedOrigins
	if len(raw) == 0 {
		raw = []string{c.PublicURL}
	}
	var out []string
	for _, o := range raw {
		if n, ok := OriginOf(o); ok && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// OriginOf is the origin of the URL raw as a browser writes it in the
// Origin header: lower-case scheme and host, the port only when it is
// not the scheme's default; the path is ignored. ok is false for
// anything that is not http(s) with a host.
func OriginOf(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

// String redacts secrets.
func (c *PictureWS) String() string { return Describe(c) }

// Migrate is the one-shot migrate subcommand: both trees, in order.
type Migrate struct {
	LogLevel string `env:"LOG_LEVEL" default:"info" enum:"debug|info|warn|error" help:"minimum level of the JSON log on stdout"`
	PGURL    string `env:"PG_URL" required:"true" secret:"true" kind:"url" help:"relational database (PostgreSQL + PostGIS)"`
	TSURL    string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (TimescaleDB)"`
}

// String redacts secrets.
func (c *Migrate) String() string { return Describe(c) }

// Validate checks what the tags cannot: the two trees live in two
// databases, never one (CLAUDE.md rule 10).
func (c *Migrate) Validate() error {
	if c.PGURL == c.TSURL {
		return &core.FieldError{Field: "TS_URL", Reason: "must name a different database from PG_URL"}
	}
	return nil
}

// Validate checks what the tags cannot.
func (c *API) Validate() error {
	var errs []error
	if c.PGURL == c.TSURL {
		errs = append(errs, &core.FieldError{Field: "TS_URL", Reason: "must name a different database from PG_URL"})
	}
	if c.Addr == c.AdminAddr && !strings.HasSuffix(c.Addr, ":0") {
		errs = append(errs, &core.FieldError{Field: "ADMIN_ADDR", Reason: "must differ from API_ADDR"})
	}
	if own := c.OwnHost(); own != "" && len(c.Audiences) > 0 && !slices.Contains(c.Audiences, own) {
		errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "must contain this system's own host %q (the host of AUTHORITY_PUBLIC_URL)", own))
	}
	for _, a := range c.Audiences {
		if strings.ContainsAny(a, "/:@ ") || a != strings.ToLower(a) {
			errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "%q is not a lower-case host name", a))
		}
	}
	if c.CISCallbackURL != "" {
		// The CISP signs a notification's aud as the host of the
		// callback (WP-2); a host this receiver does not accept would
		// have every webhook refused while the subscription shows
		// active (system audit F-5, as the ANSP refuses it).
		if u, err := url.Parse(c.CISCallbackURL); err == nil && !slices.Contains(c.AudienceList(), strings.ToLower(u.Hostname())) {
			errs = append(errs, core.Fieldf("CIS_CALLBACK_URL", "its host %q is not one of AUTHORITY_AUDIENCES %v: the CISP signs aud as that host and every notification would be refused",
				strings.ToLower(u.Hostname()), c.AudienceList()))
		}
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				errs = append(errs, core.Fieldf("AUTHORITY_TRUSTED_PROXIES", "%q is neither a CIDR nor an address", p))
			}
		}
	}
	for _, pr := range [][3]string{
		{"CISP_ISSUER_URL", c.CISPIssuerURL, c.CISPJWKSURL}, {"ANSP_ISSUER_URL", c.ANSPIssuerURL, c.ANSPJWKSURL},
		{"LAB_ISSUER_URL", c.LabIssuerURL, c.LabJWKSURL},
	} {
		if (pr[1] == "") != (pr[2] == "") {
			errs = append(errs, core.Fieldf(pr[0], "set it together with its JWKS URL, or neither"))
		}
	}
	if c.MFAHardLockAfter <= c.MFALockoutAfter {
		errs = append(errs, core.Fieldf("MFA_HARD_LOCK_AFTER", "must exceed MFA_LOCKOUT_AFTER"))
	}
	if c.MFALockoutMaxS < c.MFALockoutBaseS {
		errs = append(errs, core.Fieldf("MFA_LOCKOUT_MAX_S", "must not be shorter than MFA_LOCKOUT_BASE_S"))
	}
	if _, err := c.MTOMBounds(); err != nil {
		errs = append(errs, err)
	}
	if (c.BootstrapAdmin == "") != (c.BootstrapPassword == "") {
		errs = append(errs, core.Fieldf("BOOTSTRAP_ADMIN_USERNAME", "set it together with BOOTSTRAP_ADMIN_PASSWORD_FILE, or neither"))
	}
	if u, err := url.Parse(c.Issuer()); err == nil && (u.RawQuery != "" || u.Fragment != "") {
		errs = append(errs, core.Fieldf("ISSUER_URL", "must have no query or fragment"))
	}
	if _, err := c.NotifyIssuerList(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.SubscriptionBBox(); err != nil {
		errs = append(errs, err)
	}
	if c.CISSendBackoffMaxS < c.CISSendBackoffMinS {
		errs = append(errs, core.Fieldf("CIS_SEND_BACKOFF_MAX_S", "must not be shorter than CIS_SEND_BACKOFF_MIN_S"))
	}
	errs = append(errs, c.validatePortal()...)
	errs = append(errs, c.validateRetention()...)
	return errors.Join(errs...)
}

// OwnHost is the host of AUTHORITY_PUBLIC_URL, lower-case and without a
// port: the aud of this system's sessions and of tokens addressed to it
// (M18).
func (c *API) OwnHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// AudienceList is AUTHORITY_AUDIENCES, or the own host alone when unset.
func (c *API) AudienceList() []string {
	if len(c.Audiences) > 0 {
		return slices.Clone(c.Audiences)
	}
	return []string{c.OwnHost()}
}

// Issuer is ISSUER_URL, or AUTHORITY_PUBLIC_URL when unset, without a
// trailing slash.
func (c *API) Issuer() string {
	iss := c.IssuerURL
	if iss == "" {
		iss = c.PublicURL
	}
	return strings.TrimSuffix(iss, "/")
}
