package config

import (
	"errors"
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
	MaxBodyBytes        int     `env:"HTTP_MAX_BODY_BYTES" default:"1048576" min:"1024" max:"67108864" help:"default request body cap; routes may override it"`
	ReadHeaderTimeoutS  int     `env:"HTTP_READ_HEADER_TIMEOUT_S" default:"5" min:"1" max:"60" help:"time allowed to read request headers"`
	RateLimitRPS        float64 `env:"HTTP_RATE_LIMIT_RPS" default:"20" min:"0.1" help:"sustained requests per second per client"`
	RateLimitBurst      int     `env:"HTTP_RATE_LIMIT_BURST" default:"40" min:"1" help:"burst size per client"`
	RateLimitMaxClients int     `env:"HTTP_RATE_LIMIT_MAX_CLIENTS" default:"10000" min:"1" help:"clients tracked by the rate limiter; the least recently seen is evicted beyond it"`
}

// API is the control plane.
type API struct {
	Common
	HTTP
	Addr      string   `env:"API_ADDR" default:":8080" help:"public listen address (behind Caddy)"`
	PGURL     string   `env:"PG_URL" required:"true" secret:"true" kind:"url" help:"relational database (PostgreSQL + PostGIS); only api opens it"`
	TSURL     string   `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (TimescaleDB)"`
	NATSURL   string   `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream; may carry credentials"`
	PublicURL string   `env:"AUTHORITY_PUBLIC_URL" required:"true" kind:"url" help:"this system's published base URL; its host is the token audience and the issuer"`
	Audiences []string `env:"AUTHORITY_AUDIENCES" help:"accepted JWT audiences (hosts), comma-separated: own host plus a lab alias"`
	MTLSMode  string   `env:"AUTHORITY_MTLS_MODE" default:"required" enum:"required|off" help:"mTLS on machine routes; off only in the lab and on staging"`
}

// String redacts secrets.
func (c *API) String() string { return Describe(c) }

// RIDIngest is the F9 receiver ingest.
type RIDIngest struct {
	Common
	HTTP
	Addr    string `env:"RID_INGEST_ADDR" default:":8081" help:"public listen address of /v1/rid/observations (behind Caddy)"`
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
}

// String redacts secrets.
func (c *RIDIngest) String() string { return Describe(c) }

// DPPoller is the F3411 Display Provider.
type DPPoller struct {
	Common
	HTTP
	Addr       string `env:"DP_ADDR" default:":8082" help:"public listen address of /uss/* (behind Caddy)"`
	TSURL      string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL    string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	DSSBaseURL string `env:"DSS_BASE_URL" kind:"url" help:"InterUSS DSS base URL; required once WP-14 lands"`
}

// String redacts secrets.
func (c *DPPoller) String() string { return Describe(c) }

// MannedIngest is the F4 client of the ANSP manned feed.
type MannedIngest struct {
	Common
	NATSURL     string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	ANSPFeedURL string `env:"ANSP_FEED_URL" kind:"url" help:"ANSP manned-traffic WebSocket; required once WP-15 lands"`
	MTLSMode    string `env:"AUTHORITY_MTLS_MODE" default:"required" enum:"required|off" help:"client certificate towards the ANSP; off only in the lab and on staging"`
}

// String redacts secrets.
func (c *MannedIngest) String() string { return Describe(c) }

// Detect runs the violation detectors per cell.
type Detect struct {
	Common
	TSURL     string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL   string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
	GroundDir string `env:"GROUND_DIR" help:"directory of terrain tiles and the geoid grid; required once WP-11 lands"`
}

// String redacts secrets.
func (c *Detect) String() string { return Describe(c) }

// TSDBWriter is the only writer of the hypertables.
type TSDBWriter struct {
	Common
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
}

// String redacts secrets.
func (c *TSDBWriter) String() string { return Describe(c) }

// PictureWS is the console feed.
type PictureWS struct {
	Common
	HTTP
	Addr    string `env:"PICTURE_ADDR" default:":8083" help:"public listen address of /v1/picture/* (behind Caddy)"`
	TSURL   string `env:"TS_URL" required:"true" secret:"true" kind:"url" help:"telemetry database (projections, read only)"`
	NATSURL string `env:"NATS_URL" required:"true" secret:"true" kind:"url" help:"NATS JetStream"`
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
	return errors.Join(errs...)
}
