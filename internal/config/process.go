package config

import (
	"errors"
	"net/url"
	"slices"
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
	PGPool
	PolicyRefreshS int `env:"POLICY_REFRESH_S" default:"60" min:"1" max:"3600" help:"seconds between re-reads of the active policy by its followers (the push is repaired by the re-read, G-08)"`
	Tokens
	Argon2
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
	AssertionReplayMax   int      `env:"ASSERTION_REPLAY_MAX" default:"100000" min:"10" help:"private_key_jwt assertion ids remembered until they expire; a full memory refuses new assertions"`
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
	if own := c.OwnHost(); own != "" && len(c.Audiences) > 0 && !slices.Contains(c.Audiences, own) {
		errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "must contain this system's own host %q (the host of AUTHORITY_PUBLIC_URL)", own))
	}
	for _, a := range c.Audiences {
		if strings.ContainsAny(a, "/:@ ") || a != strings.ToLower(a) {
			errs = append(errs, core.Fieldf("AUTHORITY_AUDIENCES", "%q is not a lower-case host name", a))
		}
	}
	if u, err := url.Parse(c.Issuer()); err == nil && (u.RawQuery != "" || u.Fragment != "") {
		errs = append(errs, core.Fieldf("ISSUER_URL", "must have no query or fragment"))
	}
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
