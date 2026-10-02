module github.com/rootxkit/uspace-authority

go 1.27

// Direct dependencies, each listed in docs/PLAN.md §13:
//   uspace-core   every judgement (identification, zones, auth, geodesy)
//   oapi-codegen/runtime  parameter binding of the generated server (api/gen)
//   pgx/v5        PostgreSQL driver (database/sql for goose; pgxpool from WP-1)
//   goose/v3      the two embedded migration trees and the migrate subcommand
//   client_golang Prometheus registry and /metrics
//   otel, sdk,    OpenTelemetry tracing with the OTLP/HTTP exporter
//   otlptracehttp
//   jwx/v3        the token service's JWK handling and session signing
//                 (internal/tokens only; already core's dependency)
//   x/crypto      argon2id for passwords and client secrets (internal/passhash)
//   pquerna/otp   TOTP (RFC 6238) enrolment and codes of console MFA (internal/authz)
//   nats.go       JetStream streams, KV buckets and subjects (internal/bus,
//                 WP-10; first used by the Remote ID receivers, WP-7)
//   jsonschema/v6 the CISP's pinned JSON Schemas, checked before a
//                 publication is signed (internal/cisp, WP-6)
require (
	github.com/jackc/pgx/v5 v5.11.0
	github.com/lestrrat-go/jwx/v3 v3.3.0
	github.com/nats-io/nats.go v1.54.0
	github.com/oapi-codegen/runtime v1.7.0
	github.com/pquerna/otp v1.5.0
	github.com/pressly/goose/v3 v3.28.0
	github.com/prometheus/client_golang v1.24.1
	github.com/rootxkit/uspace-core v1.3.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.46.0
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/trace v1.46.0
	golang.org/x/crypto v0.57.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
