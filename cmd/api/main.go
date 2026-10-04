// Command api is the control plane: the national API, the registry,
// zones, certificates, the token service and the jobs. It is started as
// `uspace-authority api`; --help lists the configuration variables.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/authz"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/cell/assign"
	"github.com/rootxkit/uspace-authority/internal/certs"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dpadmin"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/occurrences"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/police"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/regimport"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/regportal"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/sources/switches"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/violations"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.API{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

// spec is the production process: identities come from bearer tokens
// verified by the authz wiring (sessions of this issuer, machine tokens
// of the allow-listed issuers).
func spec(cfg *config.API) proc.Spec { return specWith(cfg, nil) }

// specWith is spec with identify replacing the bearer-token identity
// when not nil (tests).
func specWith(cfg *config.API, identify apiserver.IdentifyFunc) proc.Spec {
	return proc.Spec{Name: "api", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		if cfg.MTLSMode == "off" {
			rt.Logger.Error("mTLS is off on machine routes; allowed only in the lab and on staging",
				slog.String("variable", "AUTHORITY_MTLS_MODE"))
		}
		db, err := pg.Open(ctx, store.PoolOptions{
			URL:              cfg.PGURL,
			MaxConns:         cfg.PGMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second,
			ApplicationName:  "uspace-authority-api",
			Role:             cfg.PGRole,
		})
		if err != nil {
			return err
		}
		defer db.Close()
		rt.Ready.Add("relational", db.Ping)

		// api follows the policy it serves: its own activations reach the
		// follower at once, and the re-read repairs anything missed.
		follower := policy.NewFollower(nil)
		counters := follower.Counters()
		rt.AddCounters("policy", counters)
		rt.AddStatus(follower.StatusAttrs)
		auditWriter := audit.NewWriter(db)
		svc := &policy.Service{DB: db, Audit: auditWriter, Publisher: follower, Logger: rt.Logger, Counters: counters}
		// The background loops end with the body: an early error return
		// cancels them before waiting, so a failed start cannot hang the
		// process on its own wait group.
		ctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		defer wg.Wait()
		defer cancel()
		wg.Go(func() {
			follower.Run(ctx, svc.Active, time.Duration(cfg.PolicyRefreshS)*time.Second, rt.Logger)
		})

		// The bus: api provisions every stream and bucket (bus.Ensure)
		// and starts degraded when NATS is down (B-08), provisioning once
		// it is back.
		bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "api", cfg.RIDKeysetBucket, rt.Logger)
		if err != nil {
			return err
		}
		// The connection closes after the loops that use it have stopped.
		defer func() { cancel(); wg.Wait(); bp.Close() }()
		// Not a readiness check: api serves its control plane with NATS
		// down (05 §6) and refuses only what needs the bus, with 503. The
		// status line says how the connection is.
		rt.AddStatus(bus.StatusAttrs(bp.NC))
		wg.Go(func() {
			bus.EnsureUntilDone(ctx, bp.JS, bp.Topology, time.Duration(cfg.NATSTimeoutMS)*time.Millisecond, rt.Logger, rt.Limiter)
		})
		// The active policy on the bus (KV policy, ctl.policy; plan §6):
		// written at activation and repaired every POLICY_REFRESH_S, so
		// detect judges with the policy api serves (INV-03, WP-12).
		policyKV := policy.KVOf(bp, time.Duration(cfg.NATSTimeoutMS)*time.Millisecond, "authority/api", counters)
		svc.Publisher = policy.Publishers{follower, policyKV}
		wg.Go(func() { policyKV.RunRepair(ctx, follower, time.Duration(cfg.PolicyRefreshS)*time.Second, rt.Limiter) })

		hasher, err := passhash.New(passhash.Params{
			MemoryKiB: uint32(cfg.Argon2MemoryKiB), Time: uint32(cfg.Argon2Time), Threads: uint8(cfg.Argon2Threads),
		})
		if err != nil {
			return err
		}
		tok, err := tokens.Assemble(ctx, tokens.Setup{
			Issuer: cfg.Issuer(), SigningKeyFiles: cfg.SigningKeyFiles, PublicationKeyFile: cfg.PublicationKeyFile,
			TTL: time.Duration(cfg.TokenTTLS) * time.Second, RetireGrace: time.Duration(cfg.KeyRetireGraceS) * time.Second,
			TwoPerson: cfg.KeyRotationTwoPerson, ConfirmWindow: time.Duration(cfg.KeyRotationConfirmS) * time.Second,
			RatePerMin: cfg.TokenRatePerMin, RateBurst: cfg.TokenRateBurst, RateMaxClients: cfg.TokenRateMaxClients,
			Store: tokens.PG{DB: db, Audit: auditWriter}, Hasher: hasher, Logger: rt.Logger,
		})
		if err != nil {
			return err
		}
		rt.AddCounters("tokens", tok.Counters)
		rt.AddStatus(tok.StatusAttrs)
		rt.Logger.Info("token service ready", slog.String("issuer", cfg.Issuer()), slog.String("signing_kid", tok.Keys.ActiveKID()))

		az, err := authz.Assemble(ctx, authz.Setup{
			Store: authz.PG{DB: db, Audit: auditWriter}, Hasher: hasher, Keys: tok.Keys,
			PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile, Audiences: cfg.AudienceList(), Peers: cfg.List(),
			Config: authz.Config{
				OwnHost: cfg.OwnHost(), SessionTTL: time.Duration(cfg.SessionTTLS) * time.Second,
				IdleTimeout: time.Duration(cfg.SessionIdleS) * time.Second, MaxSessions: cfg.SessionMaxPerUser,
				ChallengeTTL: time.Duration(cfg.MFAChallengeTTLS) * time.Second, MaxAttempts: cfg.MFAMaxAttempts,
				PasswordMinLen: cfg.PasswordMinLength, TOTPIssuer: cfg.TOTPIssuer,
				LockoutAfter: cfg.MFALockoutAfter, LockoutBase: time.Duration(cfg.MFALockoutBaseS) * time.Second,
				LockoutMax: time.Duration(cfg.MFALockoutMaxS) * time.Second, HardLockAfter: cfg.MFAHardLockAfter,
			},
			IPPerMin: cfg.LoginIPPerMin, IPBurst: cfg.LoginIPBurst, UserPerMin: cfg.LoginUserPerMin, UserBurst: cfg.LoginUserBurst,
			MaxRateKeys: cfg.LoginRateMaxKeys, Logger: rt.Logger,
		})
		if err != nil {
			return err
		}
		rt.AddCounters("authz", az.Counters)
		rt.AddCounters("verifier", az.Verifier.Counters())
		rt.AddStatus(az.Verifier.StatusAttrs)
		tok.Manager.OnChange = az.OnKeysChanged(rt.Logger)
		if _, err := az.Service.Bootstrap(ctx, cfg.BootstrapAdmin, cfg.BootstrapPassword); err != nil {
			return err
		}
		if identify == nil {
			identify = az.Authenticator.Identify
		}
		wg.Go(func() { tok.Manager.Run(ctx, time.Duration(cfg.KeyRefreshS)*time.Second) })
		wg.Go(func() { az.Run(ctx, time.Duration(cfg.SessionSweepS)*time.Second) })

		bands, err := cfg.MTOMBounds()
		if err != nil {
			return err
		}
		reg, err := registry.Assemble(ctx, registry.Setup{
			DB: db, Audit: auditWriter, PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile, HashKeyFile: cfg.RegistryHashKeyFile,
			TSURL: cfg.TSURL, TSRole: cfg.TSProjectorRole, TSMaxConns: cfg.TSMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second, MTOMBandsG: bands, Logger: rt.Logger,
			// The registration-number format of the policy api follows (G-07).
			Pattern: func() (string, bool) {
				p, ok := follower.Current()
				return p.RegistrationNumberPattern, ok
			},
		})
		if err != nil {
			return err
		}
		// The pool closes after the jobs that use it have stopped.
		defer func() { cancel(); wg.Wait(); reg.Close() }()
		rt.Ready.Add("telemetry", reg.Projector.Ping)
		rt.AddCounters("registry", reg.Counters)
		wg.Go(func() {
			reg.Service.RunJobs(ctx, time.Duration(cfg.ReprojectS)*time.Second, time.Duration(cfg.ExpiryS)*time.Second,
				time.Duration(cfg.RepairRetryS)*time.Second)
		})

		// The CISP client (WP-6): the signed publication outbox and its
		// sender, the publisher heartbeat, the subscriber with its
		// reconciliation, and the notification receiver.
		cis, err := assembleCISP(ctx, cfg, rt, tok, db, auditWriter, reg, bp, follower)
		if err != nil {
			return err
		}
		rt.AddCounters("cisp", cis.Counters)
		rt.AddStatus(cis.StatusAttrs)
		wg.Go(func() { cis.Run(ctx) })

		// Zones and U-space airspaces (WP-5): the projection shares the
		// registry's projector pool; publications are announced on the bus
		// and queued, validated and signed, in WP-6's outbox.
		zs, err := zonesvc.Assemble(zonesvc.Setup{
			DB: db, Audit: auditWriter, Projector: reg.Projector, Logger: rt.Logger,
			Publisher: zonesvc.NewBusPublisher(bp, time.Duration(cfg.NATSTimeoutMS)*time.Millisecond),
			Meta:      zonesvc.Meta{ProviderName: cfg.ZonesProviderName, ProviderLang: cfg.ZonesProviderLang},
			Outbox:    cis.Outbox,
		})
		if err != nil {
			return err
		}
		rt.AddCounters("zones", zs.Counters)
		rt.Logger.Warn("daylight events cannot be resolved until the ground package is wired (WP-11): zones scheduled by BMCT, SR, SS or EECT answer unknown")
		wg.Go(func() {
			zs.Service.RunJobs(ctx, time.Duration(cfg.ZonesReprojectS)*time.Second, time.Duration(cfg.ZonesRepairRetryS)*time.Second)
		})

		rx, err := receivers.Assemble(ctx, receivers.Setup{
			DB: db, Audit: auditWriter, Hasher: hasher, PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile,
			JS: bp.JS, Limits: bp.Limits, KVTimeout: time.Duration(cfg.RIDKVTimeoutMS) * time.Millisecond,
			TSURL: cfg.TSURL, TSRole: cfg.TSReaderRole, TSMaxConns: cfg.TSMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second,
			Defaults: receivers.Defaults{
				BatchIntervalMS: cfg.RIDDefaultBatchIntervalMS, BacklogCap: cfg.RIDDefaultBacklogCap,
				HeartbeatIntervalS: cfg.RIDDefaultHeartbeatIntervalS, PositionToleranceM: cfg.RIDDefaultPositionToleranceM,
			},
			RotationGrace:   time.Duration(cfg.RIDKeyRotationGraceS) * time.Second,
			FramesMaxWindow: time.Duration(cfg.RIDFramesMaxWindowS) * time.Second,
			Logger:          rt.Logger, Limiter: rt.Limiter,
		})
		if err != nil {
			return err
		}
		defer func() { cancel(); wg.Wait(); rx.Close() }()
		rt.AddCounters("rid_receivers", rx.Counters)
		rt.AddCounters("rid_receiver_keys", rx.KeyringCounters)
		wg.Go(func() {
			rx.Service.RunReprojection(ctx, time.Duration(cfg.RIDKeysetReprojectS)*time.Second, rt.Limiter)
		})

		cells := assign.New(db, auditWriter, cell.StoreOf(bp), rt.Logger)

		// Source control (U-15): api writes the switches, republishes
		// them from the database, keeps every adapter's last status, and
		// follows the published state like every process.
		sw := switches.NewService(db, auditWriter, bp, cfg.Bus, cfg.Sources, rt.Logger, rt.Limiter)
		rt.AddCounters("source_switches", sw.Counters)
		statuses := sources.NewStatusStore(cfg.SourceStatusMax)
		rt.AddCounters("source_status", statuses.Counters)
		_, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)
		wg.Go(func() { followSources(ctx) })
		wg.Go(func() { sw.RunRepublish(ctx, time.Duration(cfg.SourceControlRepublishS)*time.Second) })
		wg.Go(func() { statuses.Run(ctx, bp.NC, rt.Logger) })
		rt.AddCounters("cells", cells.Counters)

		// Violations (WP-12): alrt.v1 persisted, each transition audited;
		// what detect stopped republishing closed detector_silent.
		vio := violations.Assemble(violations.Setup{
			DB: db, Audit: auditWriter, BP: bp, Config: cfg.Violations,
			NATSTimeout: time.Duration(cfg.NATSTimeoutMS) * time.Millisecond, Logger: rt.Logger, Limiter: rt.Limiter,
		})
		rt.AddCounters("violations", vio.Counters)

		// Incidents and evidence packs (WP-17): an escalation opens its
		// incident in the review's transaction; packs are read from both
		// databases (the telemetry one as the reader role), sealed by
		// their hash and the publication key, and stored under
		// EVIDENCE_DIR.
		pubRing, err := tok.Keys.PublicationRing()
		if err != nil {
			return err
		}
		inc, err := incidents.Assemble(ctx, incidents.Setup{
			DB: db, Audit: auditWriter, Config: cfg.Incidents, TSURL: cfg.TSURL, TSRole: cfg.TSReaderRole, TSMaxConns: cfg.TSMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second, PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile,
			PublicationRing: pubRing, TokenURL: cfg.Issuer() + "/oauth/token", Registry: reg.Service,
			Pattern: func() (string, bool) {
				p, ok := follower.Current()
				return p.RegistrationNumberPattern, ok
			},
			Logger: rt.Logger, Limiter: rt.Limiter,
		})
		if err != nil {
			return err
		}
		defer func() { cancel(); wg.Wait(); inc.Close() }()
		rt.AddCounters("incidents", inc.Counters)
		if inc.RecordTokens != nil {
			rt.AddCounters("records_token_client", inc.RecordTokens)
		}
		vio.Service.OnEscalate = inc.Service.OpenFromViolation
		wg.Go(func() { vio.Run(ctx) })
		wg.Go(func() { inc.Run(ctx) })

		// Occurrence reports (WP-18, 376/2014): their own schema, worked
		// by their own role through a pool of their own; never joined to
		// violations or incidents. The audit writer records on that
		// pool's transactions.
		occ, err := occurrences.Assemble(ctx, occurrences.Setup{
			PGURL: cfg.PGURL, StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second, Audit: auditWriter,
			Config: cfg.Occurrences, PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile,
			Pattern: func() (string, bool) {
				p, ok := follower.Current()
				return p.RegistrationNumberPattern, ok
			},
			Logger: rt.Logger, Limiter: rt.Limiter,
		})
		if err != nil {
			return err
		}
		defer occ.Close()
		rt.Ready.Add("occurrences", occ.Ping)
		rt.AddCounters("occurrences", occ.Counters)

		// The police realm (WP-19): purpose-logged queries of the picture
		// (the telemetry database as the reader role) and of the registry,
		// legal exports through WP-17's packs, the DPO report.
		pol, err := police.Assemble(ctx, police.Setup{
			DB: db, Audit: auditWriter, Config: cfg.Police, Accounts: authz.PG{DB: db, Audit: auditWriter}, Registry: reg.Service,
			Incidents: inc.Service, Packs: inc.Packs, TSURL: cfg.TSURL, TSRole: cfg.TSReaderRole, TSMaxConns: cfg.TSMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second,
			Pattern: func() (string, bool) {
				p, ok := follower.Current()
				return p.RegistrationNumberPattern, ok
			},
			Logger: rt.Logger,
		})
		if err != nil {
			return err
		}
		defer pol.Close()
		rt.AddCounters("police", pol.Counters)

		// The uas.gov.ge import, the public check and the registration
		// portal (WP-20): the rules file checks at start or api does not
		// start; the re-import runs only from the agreed URL (G-11).
		imp, err := regimport.Assemble(regimport.Setup{
			DB: db, Registry: reg.Service, RulesFile: cfg.RegistryImportRulesFile, URL: cfg.RegistryImportURL,
			TokenFile: cfg.RegistryImportTokenFile, Timeout: time.Duration(cfg.RegistryImportTimeoutS) * time.Second,
			MaxBytes: cfg.RegistryImportMaxBytes, MaxRecords: cfg.RegistryImportMaxRows,
			WriteTimeout: time.Duration(cfg.RegistryImportWriteS) * time.Second, Logger: rt.Logger, Limiter: rt.Limiter,
		})
		if err != nil {
			return err
		}
		rt.AddCounters("registry_import", imp.Counters)
		if imp.Job != nil {
			wg.Go(func() { imp.Job.Run(ctx, time.Duration(cfg.RegistryImportEveryS)*time.Second) })
		}
		portal, err := regportal.Assemble(regportal.Setup{
			DB: db, Audit: auditWriter, Registry: reg.Service, Occurrences: occ.Service, PublicPart: occ.Service.PublicPart,
			PIIKeyID: cfg.PIIKeyID, PIIKeyFile: cfg.PIIKeyFile, HashKeyFile: cfg.RegistryHashKeyFile, PortalKey: cfg.RegistryPortalKeyFile,
			Config: portalConfig(cfg), SMTP: regportal.SMTP{
				Addr: cfg.RegistryMailSMTPAddr, From: cfg.RegistryMailFrom, User: cfg.RegistryMailUser, TLS: cfg.RegistryMailTLS,
				Timeout: time.Duration(cfg.RegistryMailTimeoutS) * time.Second,
			},
			MailPasswordFile: cfg.RegistryMailPasswordFile, CheckPerMin: cfg.RegistryCheckPerMin, CheckBurst: cfg.RegistryCheckBurst,
			CheckMaxIPs: cfg.RegistryCheckMaxIPs, Logger: rt.Logger, Limiter: rt.Limiter,
		})
		if err != nil {
			return err
		}
		rt.AddCounters("registry_portal", portal.Counters)
		if cfg.PortalOn() {
			wg.Go(func() {
				portal.Service.Run(ctx, time.Duration(cfg.RegistryMailEveryS)*time.Second, time.Duration(cfg.RegistryPortalPurgeEveryS)*time.Second)
			})
		}
		rt.Logger.Info("registry portal", slog.String("applications", cfg.RegistryApplications),
			slog.String("operator_reports", cfg.RegistryOperatorReports), slog.Bool("import_rules", imp.Service.Rules != nil),
			slog.Bool("reimport", imp.Job != nil))

		// The Display Provider's administration (WP-14).
		dpa, err := dpadmin.Assemble(cfg, rt, db, auditWriter, bp)
		if err != nil {
			return err
		}
		wg.Go(func() { dpa.Providers.Run(ctx, bp.NC, rt.Logger) })
		wg.Go(func() { dpa.RunRepublish(ctx, time.Duration(cfg.DPViewsRepublishS)*time.Second) })

		// Certificates (WP-16): issued with their clients, the operating
		// status, the lapse job, the USSP list through WP-6's outbox and
		// the certified USSPs in KV for dp-poller.
		cispHost := ""
		if cfg.CISPBaseURL != "" {
			if cispHost, err = tokens.AudienceOf(cfg.CISPBaseURL); err != nil {
				return err
			}
		}
		crt := certs.Assemble(certs.Setup{
			DB: db, Audit: auditWriter, Clients: tok.Registry, Outbox: cis.Outbox, JS: bp.JS, Bucket: cfg.CertificatesBucket,
			KVTimeout: time.Duration(cfg.NATSTimeoutMS) * time.Millisecond, Policy: follower.Current, Issuer: cfg.Issuer(),
			OwnHost: cfg.OwnHost(), CISPHost: cispHost, TokenTTL: time.Duration(cfg.TokenTTLS) * time.Second,
			RegisterPerMin: cfg.CertificatesRegisterPerMin, RegisterBurst: cfg.CertificatesRegisterBurst,
			RegisterMaxIPs: cfg.CertificatesRegisterMaxIPs, Logger: rt.Logger, Limiter: rt.Limiter,
		})
		rt.AddCounters("certificates", crt.Counters)
		wg.Go(func() {
			crt.Service.RunJobs(ctx, time.Duration(cfg.CertificatesLapseEveryS)*time.Second, time.Duration(cfg.CertificatesRepairS)*time.Second)
		})

		mux := http.NewServeMux()
		apiserver.Mount(mux, apiserver.Server{
			PolicyHandler:         policy.Handler{Service: svc},
			AuditHandler:          audit.Handler{Writer: auditWriter},
			TokenHandler:          tok.Handler,
			OAuthAdminHandler:     tok.Handler,
			AuthHandler:           az.Handler,
			UsersHandler:          az.Handler,
			RegistryHandler:       reg.Handler,
			RegistryImportHandler: regimport.Handler{Service: imp.Service},
			RegistryPortalHandler: portal.Handler,
			RIDReceiversHandler:   rx.Handler,
			CellsHandler:          assign.Handler{Service: cells},
			SourcesHandler: switches.Handler{
				Service: sw, Status: statuses, StaleAfter: time.Duration(cfg.SourceStatusStaleS) * time.Second,
			},
			ZonesHandler:       zs.Handler,
			USpaceHandler:      zs.Handler,
			CISPHandler:        cis.Handler,
			ViolationsHandler:  vio.Handler,
			IncidentsHandler:   inc.Handler,
			OccurrencesHandler: occ.Handler,
			DPHandler:          dpa,

			CertificatesHandler: crt.Handler,
			PoliceHandler:       pol.Handler,
			DPOHandler:          pol.Handler,
		}, apiserver.Options{
			Logger:      rt.Logger,
			Middlewares: []apiserver.Middleware{tok.Handler.FormGuard(), apiserver.Authorize(identify, apiserver.DefaultRules())},
			Keep:        apiserver.PathPrefix("/v1/", "/oauth/", "/.well-known/"),
			// A zone file may be as large as uspace-core's parsers accept.
			BodyLimits: map[string]int64{
				"POST /v1/zones/import":                 int64(zonesvc.MaxDocumentBytes),
				"POST /v1/zones/import/airspace-gov-ge": int64(zonesvc.MaxDocumentBytes) * 2,
				// An occurrence report is bounded below the default (E-10).
				"POST /v1/occurrences":          occurrences.MaxIntakeBytes,
				"POST /v1/occurrences/operator": occurrences.MaxIntakeBytes,
				// An export file as large as REGISTRY_IMPORT_MAX_BYTES (WP-20).
				"POST /v1/registry/import": int64(cfg.RegistryImportMaxBytes),
			},
			BodyCounters: zs.Counters,
		})
		// The receivers' own config and heartbeat (x-receiver): bearer key
		// and body HMAC, outside the generated server.
		rx.Receiver.Mount(mux)
		// The CIS change notifications (x-cis-delivery): the compact JWS
		// of the body is the credential, outside the generated server.
		cis.Receiver.Mount(mux)
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, mux)
	}}
}
