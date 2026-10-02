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
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/tokens"
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
			reg.Service.RunJobs(ctx, time.Duration(cfg.ReprojectS)*time.Second, time.Duration(cfg.ExpiryS)*time.Second)
		})

		mux := http.NewServeMux()
		apiserver.Mount(mux, apiserver.Server{
			PolicyHandler:     policy.Handler{Service: svc},
			AuditHandler:      audit.Handler{Writer: auditWriter},
			TokenHandler:      tok.Handler,
			OAuthAdminHandler: tok.Handler,
			AuthHandler:       az.Handler,
			UsersHandler:      az.Handler,
			RegistryHandler:   reg.Handler,
		}, apiserver.Options{
			Logger:      rt.Logger,
			Middlewares: []apiserver.Middleware{tok.Handler.FormGuard(), apiserver.Authorize(identify, apiserver.DefaultRules())},
			Keep:        apiserver.PathPrefix("/v1/", "/oauth/", "/.well-known/"),
		})
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, mux)
	}}
}
