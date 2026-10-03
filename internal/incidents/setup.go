package incidents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// signatureMaxAge is how old a pack's signature may be and still verify:
// a pack is kept indefinitely (05 §4), so its seal never expires.
const signatureMaxAge = 100 * 365 * 24 * time.Hour

// Setup is what api hands to Assemble.
type Setup struct {
	DB     *pg.DB
	Audit  *audit.Writer
	Config config.Incidents
	// The telemetry database, read as the reader role.
	TSURL            string
	TSRole           string
	TSMaxConns       int
	StatementTimeout time.Duration
	PIIKeyID         string
	PIIKeyFile       string
	// PublicationRing signs the seal statements; nil: packs are unsigned
	// (said at start, in each manifest's row and counted).
	PublicationRing *coreauth.KeyRing
	// TokenURL is this system's /oauth/token, for the records client.
	TokenURL string
	// Registry resolves a legal pack's personal data; nil: unavailable.
	Registry *registry.Service
	// Pattern is the active policy's registration-number pattern.
	Pattern func() (string, bool)
	Logger  *slog.Logger
	Limiter *logging.Limiter
}

// Parts are the assembled component.
type Parts struct {
	Service  *Service
	Packs    *Packs
	Handler  Handler
	Counters *core.Counters
	// RecordTokens counts the records client's token requests; nil
	// without a client.
	RecordTokens *core.Counters
	reader       *ts.Reader
	backfill     func(ctx context.Context)
}

// PublicPartOf returns the public part of a registration under the
// pattern pattern returns (uspace-core regnum, G-07); without a policy
// yet, regnum's default pattern.
func PublicPartOf(pattern func() (string, bool)) PublicPartFunc {
	return func(reg string) string {
		p := ""
		if pattern != nil {
			if cur, ok := pattern(); ok {
				p = cur
			}
		}
		v, err := regnum.NewValidator(p)
		if err != nil {
			return regnum.PublicPart(reg)
		}
		return v.PublicPart(reg)
	}
}

// Assemble builds the case files, the evidence packs and the handler.
// What is missing is said at start; the control plane still starts.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	c := s.Config
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	counters := &core.Counters{}
	public := PublicPartOf(s.Pattern)
	svc := &Service{DB: s.DB, Audit: s.Audit, PublicPart: public, WriteTimeout: time.Duration(c.IncidentsWriteTimeoutS) * time.Second,
		Counters: counters, Logger: logger}
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: s.TSURL, Role: s.TSRole, MaxConns: s.TSMaxConns,
		StatementTimeout: s.StatementTimeout, ApplicationName: "uspace-authority-api-evidence"})
	if err != nil {
		return nil, err
	}
	sealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
	if err != nil {
		rd.Close()
		return nil, err
	}
	records := &Records{HTTP: &http.Client{Timeout: time.Duration(c.RecordsTimeoutMS) * time.Millisecond},
		Timeout: time.Duration(c.RecordsTimeoutMS) * time.Millisecond, MaxBytes: int64(c.RecordsMaxBytes)}
	p := &Parts{Service: svc, Counters: counters, reader: rd}
	if c.RecordsClientSecretFile != "" {
		tc, err := recordsClient(s.TokenURL, c)
		if err != nil {
			rd.Close()
			return nil, err
		}
		records.Tokens = tc
		p.RecordTokens = tc.Counters()
	} else {
		logger.Warn("USSP service records are unavailable in evidence packs until a client secret is configured",
			slog.String("variable", "RECORDS_CLIENT_SECRET_FILE"))
	}
	var personal PersonalData
	if s.Registry != nil {
		personal = RegistryPersonalData{Registry: s.Registry}
	}
	builder := &Builder{Sources: s.DB.Queries(), Telemetry: rd.Q, Records: records, Personal: personal,
		MaxRows: c.IncidentsPackMaxRows, MaxRecords: c.RecordsMaxPerPack, MaxZones: c.IncidentsPackMaxZones, PublicPart: public,
		MannedMarginM: float64(c.IncidentsMannedMarginM), RecordsConcurrency: c.RecordsConcurrency,
		RecordsTimeout: time.Duration(c.RecordsStepTimeoutS) * time.Second}
	packs := NewPacks(&Packs{Service: svc, Builder: builder, Sealer: sealer, MaxWindow: time.Duration(c.IncidentsPackMaxWindowS) * time.Second,
		MaxBytes: int64(c.IncidentsPackMaxBytes), BuildTimeout: time.Duration(c.IncidentsBuildTimeoutS) * time.Second,
		Counters: counters, Logger: logger}, c.IncidentsPackConcurrency)
	if c.EvidenceDir != "" {
		if err := os.MkdirAll(c.EvidenceDir, 0o700); err != nil {
			rd.Close()
			return nil, fmt.Errorf("EVIDENCE_DIR: %w", err)
		}
		packs.Storage = Dir{Root: c.EvidenceDir}
	} else {
		logger.Error("evidence packs are refused (503 evidence_storage_unavailable) until EVIDENCE_DIR is configured",
			slog.String("variable", "EVIDENCE_DIR"))
	}
	if s.PublicationRing != nil {
		v, err := coreauth.NewDetachedVerifier(ctx, coreauth.DetachedConfig{
			Publishers: map[string]coreauth.IssuerConfig{PublisherAuthority: {Keys: s.PublicationRing.JWKS()}}, MaxAge: signatureMaxAge,
		})
		if err != nil {
			rd.Close()
			return nil, err
		}
		packs.Signer, packs.Verifier = s.PublicationRing, v
	} else {
		logger.Warn("evidence packs are sealed by their hash only, unsigned, until a publication key is configured",
			slog.String("variable", "PUBLICATION_KEY_FILE"))
	}
	p.Packs = packs
	p.Handler = Handler{Service: svc, Packs: packs}
	kid := ""
	if s.PublicationRing != nil {
		kid = s.PublicationRing.ActiveKID()
	}
	logger.Info("evidence packs ready", slog.Bool("storage", packs.Storage != nil), slog.String("signing_kid", kid),
		slog.Bool("records_client", records.Tokens != nil), slog.Int("max_window_s", c.IncidentsPackMaxWindowS),
		slog.Int("max_rows", c.IncidentsPackMaxRows), slog.Int("concurrency", c.IncidentsPackConcurrency))
	p.backfill = func(ctx context.Context) {
		svc.RunBackfill(ctx, time.Duration(c.IncidentsBackfillS)*time.Second, c.IncidentsBackfillBatch, s.Limiter)
	}
	return p, nil
}

// Run runs the backfill job until ctx ends.
func (p *Parts) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { p.backfill(ctx) })
	wg.Wait()
}

// Close closes the telemetry pool.
func (p *Parts) Close() { p.reader.Close() }

// RegistryPersonalData resolves an operator's personal data from the
// registry by its registration's public part; the registry records the
// read (registry_pii_viewed) with the purpose before opening anything.
type RegistryPersonalData struct {
	Registry *registry.Service
}

// Operator implements PersonalData.
func (r RegistryPersonalData) Operator(ctx context.Context, registration, purpose string, actor audit.Actor) (map[string]string, error) {
	ops, err := r.Registry.ListOperators(ctx, registration, "", registry.Page{Limit: 2})
	if err != nil {
		return nil, err
	}
	switch len(ops) {
	case 0:
		return nil, errors.New("no operator of the registry has this registration")
	case 1:
	default:
		return nil, errors.New("more than one operator of the registry compares equal to this registration")
	}
	pii, err := r.Registry.OperatorPersonalData(ctx, ops[0].ID, purpose, actor)
	if err != nil {
		return nil, err
	}
	out := map[string]string{"operator_id": ops[0].ID, "operator_type": ops[0].OperatorType, "status": string(ops[0].Status)}
	for k, v := range map[string]string{"full_name": pii.FullName, "legal_name": pii.LegalName, "date_of_birth": pii.DateOfBirth,
		"legal_identification_number": pii.LegalIdentificationNumber, "postal_address": pii.PostalAddress,
		"contact_email": pii.ContactEmail, "contact_phone": pii.ContactPhone, "insurance_policy_number": pii.InsurancePolicyNumber} {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out, nil
}

func recordsClient(tokenURL string, c config.Incidents) (*tokens.Client, error) {
	raw, err := os.ReadFile(c.RecordsClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("RECORDS_CLIENT_SECRET_FILE: cannot be read: %w", err)
	}
	return tokens.NewClient(tokens.ClientConfig{TokenURL: tokenURL, ClientID: c.RecordsClientID, ClientSecret: strings.TrimSpace(string(raw))})
}
