package police

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/authz"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/registry"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Counters of the police realm (the status line and /metrics, E-09).
const (
	CounterQueries         = "police_queries"
	CounterRefusedBudget   = "police_queries_refused_budget"
	CounterRefusedAddress  = "police_queries_refused_address"
	CounterRefusedAgency   = "police_downloads_refused_agency"
	CounterRefusalNotSaved = "police_refusal_event_failed"
	CounterPIIReleased     = "police_pii_released"
	CounterPIIUnresolved   = "police_pii_unresolved"
	CounterExports         = "police_exports"
	CounterExportNotLinked = "police_export_not_linked"
	CounterDownloads       = "police_downloads"
	CounterDPOReports      = "dpo_reports"
)

// Problem slugs of the police realm.
const (
	SlugAddressNotAllowed = "address_not_allowed"
	SlugPurposeNotPII     = "purpose_not_pii"
	SlugNothingToExport   = "nothing_to_export"
	SlugTooManyAircraft   = "too_many_aircraft"
	SlugAmbiguous         = "ambiguous"
)

// Accounts reads an account (authz.PG).
type Accounts interface {
	UserByID(ctx context.Context, id string) (authz.User, error)
}

// Registry is what the police realm reads of the registry (WP-3). Every
// personal-data read goes through OperatorPersonalData, which records
// registry_pii_viewed with the purpose before it opens anything.
type Registry interface {
	OperatorByNumber(ctx context.Context, number string) (registry.Operator, bool, error)
	UASBySerial(ctx context.Context, sn string) (registry.UAS, bool, error)
	GetOperator(ctx context.Context, id string) (registry.Operator, error)
	GetUAS(ctx context.Context, id string) (registry.UAS, error)
	ListUAS(ctx context.Context, sn, operatorID string, st registry.Status, page registry.Page) ([]registry.UAS, error)
	OperatorPersonalData(ctx context.Context, id, purpose string, actor audit.Actor) (registry.OperatorPII, error)
}

// Telemetry is what the police realm reads of the picture (the reader
// role of the telemetry database).
type Telemetry interface {
	PoliceClock(ctx context.Context, horizonS float64) (reader.PoliceClockRow, error)
	PoliceAircraft(ctx context.Context, arg reader.PoliceAircraftParams) ([]reader.PoliceAircraftRow, error)
	PolicePositions(ctx context.Context, arg reader.PolicePositionsParams) ([]reader.PolicePositionsRow, error)
	PoliceWriterGaps(ctx context.Context, arg reader.PoliceWriterGapsParams) (reader.PoliceWriterGapsRow, error)
}

// Incidents opens and reads the case files a legal export is built for
// (WP-17).
type Incidents interface {
	Get(ctx context.Context, id string) (incidents.View, error)
	OpenForPolice(ctx context.Context, actor audit.Actor, r incidents.PoliceRequest) (incidents.View, error)
}

// Packs builds and serves legal evidence packs (WP-17's builder).
type Packs interface {
	Create(ctx context.Context, actor audit.Actor, piiRole bool, incidentID string, r incidents.PackRequest) (pggen.EvidencePack, error)
	Download(ctx context.Context, actor audit.Actor, piiRole bool, incidentID, packID, purpose string) ([]byte, pggen.EvidencePack, error)
}

// Entry is one police_queries row to record.
type Entry struct {
	ID          string
	Kind        string
	Purpose     string
	CaseRef     string
	Query       map[string]any
	ResultCount int
	PII         bool
	Caller      Caller
}

// Budget is the per-user and per-agency limit of queries in a window.
type Budget struct {
	User, Agency int
	Window       time.Duration
}

// BudgetSpentError is a query refused because a budget is spent; it is
// answered 429 with Retry-After.
type BudgetSpentError struct {
	Scope      string // "user" or "agency"
	RetryAfter time.Duration
}

func (e *BudgetSpentError) Error() string {
	return "the " + e.Scope + "'s police query budget is spent; retry after " + e.RetryAfter.Round(time.Second).String()
}

// Export links a legal pack to the agency it was built for.
type Export struct {
	PackID, IncidentID, QueryID, Agency, UserID string
	CreatedAt                                   time.Time
}

// Ledger is the police realm's record in the relational database
// (PG): every query under the budgets, the exports, and the DPO
// report's reads.
type Ledger interface {
	// Record checks the budgets of e's user and agency on the database
	// clock under the agency's lock and, when neither is spent, writes
	// the police_queries row and its police_query events row in one
	// transaction. A spent budget is a *BudgetSpentError, nothing
	// written.
	Record(ctx context.Context, e Entry, b Budget) (time.Time, error)
	// Refused records a police_query_refused events row on its own.
	Refused(ctx context.Context, actor audit.Actor, reason string, payload map[string]any) error
	InsertExport(ctx context.Context, x Export) error
	ExportByPack(ctx context.Context, packID string) (Export, bool, error)
	DPO(ctx context.Context, from, to time.Time, rows int, piiTypes []string, actor audit.Actor) (DPORecords, error)
}

// Limits bound every answer (config.Police).
type Limits struct {
	LiveWindow   time.Duration
	AtWindow     time.Duration
	HistoryMax   time.Duration
	MaxBBoxDeg   float64
	MaxAircraft  int
	MaxPositions int
	MaxFleet     int
	DPOMaxRows   int
	Timeout      time.Duration
}

// Service is the police realm: the caller's checks, the queries, the
// exports and the DPO report.
type Service struct {
	Accounts   Accounts
	Registry   Registry
	Telemetry  Telemetry
	Incidents  Incidents
	Packs      Packs
	Ledger     Ledger
	Purposes   Purposes
	Budget     Budget
	Limits     Limits
	PublicPart incidents.PublicPartFunc
	Catalogue  audit.Catalogue
	Counters   *core.Counters
	Logger     *slog.Logger
	// NewID makes a police_queries id; nil is tokens.NewID.
	NewID func() (string, error)
}

func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Service) newID() (string, error) {
	if s.NewID != nil {
		return s.NewID()
	}
	return tokens.NewID()
}

func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.Limits.Timeout > 0 {
		return context.WithTimeout(ctx, s.Limits.Timeout)
	}
	return context.WithCancel(ctx)
}

func (s *Service) publicPart(reg string) string {
	if s.PublicPart != nil {
		return s.PublicPart(reg)
	}
	return reg
}

// Caller is the police account behind a request, as its row says now.
type Caller struct {
	UserID   string
	Agency   string
	JTI      string
	RemoteIP string
	Actor    audit.Actor
}

func forbidden(detail string) error {
	return httpx.Refuse(http.StatusForbidden, httpx.SlugForbidden, detail)
}

// caller resolves the police account of ctx: a live session of the
// police realm (Authorize admitted it), an active police account whose
// agency is set, and a client address inside the account's allow-list
// as it is now (a list changed after sign-in applies at once). An
// address outside is refused 403 and recorded.
func (s *Service) caller(ctx context.Context) (Caller, error) {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok || !id.Session || id.Realm != apiserver.RealmPolice || id.Subject == "" {
		return Caller{}, forbidden("a police query needs a session of the police realm")
	}
	u, err := s.Accounts.UserByID(ctx, id.Subject)
	if errors.Is(err, authz.ErrNotFound) {
		return Caller{}, forbidden("the account of this session does not exist")
	}
	if err != nil {
		return Caller{}, fmt.Errorf("read the police account: %w", err)
	}
	if u.Realm != apiserver.RealmPolice || u.Status != authz.StatusActive || u.Agency == "" {
		return Caller{}, forbidden("the account of this session is not an active police account")
	}
	ri := apiserver.RequestInfoFrom(ctx)
	c := Caller{UserID: u.ID, Agency: u.Agency, JTI: id.JTI, RemoteIP: ri.RemoteIP,
		Actor: audit.Actor{Type: audit.ActorUser, ID: u.ID, Realm: apiserver.RealmPolice}}
	if !authz.AddressAllowed(u.IPAllow, ri.RemoteIP) {
		s.inc(CounterRefusedAddress)
		s.refused(ctx, c, authz.ReasonAddressNotAllowed, nil)
		return Caller{}, httpx.Refuse(http.StatusForbidden, SlugAddressNotAllowed,
			"this address is not on the account's IP allow-list; the refusal is recorded")
	}
	return c, nil
}

// refused records a refusal on its own; a failure to record is counted
// and logged, and the refusal stands.
func (s *Service) refused(ctx context.Context, c Caller, reason string, payload map[string]any) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["agency"], payload["remote_ip"], payload["session"] = c.Agency, c.RemoteIP, c.JTI
	if err := s.Ledger.Refused(context.WithoutCancel(ctx), c.Actor, reason, payload); err != nil {
		s.inc(CounterRefusalNotSaved)
		logging.Error(ctx, s.logger(), "police refusal not recorded", err, slog.String("reason", reason))
	}
}

// record writes e under the budgets, refusing a spent one (recorded).
func (s *Service) record(ctx context.Context, e *Entry) error {
	id, err := s.newID()
	if err != nil {
		return err
	}
	e.ID = id
	if _, err := s.Ledger.Record(ctx, *e, s.Budget); err != nil {
		var spent *BudgetSpentError
		if errors.As(err, &spent) {
			s.inc(CounterRefusedBudget)
			s.refused(ctx, e.Caller, "budget_spent_"+spent.Scope, map[string]any{"kind": e.Kind, "purpose": e.Purpose,
				"case_ref": e.CaseRef, "retry_after_s": int(spent.RetryAfter.Seconds())})
		}
		return err
	}
	s.inc(CounterQueries)
	return nil
}

// piiContext marks every events row recorded under it (registry
// personal-data reads, evidence pack rows) with the police query, its
// case reference and the agency, so the DPO report links them.
func piiContext(ctx context.Context, e *Entry) context.Context {
	return audit.WithAnnotations(ctx, map[string]any{"police_query_id": e.ID, "case_ref": e.CaseRef, "agency": e.Caller.Agency})
}

// Identity is an operator's identity as a police answer carries it: the
// subset of the registry's personal data an agency needs to reach the
// person (G-10: expose only what the rule gives). The date of birth,
// the identification number and the insurance policy stay in the
// registry.
type Identity struct {
	OperatorID    string
	OperatorType  string
	FullName      string
	LegalName     string
	PostalAddress string
	ContactEmail  string
	ContactPhone  string
}

// identity reads an operator's identity for purpose, recorded as
// registry_pii_viewed by the registry.
func (s *Service) identity(ctx context.Context, op registry.Operator, purpose string, actor audit.Actor) (Identity, error) {
	p, err := s.Registry.OperatorPersonalData(ctx, op.ID, purpose, actor)
	if err != nil {
		return Identity{}, err
	}
	s.inc(CounterPIIReleased)
	return Identity{OperatorID: op.ID, OperatorType: op.OperatorType, FullName: p.FullName, LegalName: p.LegalName,
		PostalAddress: p.PostalAddress, ContactEmail: p.ContactEmail, ContactPhone: p.ContactPhone}, nil
}
