package registry

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the import (WP-20).
const (
	CounterImportApplied = "registry_import_applied" // imports committed
	CounterImportRefused = "registry_import_refused" // imports refused whole for their problems (nothing written)
	CounterImportDryRun  = "registry_import_dry_run" // dry runs (nothing written but their events row)
)

// Import kinds: one file holds one kind; operators go first, so an
// aircraft names an operator registered already.
const (
	ImportKindOperators = "operators"
	ImportKindUAS       = "uas"
)

// MaxImportRecords bounds one import (E-10): the transaction holds every
// record, so a larger file is refused before anything is read into it.
// REGISTRY_IMPORT_MAX_ROWS is at most this.
const MaxImportRecords = 50_000

// Import actions of one record.
const (
	ImportCreated   = "created"
	ImportUpdated   = "updated"
	ImportUnchanged = "unchanged"
)

// ImportedOperator is one operator record of an import, mapped by the
// rules file (internal/regimport). Record is its 1-based number in the
// file; SourceRef the source's id of it, the key the import is
// idempotent on.
type ImportedOperator struct {
	Record    int
	SourceRef string
	Operator  NewOperator
	Status    Status
}

// ImportedUAS is one aircraft record of an import. OperatorNumber is the
// owner's registration number (compared on its public part, G-04).
type ImportedUAS struct {
	Record         int
	SourceRef      string
	OperatorNumber string
	UAS            NewUAS
	Status         Status
}

// ImportOptions describes one import run: whether it is a dry run, the
// file it read (for its events row) and what the reader found before
// the registry saw a record.
type ImportOptions struct {
	DryRun bool
	// Origin is "upload" (a registrar's request) or "fetch" (the
	// periodic re-import).
	Origin       string
	SHA256       string
	RulesVersion string
	// Records is how many records the file holds, those that could not
	// be mapped included; zero means len(rows).
	Records int
	// Problems are the records the rules file could not map; with any,
	// the import is refused whole (nothing is written), and the rows
	// that did map are still checked so the report lists everything.
	Problems []*core.FieldError
}

// ImportOutcome is what an import did, or would do, with one record.
type ImportOutcome struct {
	Record    int
	SourceRef string
	Action    string
	EntityID  string
	// Fields names what an update changes (values are personal and never
	// reported); Status the status a create or a transition sets.
	Fields []string
	Status Status
}

// ImportResult is the report of one import or dry run. Problems are by
// record and field (records[<n>].<field>); with any, nothing was written.
type ImportResult struct {
	Kind      string
	DryRun    bool
	Records   int
	Created   int
	Updated   int
	Unchanged int
	Version   int64
	Outcomes  []ImportOutcome
	Problems  []*core.FieldError
}

// Applied reports a committed import (not a dry run, no problem).
func (r *ImportResult) Applied() bool { return !r.DryRun && len(r.Problems) == 0 }

// errRollback ends a dry run's or a refused import's transaction.
var errRollback = errors.New("import rolled back")

// importChange collects an import's projection rows: tight ones (a
// tightening or neutral change) are written before the relational
// commit, loose ones (a new entry, a status becoming active) after it,
// the order change() uses for one change (G-08).
type importChange struct {
	version int64
	at      time.Time
	tightOp []ProjectedOperator
	looseOp []ProjectedOperator
	tightU  []ProjectedUAS
	looseU  []ProjectedUAS
}

func (ic *importChange) operator(o *Operator, loose bool) {
	if loose {
		ic.looseOp = append(ic.looseOp, projectOperator(o))
	} else {
		ic.tightOp = append(ic.tightOp, projectOperator(o))
	}
}

func (ic *importChange) uas(u *UAS, loose bool) {
	if loose {
		ic.looseU = append(ic.looseU, projectUAS(u))
	} else {
		ic.tightU = append(ic.tightU, projectUAS(u))
	}
}

// problem records err against record: every field error it carries
// (a refusal's too), prefixed records[<n>].
func (r *ImportResult) problem(record int, err error) {
	var fes []*core.FieldError
	var pe *httpx.ProblemError
	if errors.As(err, &pe) {
		for _, e := range pe.Problem.Errors {
			fes = append(fes, &core.FieldError{Field: e.Field, Reason: e.Reason})
		}
	} else {
		fes = fieldErrorsOf(err)
	}
	if len(fes) == 0 {
		fes = []*core.FieldError{{Field: "record", Reason: err.Error()}}
	}
	for _, fe := range fes {
		field := fmt.Sprintf("records[%d]", record)
		if fe.Field != "" && fe.Field != "record" {
			field += "." + fe.Field
		}
		r.Problems = append(r.Problems, &core.FieldError{Field: field, Reason: fe.Reason})
	}
}

// isRefusal reports a refusal (a problem below 500): a record's
// problem, not a failure of the import.
func isRefusal(err error) bool {
	p := httpx.ProblemFromError(err)
	return p.Status < http.StatusInternalServerError
}

func (r *ImportResult) outcome(o ImportOutcome) {
	r.Outcomes = append(r.Outcomes, o)
	switch o.Action {
	case ImportCreated:
		r.Created++
	case ImportUpdated:
		r.Updated++
	case ImportUnchanged:
		r.Unchanged++
	}
}

// importStatus refuses a status an import may not set: expired is the
// expiry job's.
func importStatus(st Status) error {
	if st != StatusActive && st != StatusSuspended && st != StatusRevoked {
		return core.Fieldf("status", "must map to active, suspended or revoked")
	}
	return nil
}

// importReason is the reason an import records with a status it sets.
const importReason = "as recorded by uas.gov.ge"

// runImport runs fn in one transaction holding LockProjection and
// numbered by one registry version: every record of the file commits
// together or none does. A dry run, or a file with any problem, is
// rolled back; neither touches the projection. A committed import
// writes its tight projection rows before the commit (a failed write
// rolls it back, 503) and its loose ones after (a failed write leaves
// the stricter rows, counted and repaired), then publishes the version.
func (s *Service) runImport(ctx context.Context, res *ImportResult, meta ImportOptions, actor audit.Actor,
	fn func(tx Tx, v *regnum.Validator, ic *importChange) error,
) error {
	v, err := s.validator()
	if err != nil {
		return err
	}
	var ic *importChange
	projected := false
	err = s.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, LockProjection); err != nil {
			return err
		}
		version, err := tx.NextVersion(ctx)
		if err != nil {
			return err
		}
		ic = &importChange{version: version, at: s.now()}
		if err := fn(tx, v, ic); err != nil {
			return err
		}
		sortProblems(res.Problems)
		if res.DryRun || len(res.Problems) > 0 {
			return errRollback
		}
		res.Version = version
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "registry_import", EntityID: meta.SHA256, EventType: audit.EventRegistryImported,
			Payload: importPayload(res, meta),
		}); err != nil {
			return err
		}
		if len(ic.tightOp) == 0 && len(ic.tightU) == 0 {
			return nil
		}
		if err := s.writeProjection(ctx, &changeSet{version: version, at: ic.at, ops: ic.tightOp, uas: ic.tightU}); err != nil {
			s.count(CounterProjectionWriteFailed)
			logging.Error(ctx, s.logger(), "registry import rolled back: the projection was not written", err,
				slog.Int64("registry_version", version))
			return projectionRefusal(err)
		}
		projected = true
		return nil
	})
	if errors.Is(err, errRollback) {
		res.Version = 0
		return s.recordUnapplied(ctx, res, meta, actor)
	}
	if err != nil {
		if projected {
			s.count(CounterProjectionAhead)
			logging.Error(ctx, s.logger(), "registry import not committed after its projection was; re-projecting now", err,
				slog.Int64("registry_version", ic.version))
			s.RequestRepair()
		}
		return err
	}
	s.count(CounterImportApplied)
	if len(ic.looseOp) > 0 || len(ic.looseU) > 0 {
		if err := s.writeProjection(ctx, &changeSet{version: ic.version, at: ic.at, ops: ic.looseOp, uas: ic.looseU}); err != nil {
			s.count(CounterProjectionBehind)
			logging.Error(ctx, s.logger(), "registry import committed but not projected; the projection keeps the stricter state until the repair", err,
				slog.Int64("registry_version", ic.version))
			s.RequestRepair()
			return nil
		}
		projected = true
	}
	if projected {
		s.publish(ctx, ic.version)
	}
	return nil
}

// recordUnapplied writes the events row of a dry run or of an import
// refused for its problems, after their transaction rolled back.
func (s *Service) recordUnapplied(ctx context.Context, res *ImportResult, meta ImportOptions, actor audit.Actor) error {
	eventType := audit.EventRegistryImportRefused
	if res.DryRun {
		eventType = audit.EventRegistryImportDryRun
		s.count(CounterImportDryRun)
	} else {
		s.count(CounterImportRefused)
	}
	return s.Store.InTx(ctx, func(tx Tx) error {
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "registry_import", EntityID: meta.SHA256, EventType: eventType, Payload: importPayload(res, meta),
		})
	})
}

func importPayload(res *ImportResult, meta ImportOptions) map[string]any {
	return map[string]any{
		"kind": res.Kind, "origin": meta.Origin, "content_sha256": meta.SHA256, "rules_version": meta.RulesVersion,
		"dry_run": res.DryRun, "records": res.Records, "created": res.Created, "updated": res.Updated,
		"unchanged": res.Unchanged, "problems": len(res.Problems), "registry_version": res.Version,
	}
}

func newResult(kind string, rows int, o *ImportOptions) ImportResult {
	n := o.Records
	if n == 0 {
		n = rows
	}
	return ImportResult{Kind: kind, DryRun: o.DryRun, Records: n, Problems: slices.Clone(o.Problems)}
}

// sortProblems orders problems by record, then as found.
func sortProblems(ps []*core.FieldError) {
	slices.SortStableFunc(ps, func(a, b *core.FieldError) int { return cmp.Compare(recordOf(a.Field), recordOf(b.Field)) })
}

// recordOf is the n of a records[n] field; 0 for another field.
func recordOf(field string) int {
	rest, ok := strings.CutPrefix(field, "records[")
	if !ok {
		return 0
	}
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}

func checkImportSize(n int) error {
	if n > MaxImportRecords {
		return core.Fieldf("records", "%d records, at most %d per import", n, MaxImportRecords)
	}
	return nil
}

// ImportOperators registers or updates the operators of a uas.gov.ge
// export, all or nothing, idempotently on the source's record id (rows
// marked source = uas_gov_ge_import). A record the registry holds from
// this source is updated where it differs and moved to its status; one
// that matches is left alone (unchanged, nothing written). A number
// registered from another source, a record whose number, type or start
// of validity changed, a revoked record listed as anything else and a
// duplicate in the file are problems. With any problem, or as a dry run,
// nothing is written but the events row that reports it.
func (s *Service) ImportOperators(ctx context.Context, rows []ImportedOperator, meta ImportOptions, actor audit.Actor) (ImportResult, error) {
	res := newResult(ImportKindOperators, len(rows), &meta)
	if err := checkImportSize(res.Records); err != nil {
		return res, s.refused(err)
	}
	err := s.runImport(ctx, &res, meta, actor, func(tx Tx, v *regnum.Validator, ic *importChange) error {
		refs, keys := map[string]int{}, map[string]int{}
		for i := range rows {
			if err := s.importOperator(ctx, tx, v, ic, &rows[i], refs, keys, actor, &res); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func (s *Service) importOperator(ctx context.Context, tx Tx, v *regnum.Validator, ic *importChange, row *ImportedOperator,
	refs, keys map[string]int, actor audit.Actor, res *ImportResult,
) error {
	in := row.Operator
	in.Source, in.SourceRef = SourceImport, row.SourceRef
	var errs []error
	if strings.TrimSpace(row.SourceRef) == "" {
		errs = append(errs, &core.FieldError{Field: "source_id", Reason: "required: the import is idempotent on it"})
	} else if first, dup := refs[row.SourceRef]; dup {
		errs = append(errs, core.Fieldf("source_id", "%q is also record %d", row.SourceRef, first))
	} else {
		refs[row.SourceRef] = row.Record
	}
	public, key, err := checkNewOperator(v, &in, ic.at)
	if err != nil {
		errs = append(errs, err)
	} else if first, dup := keys[key]; dup {
		errs = append(errs, core.Fieldf("registration_number", "%q is also record %d", public, first))
	} else {
		keys[key] = row.Record
	}
	errs = append(errs, importStatus(row.Status))
	if err := errors.Join(errs...); err != nil {
		res.problem(row.Record, err)
		return nil
	}
	existing, err := tx.OperatorBySourceRef(ctx, SourceImport, row.SourceRef)
	switch {
	case errors.Is(err, ErrNotFound):
		return s.importNewOperator(ctx, tx, ic, row, &in, public, key, actor, res)
	case err != nil:
		return err
	}
	return s.importKnownOperator(ctx, tx, ic, row, &in, &existing, key, actor, res)
}

func (s *Service) importNewOperator(ctx context.Context, tx Tx, ic *importChange, row *ImportedOperator, in *NewOperator,
	public, key string, actor audit.Actor, res *ImportResult,
) error {
	other, err := tx.OperatorByKey(ctx, key)
	switch {
	case err == nil:
		res.problem(row.Record, core.Fieldf("registration_number",
			"%q is registered already (source %s), not from this import; resolve it by hand before importing", public, other.Source))
		return nil
	case !errors.Is(err, ErrNotFound):
		return err
	}
	if in.ValidFrom.After(ic.at) {
		res.problem(row.Record, core.Fieldf("valid_from", "must not be in the future"))
		return nil
	}
	id, err := newID()
	if err != nil {
		return err
	}
	sealed, err := s.sealOperator(id, &in.PII)
	if err != nil {
		return err
	}
	var salt []byte
	var hash string
	if in.SecretPart != "" {
		if salt, hash, err = s.Hasher.NewSecretPart(in.SecretPart); err != nil {
			return err
		}
	}
	reason := ""
	if row.Status != StatusActive {
		reason = importReason
	}
	r, err := tx.InsertOperator(ctx, OperatorRecord{
		Operator: Operator{
			ID: id, OperatorType: in.OperatorType, RegistrationNumber: public, CompetencyConfirmation: in.CompetencyConfirmation,
			Authorisations: in.Authorisations, Status: row.Status, StatusReason: reason, ValidFrom: in.ValidFrom.UTC(),
			ValidUntil: in.ValidUntil.UTC(), Source: SourceImport, SourceRef: row.SourceRef, RegistryVersion: ic.version,
			CreatedAt: ic.at, CreatedBy: actor.ID, UpdatedAt: ic.at, UpdatedBy: actor.ID,
		},
		Key: key, SecretSalt: salt, SecretHash: hash, Sealed: sealed,
	})
	if err != nil {
		return err
	}
	if err := s.feed(ctx, tx, EntityOperator, id, public, row.Status, ic.at); err != nil {
		return err
	}
	if err := tx.Record(ctx, audit.Event{
		Actor: actor, EntityType: EntityOperator, EntityID: id, EventType: audit.EventOperatorRegistered,
		Payload: map[string]any{
			"registration_number": public, "operator_type": in.OperatorType, "source": SourceImport, "source_ref": row.SourceRef,
			"status": row.Status, "has_secret_part": hash != "", "valid_until": in.ValidUntil.UTC(), "registry_version": ic.version,
		},
	}); err != nil {
		return err
	}
	ic.operator(&r.Operator, true)
	res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportCreated, EntityID: id, Status: row.Status})
	return nil
}

func jsonEqual(a, b json.RawMessage) bool {
	norm := func(raw json.RawMessage) string {
		if len(raw) == 0 {
			return "[]"
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, raw); err != nil {
			return string(raw)
		}
		return buf.String()
	}
	return norm(a) == norm(b)
}

// operatorDiff is the patch that makes r match in, with the names of the
// fields it sets.
func operatorDiff(r *Operator, cur *OperatorPII, in *NewOperator) (OperatorPatch, []string) {
	var p OperatorPatch
	var fields []string
	str := func(name, have, want string, dst **string) {
		if have != want {
			w := want
			*dst = &w
			fields = append(fields, name)
		}
	}
	str("full_name", cur.FullName, in.PII.FullName, &p.FullName)
	str("legal_name", cur.LegalName, in.PII.LegalName, &p.LegalName)
	str("date_of_birth", cur.DateOfBirth, in.PII.DateOfBirth, &p.DateOfBirth)
	str("legal_identification_number", cur.LegalIdentificationNumber, in.PII.LegalIdentificationNumber, &p.LegalIdentificationNumber)
	str("postal_address", cur.PostalAddress, in.PII.PostalAddress, &p.PostalAddress)
	str("contact_email", cur.ContactEmail, in.PII.ContactEmail, &p.ContactEmail)
	str("contact_phone", cur.ContactPhone, in.PII.ContactPhone, &p.ContactPhone)
	str("insurance_policy_number", cur.InsurancePolicyNumber, in.PII.InsurancePolicyNumber, &p.InsurancePolicyNumber)
	if r.CompetencyConfirmation != in.CompetencyConfirmation {
		c := in.CompetencyConfirmation
		p.CompetencyConfirmation = &c
		fields = append(fields, "competency_confirmation")
	}
	if in.Authorisations != nil && !jsonEqual(r.Authorisations, in.Authorisations) {
		p.Authorisations = in.Authorisations
		fields = append(fields, "authorisations")
	}
	if !r.ValidUntil.Equal(in.ValidUntil) {
		u := in.ValidUntil.UTC()
		p.ValidUntil = &u
		fields = append(fields, "valid_until")
	}
	return p, fields
}

func (s *Service) importKnownOperator(ctx context.Context, tx Tx, ic *importChange, row *ImportedOperator, in *NewOperator,
	existing *OperatorRecord, key string, actor audit.Actor, res *ImportResult,
) error {
	var errs []error
	if existing.Key != key {
		errs = append(errs, core.Fieldf("registration_number",
			"the record was imported as %q; a registration's number never changes (revoke it and register again)", existing.RegistrationNumber))
	}
	if existing.OperatorType != in.OperatorType {
		errs = append(errs, core.Fieldf("operator_type", "the record was imported as %s; an operator's type never changes", existing.OperatorType))
	}
	// valid_from is compared only when the file gives one (an absent one
	// defaults to now, which a re-import must not read as a change).
	if given := row.Operator.ValidFrom; !given.IsZero() && !existing.ValidFrom.Equal(given.UTC()) {
		errs = append(errs, core.Fieldf("valid_from", "the record was imported valid from %s; the start of a registration never changes",
			existing.ValidFrom.UTC().Format(time.RFC3339)))
	}
	if in.SecretPart != "" && (existing.SecretHash == "" || !s.Hasher.SecretPartMatches(existing.SecretSalt, existing.SecretHash, in.SecretPart)) {
		errs = append(errs, core.Fieldf("secret_part", "differs from the one imported; a secret part never changes"))
	}
	if existing.Status == StatusRevoked && row.Status != StatusRevoked {
		errs = append(errs, core.Fieldf("status", "the registration is revoked, which is final; the file lists it %s", row.Status))
	}
	if err := errors.Join(errs...); err != nil {
		res.problem(row.Record, err)
		return nil
	}
	pii, err := s.openOperator(existing)
	if err != nil {
		return err
	}
	patch, fields := operatorDiff(&existing.Operator, &pii, in)
	want := row.Status
	// An expiry is the registry's consequence of valid_until, not a
	// difference: an export that still says active for a registration
	// past its end leaves it expired.
	if existing.Status == StatusExpired && want == StatusActive && !in.ValidUntil.After(ic.at) {
		want = StatusExpired
	}
	if len(fields) == 0 && want == existing.Status {
		res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportUnchanged, EntityID: existing.ID, Status: existing.Status})
		return nil
	}
	cur := existing.Operator
	if len(fields) > 0 {
		o, newPII, err := applyOperatorPatch(cur, pii, patch, ic.at)
		if err != nil {
			res.problem(row.Record, err)
			return nil
		}
		sealed, err := s.sealOperator(existing.ID, &newPII)
		if err != nil {
			return err
		}
		rec := *existing
		rec.Operator, rec.Sealed = o, sealed
		rec.RegistryVersion, rec.UpdatedAt, rec.UpdatedBy = ic.version, ic.at, actor.ID
		u, err := tx.UpdateOperator(ctx, rec)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityOperator, EntityID: existing.ID, EventType: audit.EventOperatorUpdated,
			Payload: map[string]any{"fields": fields, "source": SourceImport, "source_ref": row.SourceRef, "registry_version": ic.version},
		}); err != nil {
			return err
		}
		cur = u.Operator
		*existing = u
	}
	if want != existing.Status {
		cs := &changeSet{version: ic.version, at: ic.at}
		o, err := s.operatorTransition(ctx, tx, cs, existing, want, importReason, actor, false)
		if err != nil {
			if isRefusal(err) {
				res.problem(row.Record, err)
				return nil
			}
			return err
		}
		ic.operator(&o, cs.loosening)
		fields = append(fields, "status")
	} else {
		ic.operator(&cur, false)
	}
	res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportUpdated, EntityID: existing.ID, Fields: fields, Status: want})
	return nil
}

// ImportUAS registers or updates the aircraft of a uas.gov.ge export,
// all or nothing, idempotently on the source's record id, as
// ImportOperators does for operators. Each record names its owner by
// registration number; the owner must be registered (import the
// operators first) and not revoked. A record whose serial or owner
// changed is a problem: an aircraft's identity never changes.
func (s *Service) ImportUAS(ctx context.Context, rows []ImportedUAS, meta ImportOptions, actor audit.Actor) (ImportResult, error) {
	res := newResult(ImportKindUAS, len(rows), &meta)
	if err := checkImportSize(res.Records); err != nil {
		return res, s.refused(err)
	}
	err := s.runImport(ctx, &res, meta, actor, func(tx Tx, v *regnum.Validator, ic *importChange) error {
		refs, folds := map[string]int{}, map[string]int{}
		owners := map[string]bool{} // owners projected already in this import
		for i := range rows {
			if err := s.importUAS(ctx, tx, v, ic, &rows[i], refs, folds, owners, actor, &res); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func (s *Service) importUAS(ctx context.Context, tx Tx, v *regnum.Validator, ic *importChange, row *ImportedUAS,
	refs, folds map[string]int, owners map[string]bool, actor audit.Actor, res *ImportResult,
) error {
	var errs []error
	if strings.TrimSpace(row.SourceRef) == "" {
		errs = append(errs, &core.FieldError{Field: "source_id", Reason: "required: the import is idempotent on it"})
	} else if first, dup := refs[row.SourceRef]; dup {
		errs = append(errs, core.Fieldf("source_id", "%q is also record %d", row.SourceRef, first))
	} else {
		refs[row.SourceRef] = row.Record
	}
	if utf8Len(row.SourceRef) > maxRefLen*2 {
		errs = append(errs, core.Fieldf("source_id", "longer than %d characters", maxRefLen*2))
	}
	var owner OperatorRecord
	if strings.TrimSpace(row.OperatorNumber) == "" {
		errs = append(errs, &core.FieldError{Field: "operator_registration_number", Reason: "required"})
	} else {
		o, err := tx.OperatorByKey(ctx, v.CompareKey(row.OperatorNumber))
		switch {
		case errors.Is(err, ErrNotFound):
			errs = append(errs, core.Fieldf("operator_registration_number", "no operator %q is registered; import the operators first",
				v.PublicPart(row.OperatorNumber)))
		case err != nil:
			return err
		case o.Status == StatusRevoked && row.Status != StatusRevoked:
			errs = append(errs, core.Fieldf("operator_registration_number", "operator %q is revoked", o.RegistrationNumber))
		default:
			owner = o
		}
	}
	in := row.UAS
	in.OperatorID = owner.ID
	if owner.ID == "" {
		in.OperatorID = strings.Repeat("0", 32) // checked above; keeps the other fields' checks running
	}
	u, err := checkNewUAS(in)
	if err != nil {
		errs = append(errs, err)
	} else if first, dup := folds[u.SerialFold]; dup {
		errs = append(errs, core.Fieldf("serial", "%q is also record %d (equal or differing only by case, G-05)", u.Serial, first))
	} else {
		folds[u.SerialFold] = row.Record
	}
	errs = append(errs, importStatus(row.Status))
	if err := errors.Join(errs...); err != nil {
		res.problem(row.Record, err)
		return nil
	}
	existing, err := tx.UASBySourceRef(ctx, SourceImport, row.SourceRef)
	switch {
	case errors.Is(err, ErrNotFound):
		return s.importNewUAS(ctx, tx, ic, row, &u, &owner, owners, actor, res)
	case err != nil:
		return err
	}
	return s.importKnownUAS(ctx, tx, ic, row, &u, &existing, actor, res)
}

func utf8Len(s string) int { return len([]rune(s)) }

func (s *Service) importNewUAS(ctx context.Context, tx Tx, ic *importChange, row *ImportedUAS, u *UAS, owner *OperatorRecord,
	owners map[string]bool, actor audit.Actor, res *ImportResult,
) error {
	existing, err := tx.UASByFold(ctx, u.SerialFold)
	if err != nil {
		return err
	}
	if err := foldConflict(u.Serial, existing); err != nil {
		res.problem(row.Record, err)
		return nil
	}
	if u.ID, err = newID(); err != nil {
		return err
	}
	u.Status, u.RegisteredAt, u.RegistryVersion = row.Status, ic.at, ic.version
	u.CreatedBy, u.UpdatedAt, u.UpdatedBy = actor.ID, ic.at, actor.ID
	u.Source, u.SourceRef = SourceImport, row.SourceRef
	if row.Status != StatusActive {
		u.StatusReason = importReason
	}
	r, err := tx.InsertUAS(ctx, *u)
	if err != nil {
		return err
	}
	if err := s.feed(ctx, tx, EntityUAS, r.ID, r.Serial, row.Status, ic.at); err != nil {
		return err
	}
	if err := tx.Record(ctx, audit.Event{
		Actor: actor, EntityType: EntityUAS, EntityID: r.ID, EventType: audit.EventUASRegistered,
		Payload: map[string]any{"serial": r.Serial, "operator_id": r.OperatorID, "class_label": r.ClassLabel, "source": SourceImport,
			"source_ref": row.SourceRef, "status": row.Status, "registry_version": ic.version},
	}); err != nil {
		return err
	}
	// The owner is projected with its aircraft, so the aircraft never
	// reaches a resolver before its owner (identify's owner_unknown).
	if !owners[owner.ID] {
		owners[owner.ID] = true
		ic.operator(&owner.Operator, true)
	}
	ic.uas(&r, true)
	res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportCreated, EntityID: r.ID, Status: row.Status})
	return nil
}

func uasDiff(cur, want *UAS) (UASPatch, []string) {
	var p UASPatch
	var fields []string
	str := func(name, have, w string, dst **string) {
		if have != w {
			v := w
			*dst = &v
			fields = append(fields, name)
		}
	}
	str("registration_mark", cur.RegistrationMark, want.RegistrationMark, &p.RegistrationMark)
	str("manufacturer", cur.Manufacturer, want.Manufacturer, &p.Manufacturer)
	str("model", cur.Model, want.Model, &p.Model)
	str("owner_ref", cur.OwnerRef, want.OwnerRef, &p.OwnerRef)
	str("class_label", cur.ClassLabel, want.ClassLabel, &p.ClassLabel)
	str("rid_capability", cur.RIDCapability, want.RIDCapability, &p.RIDCapability)
	if want.MTOMG != nil && (cur.MTOMG == nil || *cur.MTOMG != *want.MTOMG) {
		m := *want.MTOMG
		p.MTOMG = &m
		fields = append(fields, "mtom_g")
	}
	return p, fields
}

func (s *Service) importKnownUAS(ctx context.Context, tx Tx, ic *importChange, row *ImportedUAS, want, existing *UAS,
	actor audit.Actor, res *ImportResult,
) error {
	var errs []error
	if existing.Serial != want.Serial {
		errs = append(errs, core.Fieldf("serial", "the record was imported as %q; an aircraft's serial never changes", existing.Serial))
	}
	if existing.OperatorID != want.OperatorID {
		errs = append(errs, core.Fieldf("operator_registration_number",
			"the record was imported under another operator; a change of owner is a revocation and a new registration"))
	}
	if existing.Status == StatusRevoked && row.Status != StatusRevoked {
		errs = append(errs, core.Fieldf("status", "the registration is revoked, which is final; the file lists it %s", row.Status))
	}
	if err := errors.Join(errs...); err != nil {
		res.problem(row.Record, err)
		return nil
	}
	patch, fields := uasDiff(existing, want)
	if len(fields) == 0 && row.Status == existing.Status {
		res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportUnchanged, EntityID: existing.ID, Status: existing.Status})
		return nil
	}
	cur := *existing
	if len(fields) > 0 {
		u, err := applyUASPatch(cur, patch)
		if err != nil {
			res.problem(row.Record, err)
			return nil
		}
		u.RegistryVersion, u.UpdatedAt, u.UpdatedBy = ic.version, ic.at, actor.ID
		if cur, err = tx.UpdateUAS(ctx, u); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityUAS, EntityID: cur.ID, EventType: audit.EventUASUpdated,
			Payload: map[string]any{"fields": fields, "source": SourceImport, "source_ref": row.SourceRef, "registry_version": ic.version},
		}); err != nil {
			return err
		}
	}
	loose := false
	if row.Status != cur.Status {
		if err := CheckTransition(cur.Status, row.Status, importReason, false); err != nil {
			res.problem(row.Record, err)
			return nil
		}
		r, err := tx.SetUASStatus(ctx, StatusUpdate{ID: cur.ID, Status: row.Status, Reason: importReason, Version: ic.version, At: ic.at, By: actor.ID})
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityUAS, cur.ID, r.Serial, row.Status, ic.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityUAS, EntityID: cur.ID, EventType: audit.EventRegistryStatusChanged,
			Payload: map[string]any{"from": cur.Status, "to": row.Status, "reason": importReason, "serial": r.Serial,
				"source": SourceImport, "registry_version": ic.version},
		}); err != nil {
			return err
		}
		loose = row.Status == StatusActive
		cur = r
		fields = append(fields, "status")
	}
	ic.uas(&cur, loose)
	res.outcome(ImportOutcome{Record: row.Record, SourceRef: row.SourceRef, Action: ImportUpdated, EntityID: cur.ID, Fields: fields, Status: row.Status})
	return nil
}
