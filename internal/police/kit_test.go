package police

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/authz"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/registry"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// The fakes of the police realm's dependencies, and a kit holding them.

type fakeAccounts map[string]authz.User

func (f fakeAccounts) UserByID(_ context.Context, id string) (authz.User, error) {
	u, ok := f[id]
	if !ok {
		return authz.User{}, authz.ErrNotFound
	}
	return u, nil
}

type piiRead struct {
	operatorID, purpose string
	annotations         map[string]any
}

type fakeRegistry struct {
	mu        sync.Mutex
	operators map[string]registry.Operator // by id
	pii       map[string]registry.OperatorPII
	uas       map[string]registry.UAS // by id
	reads     []piiRead
	failPII   bool
}

func (r *fakeRegistry) OperatorByNumber(_ context.Context, number string) (registry.Operator, bool, error) {
	var found []registry.Operator
	for id := range r.operators {
		if strings.EqualFold(r.operators[id].RegistrationNumber, number) {
			found = append(found, r.operators[id])
		}
	}
	switch len(found) {
	case 0:
		return registry.Operator{}, false, nil
	case 1:
		return found[0], true, nil
	}
	return registry.Operator{}, false, registry.ErrAmbiguous
}

func (r *fakeRegistry) UASBySerial(_ context.Context, sn string) (registry.UAS, bool, error) {
	for id := range r.uas {
		if r.uas[id].Serial == sn {
			return r.uas[id], true, nil
		}
	}
	return registry.UAS{}, false, nil
}

func (r *fakeRegistry) GetOperator(_ context.Context, id string) (registry.Operator, error) {
	o, ok := r.operators[id]
	if !ok {
		return registry.Operator{}, errors.New("no such operator")
	}
	return o, nil
}

func (r *fakeRegistry) GetUAS(_ context.Context, id string) (registry.UAS, error) {
	u, ok := r.uas[id]
	if !ok {
		return registry.UAS{}, errors.New("no such uas")
	}
	return u, nil
}

func (r *fakeRegistry) ListUAS(_ context.Context, _, operatorID string, _ registry.Status, page registry.Page) ([]registry.UAS, error) {
	var out []registry.UAS
	for id := range r.uas {
		if r.uas[id].OperatorID == operatorID {
			out = append(out, r.uas[id])
		}
	}
	slices.SortFunc(out, func(a, b registry.UAS) int { return strings.Compare(a.Serial, b.Serial) })
	if len(out) > page.Limit {
		out = out[:page.Limit]
	}
	return out, nil
}

// annotationsOf is what the audit writer would add to an events row
// recorded under ctx.
func annotationsOf(ctx context.Context) map[string]any { return audit.Annotations(ctx) }

func (r *fakeRegistry) OperatorPersonalData(ctx context.Context, id, purpose string, _ audit.Actor) (registry.OperatorPII, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if purpose == "" {
		return registry.OperatorPII{}, errors.New("a personal-data read without a purpose")
	}
	if r.failPII {
		return registry.OperatorPII{}, errors.New("registry down")
	}
	r.reads = append(r.reads, piiRead{operatorID: id, purpose: purpose, annotations: annotationsOf(ctx)})
	return r.pii[id], nil
}

type fakeTelemetry struct {
	now       time.Time
	newestAge float64
	hasNewest bool
	rows      []reader.PoliceAircraftRow
	positions []reader.PolicePositionsRow
	gaps      reader.PoliceWriterGapsRow
	asked     []reader.PoliceAircraftParams
}

func (f *fakeTelemetry) PoliceClock(context.Context, float64) (reader.PoliceClockRow, error) {
	return reader.PoliceClockRow{DbNow: f.now, HasNewest: f.hasNewest, NewestAgeS: f.newestAge}, nil
}

func (f *fakeTelemetry) PoliceAircraft(_ context.Context, arg reader.PoliceAircraftParams) ([]reader.PoliceAircraftRow, error) {
	f.asked = append(f.asked, arg)
	rows := f.rows
	if len(rows) > int(arg.RowLimit) {
		rows = rows[:arg.RowLimit]
	}
	return rows, nil
}

func (f *fakeTelemetry) PolicePositions(_ context.Context, arg reader.PolicePositionsParams) ([]reader.PolicePositionsRow, error) {
	var out []reader.PolicePositionsRow
	per := map[string]int{}
	// The query answers newest first within a track.
	for i := len(f.positions) - 1; i >= 0; i-- {
		p := f.positions[i]
		if slices.Contains(arg.TrackIds, p.TrackID) && per[p.TrackID] < int(arg.PerTrack) {
			per[p.TrackID]++
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeTelemetry) PoliceWriterGaps(context.Context, reader.PoliceWriterGapsParams) (reader.PoliceWriterGapsRow, error) {
	return f.gaps, nil
}

type fakeIncidents struct {
	views  map[string]incidents.View
	opened []incidents.PoliceRequest
}

func (f *fakeIncidents) Get(_ context.Context, id string) (incidents.View, error) {
	v, ok := f.views[id]
	if !ok {
		return incidents.View{}, errors.New("no such incident")
	}
	return v, nil
}

func (f *fakeIncidents) OpenForPolice(_ context.Context, _ audit.Actor, r incidents.PoliceRequest) (incidents.View, error) {
	f.opened = append(f.opened, r)
	return incidents.View{Incident: pggen.Incident{IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8KA"}}, nil
}

type packCall struct {
	piiRole     bool
	incident    string
	req         incidents.PackRequest
	annotations map[string]any
}

type fakePacks struct {
	created    []packCall
	downloaded []packCall
}

func (f *fakePacks) Create(ctx context.Context, _ audit.Actor, piiRole bool, incidentID string, r incidents.PackRequest) (pggen.EvidencePack, error) {
	f.created = append(f.created, packCall{piiRole: piiRole, incident: incidentID, req: r, annotations: annotationsOf(ctx)})
	return pggen.EvidencePack{PackID: "01JTESTPACK000000000000000", IncidentID: incidentID, Kind: r.Kind, WindowFrom: r.From, WindowTo: r.To,
		ContentHash: "sha256:00", SizeBytes: 10, CreatedAt: r.From}, nil
}

func (f *fakePacks) Download(ctx context.Context, _ audit.Actor, piiRole bool, incidentID, packID, purpose string) ([]byte, pggen.EvidencePack, error) {
	f.downloaded = append(f.downloaded, packCall{piiRole: piiRole, incident: incidentID, req: incidents.PackRequest{Purpose: purpose},
		annotations: annotationsOf(ctx)})
	return []byte("zip"), pggen.EvidencePack{PackID: packID, ContentHash: "sha256:00"}, nil
}

// fakeLedger keeps the rows and budgets in memory on its own clock.
type fakeLedger struct {
	mu       sync.Mutex
	now      time.Time
	entries  []Entry
	at       []time.Time
	refusals []map[string]any
	exports  map[string]Export
	dpo      DPORecords
	dpoSeen  []string
}

func (l *fakeLedger) Record(_ context.Context, e Entry, b Budget) (time.Time, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var user, agency int
	for i := range l.entries {
		if l.now.Sub(l.at[i]) >= b.Window {
			continue
		}
		if l.entries[i].Caller.UserID == e.Caller.UserID {
			user++
		}
		if l.entries[i].Caller.Agency == e.Caller.Agency {
			agency++
		}
	}
	switch {
	case user >= b.User:
		return time.Time{}, &BudgetSpentError{Scope: "user", RetryAfter: 30 * time.Second}
	case agency >= b.Agency:
		return time.Time{}, &BudgetSpentError{Scope: "agency", RetryAfter: 30 * time.Second}
	}
	l.entries, l.at = append(l.entries, e), append(l.at, l.now)
	return l.now, nil
}

func (l *fakeLedger) Refused(_ context.Context, _ audit.Actor, reason string, payload map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	payload["reason"] = reason
	l.refusals = append(l.refusals, payload)
	return nil
}

func (l *fakeLedger) InsertExport(_ context.Context, x Export) error {
	l.exports[x.PackID] = x
	return nil
}

func (l *fakeLedger) ExportByPack(_ context.Context, id string) (Export, bool, error) {
	x, ok := l.exports[id]
	return x, ok, nil
}

func (l *fakeLedger) DPO(_ context.Context, _, _ time.Time, _ int, piiTypes []string, _ audit.Actor) (DPORecords, error) {
	l.dpoSeen = piiTypes
	return l.dpo, nil
}

type kit struct {
	svc   *Service
	acc   fakeAccounts
	reg   *fakeRegistry
	tel   *fakeTelemetry
	inc   *fakeIncidents
	packs *fakePacks
	led   *fakeLedger
	now   time.Time
}

const (
	officerID = "0123456789abcdef0123456789abcdef"
	agencyA   = "TEST-POLICE"
	insideIP  = "192.0.2.10"
	outsideIP = "198.51.100.9"
	opID      = "op-1"
	uasID     = "uas-1"
)

func newKit(t *testing.T) *kit {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	purposes, err := NewPurposes([]string{"public_order", "criminal_investigation"}, []string{"criminal_investigation"})
	if err != nil {
		t.Fatal(err)
	}
	k := &kit{
		acc: fakeAccounts{officerID: {ID: officerID, Realm: apiserver.RealmPolice, Status: authz.StatusActive, Agency: agencyA,
			IPAllow: []string{"192.0.2.0/24"}, Roles: []string{apiserver.RolePoliceQuery}}},
		reg: &fakeRegistry{
			operators: map[string]registry.Operator{opID: {ID: opID, OperatorType: "natural", RegistrationNumber: "GEOTEST00000001",
				Status: registry.StatusActive, ValidFrom: now.AddDate(-1, 0, 0), ValidUntil: now.AddDate(1, 0, 0)}},
			pii: map[string]registry.OperatorPII{opID: {FullName: "Test Person", PostalAddress: "1 Test Street", ContactEmail: "p@example.test",
				ContactPhone: "+995 555 000 001", DateOfBirth: "1990-01-01", LegalIdentificationNumber: "TEST-01", InsurancePolicyNumber: "TEST-INS"}},
			uas: map[string]registry.UAS{uasID: {ID: uasID, OperatorID: opID, Serial: "TESTA0123456789", Status: registry.StatusActive, ClassLabel: "C1"}},
		},
		tel:   &fakeTelemetry{now: now, hasNewest: true, newestAge: 2},
		inc:   &fakeIncidents{views: map[string]incidents.View{}},
		packs: &fakePacks{},
		led:   &fakeLedger{now: now, exports: map[string]Export{}},
		now:   now,
	}
	n := 0
	k.svc = &Service{Accounts: k.acc, Registry: k.reg, Telemetry: k.tel, Incidents: k.inc, Packs: k.packs, Ledger: k.led,
		Purposes: purposes, Budget: Budget{User: 5, Agency: 8, Window: time.Minute},
		Limits: Limits{LiveWindow: 30 * time.Second, AtWindow: time.Minute, HistoryMax: 90 * 24 * time.Hour, MaxBBoxDeg: 1,
			MaxAircraft: 10, MaxPositions: 3, MaxFleet: 10, DPOMaxRows: 100},
		Counters: &core.Counters{},
		NewID: func() (string, error) {
			n++
			return fmt.Sprintf("%032x", n), nil
		},
	}
	return k
}

// as is a request context of the police session of user from ip.
func as(user, ip string) context.Context {
	ctx := apiserver.WithIdentity(context.Background(), apiserver.Identity{ActorType: "user", Subject: user, Realm: apiserver.RealmPolice,
		Roles: []string{apiserver.RolePoliceQuery}, Session: true, JTI: "jti-" + user})
	return apiserver.WithRequestInfo(ctx, apiserver.RequestInfo{RemoteIP: ip})
}

func (k *kit) track(id, reg string, registryUAS *string, at time.Time, positions int) {
	r := reg
	k.tel.rows = append(k.tel.rows, reader.PoliceAircraftRow{TrackID: id, FirstSeen: at.Add(-time.Minute), LastSeen: at,
		Samples: int64(positions), Source: "direct_rid", Trust: "broadcast", IdentStatus: "registered", IdentBasis: "as_broadcast",
		Serial: &id, OperatorReg: &r, RegistryUasID: registryUAS})
	for i := range positions {
		k.tel.positions = append(k.tel.positions, reader.PolicePositionsRow{TrackID: id, CapturedAt: at.Add(time.Duration(i-positions+1) * time.Second),
			LatDeg: 41.7 + float64(i)/1000, LonDeg: 44.8, AltSource: "geodetic"})
	}
}

func ptr[T any](v T) *T { return &v }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
