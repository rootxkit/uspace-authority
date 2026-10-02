package registry

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
)

func resolve(t *testing.T, r *ProjectionReader, sn, operator string) core.Identification {
	t.Helper()
	return identify.ResolveBroadcast(r.Lookup(), &sn, &operator)
}

func newReader(f *fixture) *ProjectionReader {
	return &ProjectionReader{Source: f.proj, Counters: &core.Counters{}, Now: func() time.Time { return f.now }}
}

// G-08 presence: every change writes its projection rows with it, and a
// resolver reading the projection judges the new state (registered,
// then suspended, then reinstated).
func TestAChangeIsProjectedWithIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, serialC1, "C1")
	if p := f.proj.operators[op.ID]; p.RegistrationNumber != numberA || p.Status != "active" || p.Version != op.RegistryVersion {
		t.Fatalf("operator row %+v", p)
	}
	if p := f.proj.uas[u.ID]; p.Serial != serialC1 || p.SerialFold != serialC1 || p.OperatorID != op.ID || !f.proj.inReg[u.ID] {
		t.Fatalf("aircraft row %+v", p)
	}
	r := newReader(f)
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("before: %+v", id)
	}
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar); err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentSuspended || id.Reason != core.ReasonUASSuspended {
		t.Fatalf("after the suspension: %+v", id)
	}
	if _, err := f.svc.SetOperatorStatus(ctx, op.ID, StatusSuspended, "insurance", registrar); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusActive, "", registrar); err != nil {
		t.Fatal(err)
	}
	_ = r.Refresh(ctx)
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentSuspended || id.Reason != core.ReasonOperatorSuspended {
		t.Fatalf("owner suspended: %+v", id)
	}
	if _, err := f.svc.SetOperatorStatus(ctx, op.ID, StatusActive, "", registrar); err != nil {
		t.Fatal(err)
	}
	_ = r.Refresh(ctx)
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("reinstated: %+v", id)
	}
	if r.Version() != f.store.version {
		t.Errorf("reader version %d, registry %d", r.Version(), f.store.version)
	}
}

// An expired registration is projected as expired, which identification
// does not recognise as in good standing: the aircraft of an expired
// operator is never registered (fail safe, G-03).
func TestAnExpiredOwnerIsNeverRegistered(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	f.uas(t, op.ID, serialC1, "C1")
	f.now = op.ValidUntil.Add(time.Second)
	if _, err := f.svc.ExpireDue(ctx); err != nil {
		t.Fatal(err)
	}
	r := newReader(f)
	_ = r.Refresh(ctx)
	if id := resolve(t, r, serialC1, numberA); id.Status == core.IdentRegistered || id.Reason != core.ReasonOwnerUnknown {
		t.Fatalf("expired owner: %+v", id)
	}
}

// SC-17 step 3 (absence beside presence): a projection write that fails
// at any point rolls the change back whole — no row, no event, no feed
// entry — and is a 503 naming the cause, counted. The same change with
// the projection reachable is applied (the presence twin above).
func TestAFailedProjectionWriteRollsTheChangeBack(t *testing.T) {
	for _, point := range []string{"begin", "write", "commit"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			op := f.operator(t, naturalOperator(numberA))
			u := f.uas(t, op.ID, serialC1, "C1")
			events, changes := len(f.store.events), len(f.store.changes)
			switch point {
			case "begin":
				f.proj.failBegin = true
			case "write":
				f.proj.failUAS = true
			case "commit":
				f.proj.failCommit = true
			}
			_, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar)
			wantProblem(t, err, http.StatusServiceUnavailable, "")
			if !errors.Is(err, ErrProjection) || problemOf(err).Slug() != SlugProjection {
				t.Fatalf("not a projection refusal: %v", err)
			}
			if f.store.uas[u.ID].Status != StatusActive || len(f.store.events) != events || len(f.store.changes) != changes {
				t.Fatal("the change was half applied")
			}
			if f.proj.uas[u.ID].Status != string(StatusActive) {
				t.Fatal("the projection moved without the registry")
			}
			if f.svc.Counters.Get(CounterProjectionWriteFailed) != 1 {
				t.Errorf("not counted: %v", f.svc.Counters.Snapshot())
			}
			f.proj.failBegin, f.proj.failUAS, f.proj.failCommit = false, false, false
			if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}

// The window G-08 leaves: the projection committed and the relational
// commit then failed. The projection is ahead of the registry (here a
// reinstatement the registry never committed: the unsafe direction), so
// a repair is requested at once and counted, and the repair writes the
// registry's state over the newer row.
func TestARelationalCommitFailureAfterTheProjectionRequestsARepair(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, serialC1, "C1")
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar); err != nil {
		t.Fatal(err)
	}
	f.store.failCommit = true
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusActive, "", registrar); err == nil {
		t.Fatal("a failed commit reported success")
	}
	f.store.failCommit = false
	if f.svc.Counters.Get(CounterProjectionAhead) != 1 {
		t.Fatalf("not counted: %v", f.svc.Counters.Snapshot())
	}
	select {
	case <-f.svc.repairs():
	default:
		t.Fatal("no repair requested")
	}
	if f.proj.uas[u.ID].Status != string(StatusActive) || f.store.uas[u.ID].Status != StatusSuspended {
		t.Fatal("the projection did not run ahead (the premise)")
	}
	if _, err := f.svc.Reproject(ctx); err != nil {
		t.Fatal(err)
	}
	if p := f.proj.uas[u.ID]; p.Status != string(StatusSuspended) || p.Version != f.store.uas[u.ID].RegistryVersion {
		t.Fatalf("the repair left the projection ahead: %+v", p)
	}
}

// SC-17 step 4: a projection row deleted by hand is restored by the full
// re-projection; rows the registry does not hold are marked, never
// deleted; a held job lock skips the run; a failed run is counted.
func TestReprojectionRepairsAndMarks(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, serialC1, "C1")
	delete(f.proj.uas, u.ID)
	f.proj.uas["orphan"] = ProjectedUAS{UASID: "orphan", Serial: "TEST-ORPHAN", SerialFold: "TEST-ORPHAN", Status: "active", Version: 1}
	f.proj.inReg["orphan"] = true
	f.proj.operators["ghost"] = ProjectedOperator{OperatorID: "ghost", RegistrationNumber: "GEOGHOST0000001", Status: "active", Version: 1}

	r, err := f.svc.Reproject(ctx)
	if err != nil || !r.Ran || r.Operators != 1 || r.UAS != 1 || r.Marked != 2 {
		t.Fatalf("reprojected %+v %v", r, err)
	}
	if _, ok := f.proj.uas[u.ID]; !ok {
		t.Fatal("deleted row not restored")
	}
	if _, ok := f.proj.uas["orphan"]; !ok || f.proj.inReg["orphan"] {
		t.Fatal("orphan deleted or still in the registry")
	}
	if f.proj.operators["ghost"].Status != StatusUnregistered {
		t.Fatal("ghost operator not marked")
	}
	reader := newReader(f)
	_ = reader.Refresh(ctx)
	if id := resolve(t, reader, "TEST-ORPHAN", "GEOGHOST0000001"); id.Reason != core.ReasonNotInRegistry {
		t.Fatalf("orphan resolves as %+v", id)
	}
	if id := resolve(t, reader, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("restored aircraft resolves as %+v", id)
	}
	if f.svc.Counters.Get(CounterReprojected) != 1 || f.svc.Counters.Get(CounterProjectionMarked) != 2 {
		t.Errorf("counters %v", f.svc.Counters.Snapshot())
	}
	// A second run marks nothing more.
	if r, _ := f.svc.Reproject(ctx); r.Marked != 0 {
		t.Fatalf("marked again: %+v", r)
	}

	f.store.lockHeld = true
	if r, err := f.svc.Reproject(ctx); err != nil || r.Ran || f.svc.Counters.Get(CounterReprojectSkipped) != 1 {
		t.Fatalf("ran without the job lock: %+v %v", r, err)
	}
	f.store.lockHeld = false
	for _, fail := range []func(){
		func() { f.store.failFacts = true },
		func() { f.store.failFacts, f.proj.failBegin = false, true },
		func() { f.proj.failBegin, f.proj.failUAS = false, true },
		func() { f.proj.failUAS, f.proj.failCommit = false, true },
	} {
		fail()
		if _, err := f.svc.Reproject(ctx); err == nil {
			t.Fatal("failed run reported success")
		}
	}
	if f.svc.Counters.Get(CounterReprojectFailed) != 4 {
		t.Errorf("failures counted %d", f.svc.Counters.Get(CounterReprojectFailed))
	}
}

// The re-projection takes LockProjection, the lock every change takes,
// after its job lock (SC-17 step 5: a change waits for it).
func TestReprojectionHoldsTheChangeLock(t *testing.T) {
	f := newFixture(t)
	f.store.locks = nil
	if _, err := f.svc.Reproject(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.store.locks) != 2 || f.store.locks[0] != LockReprojectJob || f.store.locks[1] != LockProjection {
		t.Fatalf("locks %v", f.store.locks)
	}
	f.store.locks = nil
	f.operator(t, naturalOperator(numberA))
	if len(f.store.locks) != 1 || f.store.locks[0] != LockProjection {
		t.Fatalf("change locks %v", f.store.locks)
	}
}

type recordingPublisher struct {
	versions []int64
	err      error
}

func (p *recordingPublisher) PublishRegistryVersion(_ context.Context, v int64) error {
	p.versions = append(p.versions, v)
	return p.err
}

// After a commit the version is published; a failed publish does not
// undo the change (readers re-read every 5 s) and is counted. Pilot
// changes project nothing and publish nothing.
func TestAChangeIsPublishedAfterItsCommit(t *testing.T) {
	f := newFixture(t)
	pub := &recordingPublisher{}
	f.svc.Publisher = pub
	op := f.operator(t, naturalOperator(numberA))
	if len(pub.versions) != 1 || pub.versions[0] != op.RegistryVersion {
		t.Fatalf("published %v", pub.versions)
	}
	pub.err = errInjected
	if _, err := f.svc.SetOperatorStatus(context.Background(), op.ID, StatusSuspended, "x", registrar); err != nil {
		t.Fatal(err)
	}
	if f.store.operators[op.ID].Status != StatusSuspended || f.svc.Counters.Get(CounterPublishFailed) != 1 {
		t.Fatal("publish failure undid the change or was not counted")
	}
	before := len(pub.versions)
	if _, err := f.svc.CreatePilot(context.Background(), NewPilot{PersonRef: "01001012345", Name: "P"}, registrar); err != nil {
		t.Fatal(err)
	}
	if len(pub.versions) != before {
		t.Fatal("a pilot change was published")
	}
	if err := (NopPublisher{}).PublishRegistryVersion(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}

// RunJobs re-projects at start, on request and periodically, and stops
// with its context.
func TestRunJobsReprojectsAtStartAndOnRepair(t *testing.T) {
	f := newFixture(t)
	f.operator(t, naturalOperator(numberA))
	clear(f.proj.operators)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.svc.RunJobs(ctx, time.Hour, time.Hour) }()
	waitFor(t, func() bool { return f.svc.Counters.Get(CounterReprojected) >= 1 })
	f.proj.mu.Lock()
	n := len(f.proj.operators)
	f.proj.mu.Unlock()
	if n != 1 {
		t.Fatalf("startup run restored %d operators", n)
	}
	f.svc.RequestRepair()
	waitFor(t, func() bool { return f.svc.Counters.Get(CounterReprojected) >= 2 })
	cancel()
	<-done
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in 5 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
