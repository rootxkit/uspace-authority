package cell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy/cell"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// OwnershipKey is the key of the map in KV bucket cells.
const OwnershipKey = "ownership"

// workerPattern is a detect worker id: a subject-safe slug.
var workerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Ownership is the cell3 → detect worker map (05 §3): every cell3 named
// is judged by exactly one worker. Version rises by one with every
// change; UpdatedBy and UpdatedAt say who made the last one.
type Ownership struct {
	Version uint64 `json:"version"`
	// Assignments maps a cell3 name (c3:<lat_idx>:<lon_idx>) to the
	// worker id that owns it.
	Assignments map[string]string `json:"assignments"`
	UpdatedBy   string            `json:"updated_by"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ValidateAssignments refuses a map with a key that is not a c3 cell
// name or a worker id that is not a slug, naming each fault by its path.
func ValidateAssignments(a map[string]string) error {
	var errs []error
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		c, err := cell.Parse(k)
		if err != nil || c.Level != cell.Level3 {
			errs = append(errs, core.Fieldf("assignments."+k, "not a cell3 name (c3:<lat_idx>:<lon_idx>)"))
			continue
		}
		if !workerPattern.MatchString(a[k]) {
			errs = append(errs, core.Fieldf("assignments."+k, "worker id must match %s", workerPattern))
		}
	}
	return errors.Join(errs...)
}

// Owned is the cells worker owns, sorted.
func (o Ownership) Owned(worker string) []ID {
	var out []ID
	for k, w := range o.Assignments {
		if w != worker {
			continue
		}
		if c, err := cell.Parse(k); err == nil && c.Level == cell.Level3 {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b ID) int {
		if a.LatIdx != b.LatIdx {
			return a.LatIdx - b.LatIdx
		}
		return a.LonIdx - b.LonIdx
	})
	return out
}

// ErrNoCells is a worker the map gives no cell to, without CELLS=all.
var ErrNoCells = errors.New("no cell is assigned to this worker")

// Claim is what a worker judges: All (every cell, CELLS=all, the demo)
// or the cells the map gives it.
type Claim struct {
	All   bool
	Cells []ID
	// Version is the map's version the claim was made from (0 with All
	// and no map).
	Version uint64
}

// Owns reports whether the claim covers the cell3 c.
func (c Claim) Owns(c3 ID) bool { return c.All || slices.Contains(c.Cells, c3) }

// ClaimFor is worker's claim on o. all is CELLS=all. A worker the map
// gives nothing refuses to start (ErrNoCells) unless all: an unowned
// worker judging nothing would look like a quiet sky (E-02).
func ClaimFor(o Ownership, have bool, worker string, all bool) (Claim, error) {
	if all {
		return Claim{All: true, Version: o.Version}, nil
	}
	if !have {
		return Claim{}, fmt.Errorf("%w: no ownership map in KV cells; assign with PUT /v1/cells or set CELLS=all", ErrNoCells)
	}
	cells := o.Owned(worker)
	if len(cells) == 0 {
		return Claim{}, fmt.Errorf("%w: worker %q owns no cell in ownership map version %d; assign with PUT /v1/cells or set CELLS=all",
			ErrNoCells, worker, o.Version)
	}
	return Claim{Cells: cells, Version: o.Version}, nil
}

// Store is the map in KV bucket cells.
type Store struct {
	// Open returns the bucket (bus.OpenBucket).
	Open func(ctx context.Context) (jetstream.KeyValue, error)
	// MaxBytes is the bucket's value bound; a map that does not fit is
	// refused naming it (E-10).
	MaxBytes int
}

// ErrTooLarge is a map past the bucket's value bound.
var ErrTooLarge = errors.New("the ownership map exceeds the bucket's value bound")

// Get reads the map and its revision; have is false when there is none.
func (s Store) Get(ctx context.Context) (o Ownership, revision uint64, have bool, err error) {
	kv, err := s.Open(ctx)
	if err != nil {
		return Ownership{}, 0, false, err
	}
	e, err := kv.Get(ctx, OwnershipKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Ownership{}, 0, false, nil
	}
	if err != nil {
		return Ownership{}, 0, false, err
	}
	if err := json.Unmarshal(e.Value(), &o); err != nil {
		return Ownership{}, 0, false, fmt.Errorf("ownership map unreadable: %w", err)
	}
	return o, e.Revision(), true, nil
}

// Encode is o as stored, refused with ErrTooLarge past MaxBytes.
func (s Store) Encode(o Ownership) ([]byte, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	if s.MaxBytes > 0 && len(raw) > s.MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes, the bound is %d", ErrTooLarge, len(raw), s.MaxBytes)
	}
	return raw, nil
}

// Put writes o if the stored revision is still revision (0: no map yet),
// so two writers never overwrite each other.
func (s Store) Put(ctx context.Context, o Ownership, revision uint64) error {
	raw, err := s.Encode(o)
	if err != nil {
		return err
	}
	kv, err := s.Open(ctx)
	if err != nil {
		return err
	}
	if revision == 0 {
		_, err = kv.Create(ctx, OwnershipKey, raw)
	} else {
		_, err = kv.Update(ctx, OwnershipKey, raw, revision)
	}
	return err
}

// LoadClaim reads the map (trying attempts times with a doubling backoff
// while the bus is unreachable) and returns worker's claim. With all
// (CELLS=all) nothing is read. A map that cannot be read after the
// attempts is an error: a worker that cannot know its cells does not
// guess them.
func LoadClaim(ctx context.Context, s Store, worker string, all bool, attempts int, backoff time.Duration) (Claim, error) {
	if all {
		return ClaimFor(Ownership{}, false, worker, true)
	}
	var last error
	for i := 1; i <= max(attempts, 1); i++ {
		o, _, have, err := s.Get(ctx)
		if err == nil {
			return ClaimFor(o, have, worker, false)
		}
		last = err
		if i < attempts {
			select {
			case <-ctx.Done():
				return Claim{}, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return Claim{}, fmt.Errorf("cell ownership map unreadable after %d attempts: %w", max(attempts, 1), last)
}

// StoreOf is the map's store on a process's bus: the bucket cells as
// the topology configures it, created when api has not provisioned it.
func StoreOf(bp *bus.Process) Store {
	cfg, _ := bp.Topology.Bucket(bus.BucketCells)
	return Store{
		Open:     func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, cfg) },
		MaxBytes: int(cfg.MaxValueSize),
	}
}
