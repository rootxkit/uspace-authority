package receivers

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Owners of a receiver. The authority's name is configuration (spec 06
// §4), so its own receivers are "authority", not a name.
const (
	OwnerAuthority  = "authority"
	OwnerThirdParty = "third_party"
)

// Position is a reported or last-known position.
type Position struct {
	LatDeg  float64  `json:"lat_deg"`
	LonDeg  float64  `json:"lon_deg"`
	AltHAEM *float64 `json:"alt_hae_m,omitempty"`
}

// Receiver is one registry row without its key material.
type Receiver struct {
	ID                    string
	Name                  string
	LatDeg, LonDeg        float64
	Owner                 string
	OwnerName             *string
	Status                string
	DisabledBy            *string
	DisabledReason        *string
	DisabledAt            *time.Time
	KeyGeneration         int
	PreviousKeyValidUntil *time.Time
	LastSeenAt            *time.Time
	LastPosition          *Position
	PositionDeviationM    *float64
	PositionDeviations    int64
	Firmware              *string
	Config                Config
	Version               int64
	CreatedAt, UpdatedAt  time.Time
	CreatedBy, UpdatedBy  string
}

// row is one rid_receivers row; every query's row type has its columns.
type row = gen.ReceiverByIDRow

func receiverFrom(r *row) (Receiver, error) {
	var cfg Config
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return Receiver{}, err
	}
	out := Receiver{
		ID: r.ID, Name: r.Name, LatDeg: r.LatDeg, LonDeg: r.LonDeg, Owner: r.Owner, OwnerName: r.OwnerName,
		Status: r.Status, DisabledBy: r.DisabledBy, DisabledReason: r.DisabledReason, DisabledAt: r.DisabledAt,
		KeyGeneration: int(r.KeyGeneration), PreviousKeyValidUntil: r.PrevValidUntil, LastSeenAt: r.LastSeenAt,
		PositionDeviationM: r.PositionDeviationM, PositionDeviations: r.PositionDeviations, Firmware: r.Firmware,
		Config: cfg, Version: r.Version, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy,
	}
	if r.LastLatDeg != nil && r.LastLonDeg != nil {
		out.LastPosition = &Position{LatDeg: *r.LastLatDeg, LonDeg: *r.LastLonDeg, AltHAEM: r.LastAltHaeM}
	}
	return out, nil
}

// NewReceiver is what an admin registers.
type NewReceiver struct {
	ID             string
	Name           string
	LatDeg, LonDeg float64
	Owner          string
	OwnerName      *string
	Config         Config
}

// Patch is a change of a receiver's details; nil members are unchanged.
type Patch struct {
	Name           *string
	LatDeg, LonDeg *float64
	Owner          *string
	OwnerName      *string
	Config         *Config
}

func validName(name string) bool { return name != "" && len(name) <= 200 }

func validOwner(owner string) bool { return owner == OwnerAuthority || owner == OwnerThirdParty }

// validPosition refuses a non-finite or out-of-range pinned position.
func validPosition(lat, lon float64) bool {
	return (core.LatLon{LatDeg: lat, LonDeg: lon}).Valid()
}

// Validate refuses an invalid registration, naming every field.
func (n NewReceiver) Validate() error {
	var errs []error
	if !ValidID(n.ID) {
		errs = append(errs, core.Fieldf("id", "must match ^[a-z0-9][a-z0-9-]{1,62}$"))
	}
	if !validName(n.Name) {
		errs = append(errs, core.Fieldf("label", "1 to 200 characters"))
	}
	if !validPosition(n.LatDeg, n.LonDeg) {
		errs = append(errs, core.Fieldf("lat_deg", "the pinned position is not a valid WGS84 position"))
	}
	if !validOwner(n.Owner) {
		errs = append(errs, core.Fieldf("owner", "must be authority or third_party"))
	}
	if n.OwnerName != nil && len(*n.OwnerName) > 200 {
		errs = append(errs, core.Fieldf("owner_name", "at most 200 characters"))
	}
	if err := n.Config.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
