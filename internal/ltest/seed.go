package ltest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/serial"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

// Zone is a square geo-zone or U-space airspace a scenario publishes.
type Zone struct {
	// Dataset is "zones" (empty) or "uspace_airspace".
	Dataset string `json:"dataset,omitempty"`
	// ID is the ED-318 identifier (the zone_id is GEO/<ID>).
	ID string `json:"id"`
	// Type is the ED-318 type: PROHIBITED, REQ_AUTHORISATION,
	// CONDITIONAL, USPACE, ...
	Type string `json:"type"`
	// LatDeg, LonDeg is the centre and HalfSideDeg half the side, in
	// degrees of latitude and longitude.
	LatDeg      float64 `json:"lat_deg"`
	LonDeg      float64 `json:"lon_deg"`
	HalfSideDeg float64 `json:"half_side_deg"`
	// Lower and Upper are the vertical limits in metres over their
	// references (AMSL, AGL, WGS84; AMSL when empty).
	LowerM   float64 `json:"lower_m"`
	UpperM   float64 `json:"upper_m"`
	LowerRef string  `json:"lower_ref,omitempty"`
	UpperRef string  `json:"upper_ref,omitempty"`
	// ValidFrom and ValidTo bound the version in force (from an hour
	// ago to a day ahead when zero).
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
	// Version is the zone version (1 when 0).
	Version int `json:"version,omitempty"`
}

// ZoneID is the zone_id a violation names (country/identifier).
func (z Zone) ZoneID() string { return "GEO/" + z.ID }

func (z Zone) dataset() zonesvc.Dataset {
	if z.Dataset == string(zonesvc.DatasetUSpace) {
		return zonesvc.DatasetUSpace
	}
	return zonesvc.DatasetZones
}

func ref(r string) string {
	if r == "" {
		return "AMSL"
	}
	return r
}

// Feature is the zone as an ED-318 feature, checked by uspace-core's
// ed318.Parse (the parser detect's projection reader uses).
func (z Zone) Feature() (json.RawMessage, error) {
	d := z.HalfSideDeg
	ring := fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`,
		z.LonDeg-d, z.LatDeg-d, z.LonDeg+d, z.LatDeg-d, z.LonDeg+d, z.LatDeg+d, z.LonDeg-d, z.LatDeg+d, z.LonDeg-d, z.LatDeg-d)
	reason := "SENSITIVE"
	if z.Type == "USPACE" {
		reason = "OTHER"
	}
	f := fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":%s,"layer":{"lower":%g,"lowerReference":%q,"upper":%g,"upperReference":%q,"uom":"m"}},"properties":{"identifier":%q,"country":"GEO","name":[{"text":%q,"lang":"en-GB"}],"type":%q,"variant":"COMMON","reason":[%q],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`,
		ring, z.LowerM, ref(z.LowerRef), z.UpperM, ref(z.UpperRef), z.ID, "Scenario zone "+z.ID, z.Type, reason)
	if _, probs := ed318.Parse([]byte(`{"type":"FeatureCollection","features":[`+f+`]}`), ed318.Limits{}); probs != nil {
		return nil, fmt.Errorf("zone %s: %w", z.ID, probs)
	}
	return json.RawMessage(f), nil
}

// PublishZones makes the zones projection hold exactly zs, as api's
// projector writes it (internal/zonesvc TSProjection, one telemetry
// transaction), then announces the new zones version on KV
// zones_version and zones.v1.changed.
func (s *Stack) PublishZones(zs ...Zone) {
	s.T.Helper()
	now := time.Now().UTC()
	rows := make([]zonesvc.ProjectedZone, 0, len(zs))
	for i := range zs {
		z := &zs[i]
		f, err := z.Feature()
		if err != nil {
			s.T.Fatalf("ltest: %v", err)
		}
		from, to := z.ValidFrom, z.ValidTo
		if from.IsZero() {
			from = now.Add(-time.Hour)
		}
		if to.IsZero() {
			to = now.Add(24 * time.Hour)
		}
		v := z.Version
		if v == 0 {
			v = 1
		}
		d := z.HalfSideDeg
		rows = append(rows, zonesvc.ProjectedZone{Dataset: z.dataset(), Identifier: z.ID, ZoneVersion: v, Feature: f,
			ValidFrom: from, ValidTo: to, Type: z.Type,
			BBox: zonesvc.BBox{MinLatDeg: z.LatDeg - d, MinLonDeg: z.LonDeg - d, MaxLatDeg: z.LatDeg + d, MaxLonDeg: z.LonDeg + d}})
	}
	s.mu.Lock()
	s.zonesVer++
	ver := s.zonesVer
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := (zonesvc.TSProjection{P: s.projector()}).Replace(ctx, rows, now, ver); err != nil {
		s.T.Fatalf("ltest: zones projection: %v", err)
	}
	if err := zonesvc.NewBusPublisher(s.BP, 5*time.Second).PublishZonesVersion(ctx, ver); err != nil {
		s.T.Fatalf("ltest: zones version: %v", err)
	}
}

// Operator is a registry operator as projected.
type Operator struct {
	ID                 string `json:"id"`
	RegistrationNumber string `json:"registration_number"`
	Status             string `json:"status"`
}

// UAS is a registry aircraft as projected.
type UAS struct {
	ID         string `json:"id"`
	Serial     string `json:"serial"`
	Status     string `json:"status"`
	OperatorID string `json:"operator_id"`
	Label      string `json:"label,omitempty"`
}

// SeedRegistry writes operators and aircraft to the registry projection
// as api's projector does (internal/registry TSProjection), each row at
// a new registry version, and announces registry.v1.changed.
func (s *Stack) SeedRegistry(ops []Operator, uas []UAS) {
	s.T.Helper()
	for _, o := range ops {
		if !strings.HasPrefix(o.RegistrationNumber, "GEO") || !strings.Contains(o.RegistrationNumber, "TEST") {
			s.T.Fatalf("ltest: operator %s: fixtures use GEO...TEST numbers (CLAUDE.md rule 11), not %q", o.ID, o.RegistrationNumber)
		}
	}
	for _, u := range uas {
		if !strings.HasPrefix(u.Serial, "TEST") {
			s.T.Fatalf("ltest: aircraft %s: fixtures use TEST serials (CLAUDE.md rule 11), not %q", u.ID, u.Serial)
		}
	}
	s.mu.Lock()
	s.regVer++
	ver := s.regVer
	s.mu.Unlock()
	pops := make([]registry.ProjectedOperator, 0, len(ops))
	for _, o := range ops {
		pops = append(pops, registry.ProjectedOperator{OperatorID: o.ID, RegistrationNumber: o.RegistrationNumber, Status: o.Status, Version: ver})
	}
	puas := make([]registry.ProjectedUAS, 0, len(uas))
	for _, u := range uas {
		puas = append(puas, registry.ProjectedUAS{UASID: u.ID, Label: u.Label, Serial: u.Serial, SerialFold: serial.FoldKey(u.Serial),
			Status: u.Status, OperatorID: u.OperatorID, Version: ver})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := (registry.TSProjection{P: s.projector()}).Begin(ctx)
	if err != nil {
		s.T.Fatalf("ltest: registry projection: %v", err)
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	if err := tx.UpsertOperators(ctx, pops, now, false); err != nil {
		s.T.Fatalf("ltest: registry projection: %v", err)
	}
	if err := tx.UpsertUAS(ctx, puas, now, false); err != nil {
		s.T.Fatalf("ltest: registry projection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		s.T.Fatalf("ltest: registry projection: %v", err)
	}
	// After the commit (never before: a reader told to re-read must
	// find the rows).
	if err := s.BP.NC.Publish(bus.SubjectRegistryChanged, fmt.Appendf(nil, `{"registry_version":%d}`, ver)); err != nil {
		s.T.Fatalf("ltest: registry.v1.changed: %v", err)
	}
}

// Seed is a scenario file: the registry and the zones a scenario starts
// with (internal/ltest/scenarios/testdata/*.json).
type Seed struct {
	Operators []Operator `json:"operators"`
	UAS       []UAS      `json:"uas"`
	Zones     []Zone     `json:"zones"`
}

// LoadSeed reads a scenario file, refusing an unknown member.
func LoadSeed(path string) (Seed, error) {
	var sd Seed
	raw, err := os.ReadFile(path) //nolint:gosec // a scenario's own testdata file, named by the test
	if err != nil {
		return sd, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sd); err != nil {
		return sd, fmt.Errorf("%s: %w", path, err)
	}
	return sd, nil
}

// Seed applies a scenario file and returns it.
func (s *Stack) Seed(path string) Seed {
	s.T.Helper()
	sd, err := LoadSeed(path)
	if err != nil {
		s.T.Fatalf("ltest: seed: %v", err)
	}
	if len(sd.Operators) > 0 || len(sd.UAS) > 0 {
		s.SeedRegistry(sd.Operators, sd.UAS)
	}
	if len(sd.Zones) > 0 {
		s.PublishZones(sd.Zones...)
	}
	s.Note("seed", path)
	return sd
}

// ZoneByID is the seed's zone id, failing the test without one.
func (s *Stack) ZoneByID(sd Seed, id string) Zone {
	s.T.Helper()
	for i := range sd.Zones {
		if sd.Zones[i].ID == id {
			return sd.Zones[i]
		}
	}
	s.T.Fatalf("ltest: no zone %s in the seed", id)
	return Zone{}
}
