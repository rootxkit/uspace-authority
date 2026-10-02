package dp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/timeplace"
	"github.com/rootxkit/uspace-core/vectors"
)

// The knowledge vectors through this package's adapters: the wire shape
// (an F3411 response and its flight's state; a flight's details) is
// mapped onto core's input by the adapter and its output compared with
// the vector. Nothing here re-implements the judgement.

// rid_time.json's network cases: a GET /uss/flights response stamped
// response_timestamp, received at received_at, carrying a state stamped
// state_timestamp, through Map; expected null is a state not published.
//
// Spec gap (WP-14 PR): the file names only "ussp" as the owner of the
// network cases, although the authority's Display Provider places
// network states by the same rule (02 F7), so RunOwned("authority")
// finds none of them. They are run here by their input shape until the
// lab adds "authority" to their owners; the direct cases owned by the
// authority run through RunOwned in internal/ridpipe.
func TestVectorsRIDTimeNetworkCasesThroughMap(t *testing.T) {
	f := vectors.Load(t, "rid_time.json")
	ran := 0
	for _, c := range f.Cases {
		if !hasMember(c.Input, "state_timestamp") {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			t.Logf("why: %s", c.Why)
			var in struct {
				StateTimestamp    time.Time  `json:"state_timestamp"`
				ResponseTimestamp *time.Time `json:"response_timestamp"`
				ReceivedAt        time.Time  `json:"received_at"`
				MaxAgeS           float64    `json:"max_age_s"`
				TimeToleranceS    float64    `json:"time_tolerance_s"`
				MaxLatencyS       float64    `json:"max_latency_s"`
			}
			c.Decode(t, &in, nil)
			pol := timeplace.NetworkPolicy{MaxAgeS: in.MaxAgeS, ToleranceS: in.TimeToleranceS, MaxLatencyS: in.MaxLatencyS}
			fl := flight("fl-1", state(in.StateTimestamp, baseLatDeg, baseLonDeg))
			m, ok := Map(&Input{USSID: "ussp-lab-01", Flight: &fl, ResponseTS: in.ResponseTimestamp, RxTS: in.ReceivedAt}, MapDeps{Network: pol})
			if c.ExpectedIsNull() {
				if ok {
					t.Fatalf("published at %v; the vector says not shown", m.Times.CapturedAt)
				}
				return
			}
			var exp struct {
				TS         time.Time `json:"ts"`
				CapturedAt time.Time `json:"captured_at"`
				TimeSource string    `json:"time_source"`
				Note       *string   `json:"note"`
			}
			c.Decode(t, nil, &exp)
			if !ok {
				t.Fatal("not published")
			}
			if m.Times.TS == nil || !m.Times.TS.Equal(exp.TS) || !m.Times.CapturedAt.Equal(exp.CapturedAt) || string(m.Times.Source) != exp.TimeSource {
				t.Fatalf("ts %v captured_at %v source %s, want %v %v %s", m.Times.TS, m.Times.CapturedAt, m.Times.Source, exp.TS, exp.CapturedAt, exp.TimeSource)
			}
			if m.Message.CapturedAt != stampOf(exp.CapturedAt) {
				t.Fatalf("message captured_at %s", m.Message.CapturedAt)
			}
		})
	}
	if ran != 7 {
		t.Fatalf("%d network cases, want 7", ran)
	}
}

func stampOf(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// hasMember reports whether the JSON object raw has the member name.
func hasMember(raw []byte, name string) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[name]
	return ok
}

// identification_status.json's broadcast cases: the case's serial and
// operator id as an F3411 flight's details (uas_id.serial_number,
// operator_id), through Identify; the vector's status, reason, serial,
// numbers, mismatch and registry id, on the provider basis.
func TestVectorsIdentificationStatusThroughTheDetails(t *testing.T) {
	f := vectors.Load(t, "identification_status.json")
	var fx struct {
		Registry vecRegistry `json:"registry"`
	}
	vectors.Unmarshal(t, f.Fixtures, &fx)
	ran := map[string]int{}
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			Kind             string       `json:"kind"`
			Serial           *string      `json:"serial"`
			OperatorReg      *string      `json:"operator_reg"`
			RegistryOverride *vecRegistry `json:"registry_override"`
			RemoteID         any          `json:"remote_id"`
			DroneID          *string      `json:"drone_id"`
		}
		var exp struct {
			Status                string  `json:"status"`
			Reason                string  `json:"reason"`
			Serial                *string `json:"serial"`
			OperatorReg           *string `json:"operator_reg"`
			Mismatch              bool    `json:"mismatch"`
			RegisteredOperatorReg *string `json:"registered_operator_reg"`
			DroneID               *string `json:"drone_id"`
		}
		c.Decode(t, &in, &exp)
		if in.Kind != "broadcast" {
			ran[in.Kind+" (skipped)"]++
			t.Skipf("kind %s: not a Service Provider's details (direct Remote ID or a binding, run elsewhere or not the authority's)", in.Kind)
		}
		ran[in.Kind]++
		reg := fx.Registry
		if in.RegistryOverride != nil {
			reg = *in.RegistryOverride
		}
		d := &f3411.RIDFlightDetails{Id: "fl-1", UasId: &f3411.UASID{SerialNumber: in.Serial}, OperatorId: in.OperatorReg}
		id := Identify(reg.snapshot(), d)
		if string(id.Status) != exp.Status || string(id.Reason) != exp.Reason {
			t.Errorf("%s/%s, want %s/%s", id.Status, id.Reason, exp.Status, exp.Reason)
		}
		vectors.EqualStrPtr(t, "serial", id.Serial, exp.Serial)
		vectors.EqualStrPtr(t, "operator_reg", id.OperatorReg, exp.OperatorReg)
		vectors.EqualStrPtr(t, "registered_operator_reg", id.RegisteredOperatorReg, exp.RegisteredOperatorReg)
		vectors.EqualStrPtr(t, "drone_id", id.RegistryUASID, exp.DroneID)
		if id.Mismatch != exp.Mismatch {
			t.Errorf("mismatch %v, want %v", id.Mismatch, exp.Mismatch)
		}
		if id.Basis != "provider" {
			t.Errorf("basis %s, want provider (Q-A8)", id.Basis)
		}
	})
	if ran["broadcast"] != 29 {
		t.Errorf("ran %v, want 29 broadcast cases", ran)
	}
}

type vecRegistry struct {
	Operators []struct {
		OperatorID         string `json:"operator_id"`
		RegistrationNumber string `json:"registration_number"`
		Status             string `json:"status"`
	} `json:"operators"`
	UAS []struct {
		DroneID            string  `json:"drone_id"`
		Label              string  `json:"label"`
		Serial             string  `json:"serial"`
		RegistrationStatus string  `json:"registration_status"`
		UASOperatorID      *string `json:"uas_operator_id"`
		InRegistry         bool    `json:"in_registry"`
	} `json:"uas"`
	Notes []string `json:"notes"`
}

func (r vecRegistry) snapshot() *identify.Snapshot {
	ops := make([]identify.OperatorFacts, 0, len(r.Operators))
	for _, o := range r.Operators {
		ops = append(ops, identify.OperatorFacts{OperatorID: o.OperatorID, RegistrationNumber: o.RegistrationNumber, Status: o.Status})
	}
	uas := make([]identify.UASFacts, 0, len(r.UAS))
	for _, u := range r.UAS {
		uas = append(uas, identify.UASFacts{DroneID: u.DroneID, Label: u.Label, Serial: u.Serial,
			RegistrationStatus: u.RegistrationStatus, OperatorID: u.UASOperatorID, InRegistry: u.InRegistry})
	}
	return identify.NewSnapshot(ops, uas)
}
