package registry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/regnum"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// The vectors run through this repository's adapters; the judgement is
// uspace-core's (CLAUDE.md, knowledge vectors). identification_status:
// the fixture registry becomes projection rows (reader.ProjRegistry*),
// the rows reach a ProjectionReader through toLoaded, the mapping
// TSSource uses, and the reader's Lookup is what core resolves against.

type vecOperator struct {
	OperatorID         string `json:"operator_id"`
	RegistrationNumber string `json:"registration_number"`
	Status             string `json:"status"`
}

type vecUAS struct {
	DroneID            string  `json:"drone_id"`
	Label              string  `json:"label"`
	Serial             string  `json:"serial"`
	RegistrationStatus string  `json:"registration_status"`
	UASOperatorID      *string `json:"uas_operator_id"`
	InRegistry         bool    `json:"in_registry"`
}

type vecRegistry struct {
	Operators []vecOperator `json:"operators"`
	UAS       []vecUAS      `json:"uas"`
	Notes     []string      `json:"notes"`
}

// staticSource serves fixed projection rows.
type staticSource struct {
	ops []reader.ProjRegistryOperator
	uas []reader.ProjRegistryUAS
}

func (s staticSource) LoadProjection(context.Context) (Loaded, error) {
	return toLoaded(s.ops, s.uas), nil
}

// projectionOf writes the vector registry as projection rows and reads
// them back through a ProjectionReader.
func projectionOf(t *testing.T, r vecRegistry) identify.Lookup {
	t.Helper()
	var src staticSource
	for i, o := range r.Operators {
		src.ops = append(src.ops, reader.ProjRegistryOperator{
			OperatorID: o.OperatorID, RegistrationNumberPublic: o.RegistrationNumber, Status: o.Status, RegistryVersion: int64(i + 1),
		})
	}
	for i, u := range r.UAS {
		src.uas = append(src.uas, reader.ProjRegistryUAS{
			UasID: u.DroneID, Label: u.Label, Serial: u.Serial, RegistrationStatus: u.RegistrationStatus,
			OperatorID: u.UASOperatorID, InRegistry: u.InRegistry, RegistryVersion: int64(i + 1),
		})
	}
	pr := &ProjectionReader{Source: src}
	if err := pr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return pr.Lookup()
}

type vecRemoteID struct {
	Identified bool    `json:"identified"`
	UAID       string  `json:"ua_id"`
	IDType     uint8   `json:"id_type"`
	OperatorID *string `json:"operator_id"`
}

type vecIdentInput struct {
	Kind             string       `json:"kind"`
	Serial           *string      `json:"serial"`
	OperatorReg      *string      `json:"operator_reg"`
	RegistryOverride *vecRegistry `json:"registry_override"`
	RemoteID         *vecRemoteID `json:"remote_id"`
	DroneID          *string      `json:"drone_id"`
}

type vecIdentExpected struct {
	Status                string  `json:"status"`
	Reason                string  `json:"reason"`
	Serial                *string `json:"serial"`
	OperatorReg           *string `json:"operator_reg"`
	Mismatch              bool    `json:"mismatch"`
	RegisteredOperatorReg *string `json:"registered_operator_reg"`
	DroneID               *string `json:"drone_id"`
}

func TestVectorsIdentificationStatusThroughTheProjection(t *testing.T) {
	f := vectors.Load(t, "identification_status.json")
	var fx struct {
		Registry vecRegistry `json:"registry"`
	}
	vectors.Unmarshal(t, f.Fixtures, &fx)
	fixture := projectionOf(t, fx.Registry)
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vecIdentInput
		var exp vecIdentExpected
		c.Decode(t, &in, &exp)
		reg := fixture
		if in.RegistryOverride != nil {
			reg = projectionOf(t, *in.RegistryOverride)
		}
		var got core.Identification
		switch in.Kind {
		case "broadcast":
			got = identify.ResolveBroadcast(reg, in.Serial, in.OperatorReg)
		case "remote_id_block":
			got = identify.ResolveRemoteID(reg, identify.RemoteIDIdentity{
				Identified: in.RemoteID.Identified, UAID: in.RemoteID.UAID,
				IDType: odid.IDType(in.RemoteID.IDType), OperatorID: in.RemoteID.OperatorID,
			})
		case "serial_conflict":
			got = identify.SerialConflict(*in.Serial, in.OperatorReg)
		default:
			t.Fatalf("kind %q is not the authority's (D6: no bound tracks here)", in.Kind)
		}
		if got.Status != core.IdentStatus(exp.Status) || got.Reason != core.IdentReason(exp.Reason) {
			t.Errorf("%s/%s, want %s/%s", got.Status, got.Reason, exp.Status, exp.Reason)
		}
		vectors.EqualStrPtr(t, "serial", got.Serial, exp.Serial)
		vectors.EqualStrPtr(t, "operator_reg", got.OperatorReg, exp.OperatorReg)
		vectors.EqualStrPtr(t, "registered_operator_reg", got.RegisteredOperatorReg, exp.RegisteredOperatorReg)
		vectors.EqualStrPtr(t, "drone_id", got.RegistryUASID, exp.DroneID)
		if got.Mismatch != exp.Mismatch {
			t.Errorf("mismatch %v, want %v", got.Mismatch, exp.Mismatch)
		}
	})
}

type vecSerialInput struct {
	Kind       string  `json:"kind"`
	Serial     *string `json:"serial"`
	ClassLabel *string `json:"class_label"`
	Value      string  `json:"value"`
	Pattern    string  `json:"pattern"`
}

type vecSerialExpected struct {
	Valid           *bool   `json:"valid"`
	Problem         *string `json:"problem"`
	ProblemContains string  `json:"problem_contains"`
	Public          string  `json:"public"`
	CompareKey      string  `json:"compare_key"`
	FoldKey         string  `json:"fold_key"`
}

// reasonOn is the reason of the field error on field, or "".
func reasonOn(err error, field string) string {
	for _, fe := range fieldErrorsOf(err) {
		if fe.Field == field {
			return fe.Reason
		}
	}
	return ""
}

// serials_and_registration through the registry's adapters: a
// registration request (checkNewOperator, checkNewUAS), the uniqueness
// scope (manufacturerCode), the stored fold key, and the operator lookup
// key the service derives from the policy's pattern.
func TestVectorsSerialsAndRegistrationThroughTheRegistry(t *testing.T) {
	f := vectors.Load(t, "serials_and_registration.json")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vecSerialInput
		var exp vecSerialExpected
		c.Decode(t, &in, &exp)
		switch in.Kind {
		case "cta2063":
			// The registry scopes a serial's uniqueness by its CTA-2063-A
			// manufacturer code only when the serial is one.
			sn := *in.Serial
			if got := manufacturerCode(sn) != sn; got != *exp.Valid {
				t.Errorf("CTA %v, want %v", got, *exp.Valid)
			}
		case "serial_for_class":
			class := ""
			if in.ClassLabel != nil {
				class = *in.ClassLabel
			}
			_, err := checkNewUAS(NewUAS{OperatorID: strings.Repeat("a", 32), Serial: *in.Serial, ClassLabel: class, RIDCapability: "none"})
			reason := reasonOn(err, "serial")
			if (reason == "") != *exp.Valid {
				t.Fatalf("valid %v (%v), want %v", reason == "", err, *exp.Valid)
			}
			if exp.Problem != nil && reason != *exp.Problem {
				t.Errorf("problem %q, want %q", reason, *exp.Problem)
			}
		case "registration_number":
			v, err := regnum.NewValidator(in.Pattern)
			if err != nil {
				t.Fatal(err)
			}
			op := naturalOperator(in.Value)
			_, _, err = checkNewOperator(v, &op, t0)
			reason := reasonOn(err, "registration_number")
			if (reason == "") != *exp.Valid {
				t.Fatalf("valid %v (%v), want %v", reason == "", err, *exp.Valid)
			}
			if exp.Problem != nil && reason != *exp.Problem {
				t.Errorf("problem %q, want %q", reason, *exp.Problem)
			}
		case "public_registration_number":
			// An operator stored under the vector's compare key is what
			// the registry's lookup of the value finds.
			fx := newFixture(t)
			fx.svc.Pattern = func() (string, bool) { return in.Pattern, true }
			fx.store.operators["op"] = OperatorRecord{Operator: Operator{ID: "op", RegistrationNumber: exp.Public}, Key: exp.CompareKey}
			rows, err := fx.svc.ListOperators(context.Background(), in.Value, "", Page{})
			if err != nil || len(rows) != 1 {
				t.Fatalf("lookup of %q by its compare key %q: %v %v", in.Value, exp.CompareKey, rows, err)
			}
			v, err := fx.svc.validator()
			if err != nil {
				t.Fatal(err)
			}
			if pub, key := v.Public(in.Value); pub != exp.Public || key != exp.CompareKey {
				t.Errorf("public %q key %q", pub, key)
			}
		case "serial_fold":
			u, err := checkNewUAS(NewUAS{OperatorID: strings.Repeat("a", 32), Serial: *in.Serial, RIDCapability: "none"})
			var fe *core.FieldError
			if err != nil && (!errors.As(err, &fe) || fe.Field == "serial_fold") {
				t.Fatal(err)
			}
			if u.SerialFold != exp.FoldKey {
				t.Errorf("stored fold %q, want %q", u.SerialFold, exp.FoldKey)
			}
		default:
			t.Fatalf("unknown kind %q", in.Kind)
		}
	})
}
