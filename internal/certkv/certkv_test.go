package certkv

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func good() Register {
	return Register{Version: 3, USSPs: []USSP{
		{ClientID: "ussp-AB12-01", Code: "AB12", BaseURL: "https://ab12.example.test", Status: "operating"},
		{ClientID: "ussp-CD34-01", Code: "CD34", BaseURL: "https://cd34.example.test", Status: "limited"},
	}}
}

// E-01: the shape api writes is taken; each malformed member refuses
// the whole value.
func TestDecodeTakesTheShapeAndRefusesEachFault(t *testing.T) {
	raw, _ := json.Marshal(good())
	r, err := Decode(raw)
	if err != nil || r.Version != 3 || len(r.ClientIDs()) != 2 || !r.ClientIDs()["ussp-CD34-01"] {
		t.Fatalf("%+v %v", r, err)
	}
	for name, edit := range map[string]func(*Register){
		"version":     func(r *Register) { r.Version = -1 },
		"client id":   func(r *Register) { r.USSPs[0].ClientID = "cisp-01" },
		"lower code":  func(r *Register) { r.USSPs[0].Code = "ab12" },
		"empty url":   func(r *Register) { r.USSPs[0].BaseURL = "" },
		"long url":    func(r *Register) { r.USSPs[0].BaseURL = "https://" + strings.Repeat("a", MaxBaseURL) },
		"status":      func(r *Register) { r.USSPs[1].Status = "suspended" },
		"over bounds": func(r *Register) { r.USSPs = make([]USSP, MaxUSSPs+1) },
	} {
		r := good()
		edit(&r)
		raw, _ := json.Marshal(r)
		if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Decode([]byte(`{"version":`)); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	if _, err := Decode(make([]byte, ValueBytes+1)); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

// E-10: the bound holds exactly MaxUSSPs and fits the value bound.
func TestRegisterAtItsBoundFitsTheValue(t *testing.T) {
	r := Register{Version: 1}
	for i := range MaxUSSPs {
		code := fmt.Sprintf("U%07d", i)
		r.USSPs = append(r.USSPs, USSP{ClientID: "ussp-" + code + "-01", Code: code, BaseURL: "https://" + strings.Repeat("h", 200) + ".example.test", Status: "operating"})
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > ValueBytes {
		t.Fatalf("%d bytes, bound %d: %v", len(raw), ValueBytes, err)
	}
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
}

func TestBucketConfig(t *testing.T) {
	if c := BucketConfig(""); c.Bucket != Bucket || c.MaxValueSize != ValueBytes || c.TTL != 0 {
		t.Fatalf("%+v", c)
	}
	if BucketConfig("x").Bucket != "x" {
		t.Fatal("name")
	}
}

// Fuzz: no input panics Decode, and whatever it takes passes Check and
// is within the bounds.
func FuzzDecode(f *testing.F) {
	raw, _ := json.Marshal(good())
	f.Add(raw)
	f.Add([]byte(`{"version":1,"ussps":[]}`))
	f.Add([]byte(`{"version":1,"ussps":[{"client_id":"ussp-A-01","code":"A","base_url":"x","status":"operating"}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decode(b)
		if err != nil {
			return
		}
		if r.Check() != nil || len(r.USSPs) > MaxUSSPs || r.Version < 0 {
			t.Fatalf("took %q as %+v", b, r)
		}
	})
}
