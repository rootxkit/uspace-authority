package dpviews

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A usable box is accepted; one outside WGS84, empty, non-finite or
// across the antimeridian is refused (E-01).
func TestBBoxCheck(t *testing.T) {
	if err := (BBox{44.7, 41.6, 44.9, 41.8}).Check(); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]BBox{
		"south above north": {44.7, 41.8, 44.9, 41.6}, "antimeridian": {179, 1, -179, 2}, "latitude": {0, -91, 1, 0},
		"longitude": {-181, 0, 1, 1}, "empty": {1, 1, 1, 2},
	} {
		if b.Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// E-10: the decoders hold their bounds and refuse a bad box with the
// whole value; within the bounds they read.
func TestDecodeBounds(t *testing.T) {
	ok, _ := json.Marshal(Oversight{Version: 3, Areas: []Area{{ID: 1, Label: "airport", BBox: BBox{44.7, 41.6, 44.9, 41.8}}}})
	if o, err := DecodeOversight(ok); err != nil || o.Version != 3 {
		t.Fatalf("%+v %v", o, err)
	}
	areas := make([]Area, MaxOversight+1)
	for i := range areas {
		areas[i] = Area{BBox: BBox{0, 0, 1, 1}}
	}
	over, _ := json.Marshal(Oversight{Areas: areas})
	if _, err := DecodeOversight(over); err == nil {
		t.Error("more areas than the bound accepted")
	}
	bad, _ := json.Marshal(Oversight{Areas: []Area{{BBox: BBox{179, 1, -179, 2}}}})
	if _, err := DecodeOversight(bad); err == nil {
		t.Error("an area across the antimeridian accepted")
	}
	boxes := make([]BBox, MaxConsoleBoxes+1)
	for i := range boxes {
		boxes[i] = BBox{0, 0, 1, 1}
	}
	tooMany, _ := json.Marshal(Console{Instance: "p", At: time.Now(), BBoxes: boxes})
	if _, err := DecodeConsole(tooMany); err == nil {
		t.Error("more viewports than the bound accepted")
	}
	c, _ := json.Marshal(Console{Instance: "p", At: time.Now(), BBoxes: boxes[:2]})
	if got, err := DecodeConsole(c); err != nil || len(got.BBoxes) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeConsole([]byte(strings.Repeat(" ", ConsoleValueBytes+1))); err == nil {
		t.Error("a value over the bound accepted")
	}
}

// The console bucket expires what is not reported again; the oversight
// bucket keeps its value.
func TestBucketsAndKeys(t *testing.T) {
	if ConsoleBucketConfig("").TTL != ConsoleTTL || ConsoleEvery >= ConsoleTTL {
		t.Fatal("console viewports do not expire, or expire before they are reported again")
	}
	if OversightBucketConfig("").TTL != 0 {
		t.Fatal("oversight areas expire")
	}
	if k := ConsoleKey("host a.b/1"); k != "console.host_a_b_1" {
		t.Fatalf("key %q", k)
	}
	if r := Round(BBox{44.71234, 41.61234, 44.81234, 41.71234}); r != (BBox{44.7123, 41.6123, 44.8124, 41.7124}) {
		t.Fatalf("round %v", r)
	}
}
