package receivers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func entryJSON(t *testing.T, e Entry) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// E-01: a valid entry parses; each way an entry can be wrong is refused
// by name, one change at a time.
func TestParseEntryAcceptsAValidEntryAndRefusesEachFault(t *testing.T) {
	h := cheapHasher(t)
	good := newTestReceiver(t, h, "rx-a").Entry
	if _, err := ParseEntry("rx-a", entryJSON(t, good)); err != nil {
		t.Fatalf("valid: %v", err)
	}
	until := time.Now()
	cases := map[string]func(e *Entry){
		"bad id":         func(e *Entry) { e.ReceiverID = "RX_A" },
		"status":         func(e *Entry) { e.Status = "paused" },
		"position":       func(e *Entry) { e.LatDeg = 91 },
		"no keys":        func(e *Entry) { e.Keys = nil },
		"three keys":     func(e *Entry) { e.Keys = append(e.Keys, e.Keys[0], e.Keys[0]) },
		"repeated gen":   func(e *Entry) { k := e.Keys[0]; k.NotAfter = &until; e.Keys = append(e.Keys, k) },
		"not argon2id":   func(e *Entry) { e.Keys[0].BearerHash = "$2a$10$abc" },
		"short secret":   func(e *Entry) { e.Keys[0].HMACSecretHex = "00ff" },
		"secret not hex": func(e *Entry) { e.Keys[0].HMACSecretHex = strings.Repeat("zz", 32) },
		"two current":    func(e *Entry) { k := e.Keys[0]; k.Generation = 2; e.Keys = append(e.Keys, k) },
		"no current":     func(e *Entry) { e.Keys[0].NotAfter = &until },
	}
	for name, mutate := range cases {
		e := good
		e.Keys = append([]KeyGeneration(nil), good.Keys...)
		mutate(&e)
		if _, err := ParseEntry(e.ReceiverID, entryJSON(t, e)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseEntry("rx-b", entryJSON(t, good)); err == nil || !strings.Contains(err.Error(), "stored under the key") {
		t.Errorf("key mismatch: %v", err)
	}
	raw := entryJSON(t, good)
	if _, err := ParseEntry("rx-a", append(raw[:len(raw)-1:len(raw)-1], []byte(`,"extra":1}`)...)); err == nil {
		t.Error("unknown member accepted")
	}
	if _, err := ParseEntry("rx-a", append(append([]byte(nil), raw...), []byte(` {}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParseEntry("rx-a", make([]byte, MaxEntryBytes+1)); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("oversize: %v", err)
	}
}

// Every decoder entry is fuzzed: ParseEntry never panics and never
// returns an entry that does not validate.
func FuzzParseEntry(f *testing.F) {
	h := cheapHasher(f)
	good := newTestReceiver(f, h, "rx-a").Entry
	raw, _ := json.Marshal(good)
	f.Add("rx-a", raw)
	f.Add("rx-a", []byte(`{}`))
	f.Add("", []byte(`null`))
	f.Add("rx-a", []byte(`{"receiver_id":"rx-a","keys":[{"generation":1}]}`))
	f.Fuzz(func(t *testing.T, key string, b []byte) {
		e, err := ParseEntry(key, b)
		if err == nil {
			if verr := e.Validate(); verr != nil || e.ReceiverID != key {
				t.Fatalf("returned an invalid entry: %v", verr)
			}
		}
	})
}

// E-01: a generated key parses back to its receiver; each malformed form
// is refused.
func TestParseBearer(t *testing.T) {
	c, secret, err := GenerateCredentials("rx-a", 1)
	if err != nil || len(secret) != HMACSecretBytes || len(c.HMACSecretHex) != 64 {
		t.Fatalf("generate: %v", err)
	}
	if id, key, err := ParseBearer("Bearer " + c.BearerKey); err != nil || id != "rx-a" || key != c.BearerKey {
		t.Fatalf("own key: %q %v", id, err)
	}
	if _, _, err := ParseBearer("bearer  " + c.BearerKey + " "); err != nil {
		t.Fatalf("case and spaces: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, bad := range []string{"", "Bearer", "Token " + c.BearerKey, "Bearer rx-a", "Bearer rx-a." + b64[:10],
		"Bearer RX-A." + b64, "Bearer rx-a." + strings.Repeat("!", len(b64)), "Bearer " + strings.Repeat("a", 300)} {
		if _, _, err := ParseBearer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzParseBearer(f *testing.F) {
	c, _, _ := GenerateCredentials("rx-a", 1)
	f.Add("Bearer " + c.BearerKey)
	f.Add("Bearer .")
	f.Add("")
	f.Fuzz(func(t *testing.T, header string) {
		id, key, err := ParseBearer(header)
		if err == nil && (!ValidID(id) || !strings.HasPrefix(key, id+".")) {
			t.Fatalf("accepted %q as %q", header, id)
		}
	})
}

func TestDatagramIsBodyThenSignature(t *testing.T) {
	if got := string(Datagram([]byte("{}"), "ab")); got != "{}\nsig=ab" {
		t.Fatalf("%q", got)
	}
	if got := string(Datagram([]byte("{}"), "")); got != "{}" {
		t.Fatalf("unsigned %q", got)
	}
}
