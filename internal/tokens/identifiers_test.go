package tokens

import (
	"strings"
	"testing"
)

func TestSystemOfAcceptsM24IdsAndRefusesOthers(t *testing.T) {
	ok := map[string]string{
		"authority-01": SystemAuthority, "cisp-01": SystemCISP, "ansp-01": SystemANSP, "lab-01": SystemLab,
		"ussp-GEO1-01": SystemUSSP, "ussp-A-02": SystemUSSP, "ussp-ABCDEFGH-99": SystemUSSP,
	}
	for id, want := range ok {
		if got, err := SystemOf(id); err != nil || got != want {
			t.Errorf("%s: %q %v", id, got, err)
		}
	}
	for _, bad := range []string{"", "cisp", "cisp-1", "cisp-001", "authority-cisp-01", "ussp-geo1-01", "ussp-ABCDEFGHI-01",
		"ussp--01", "dss-01", "CISP-01", "lab-01 ", "sys-name-01", "ussp-GEO1-01\n"} {
		if _, err := SystemOf(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeAudience(t *testing.T) {
	ok := map[string]string{
		"uspace-cisp.example.test":               "uspace-cisp.example.test",
		"USPACE-CISP.Example.Test":               "uspace-cisp.example.test",
		"https://uspace-cisp.example.test":       "uspace-cisp.example.test",
		"https://uspace-cisp.example.test/v1/x":  "uspace-cisp.example.test",
		"https://dss.example.test:8443/dss/v1":   "dss.example.test",
		"http://authority:8080":                  "authority",
		"authority":                              "authority",
		"a-b.c-d.example.test":                   "a-b.c-d.example.test",
		"x." + strings.Repeat("a", 63) + ".test": "x." + strings.Repeat("a", 63) + ".test",
	}
	for in, want := range ok {
		if got, err := NormalizeAudience(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"", "host:443", "host/path", "user@host", "https://user@host", "https://host?x=1", "https://host#f",
		"ftp://host", "https://", "10.0.0.1", "https://[::1]/", "-host", "host-", "ho_st", "a..b", "host.",
		"x." + strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 130) + "test", "héllo", "mailto:x@y",
		strings.Repeat("h", 2049),
	} {
		if got, err := NormalizeAudience(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestAudienceOf(t *testing.T) {
	if h, err := AudienceOf("https://Uspace-CISP.example.test:443/v1"); err != nil || h != "uspace-cisp.example.test" {
		t.Fatalf("%q %v", h, err)
	}
	for _, bad := range []string{"uspace-cisp.example.test", "https://", "https://10.0.0.1/", "://x"} {
		if _, err := AudienceOf(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzNormalizeAudience(f *testing.F) {
	for _, s := range []string{"uspace-cisp.example.test", "https://a.b/c?d", "x:1", "\x00", "https://[::1]:80/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		h, err := NormalizeAudience(raw)
		if err != nil {
			return
		}
		if !validHostName(h) || h != strings.ToLower(h) || strings.ContainsAny(h, ":/?#@ ") {
			t.Fatalf("%q normalised to %q", raw, h)
		}
		// Idempotent: a normalised host normalises to itself.
		if h2, err := NormalizeAudience(h); err != nil || h2 != h {
			t.Fatalf("%q -> %q -> %q %v", raw, h, h2, err)
		}
	})
}

func FuzzSystemOf(f *testing.F) {
	f.Add("ussp-GEO1-01")
	f.Add("cisp-01")
	f.Fuzz(func(t *testing.T, id string) {
		sys, err := SystemOf(id)
		if err != nil {
			return
		}
		if !strings.HasPrefix(id, sys+"-") || len(id) > 17 {
			t.Fatalf("%q -> %q", id, sys)
		}
	})
}
