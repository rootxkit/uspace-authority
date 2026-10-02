package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func env(m map[string]string) LookupFunc {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func validAPI() map[string]string {
	return map[string]string{
		"PG_URL":               "postgres://u:pw-relational@db:5432/authority",
		"TS_URL":               "postgres://u:pw-telemetry@db:5432/authority_ts",
		"NATS_URL":             "nats://nats:4222",
		"AUTHORITY_PUBLIC_URL": "https://authority.example.test",
		"PICTURE_SESSION_URL":  "http://api:8080/v1/auth/session",
		"SIGNING_KEY_FILES":    "/run/keys/token-1.pem",
		"PII_KEY_FILE":         "/run/keys/pii.key",

		"REGISTRY_HASH_KEY_FILE": "/run/keys/registry-hash.key",
	}
}

func TestLoadAcceptsAValidAPIConfigAndAppliesDefaults(t *testing.T) {
	var c API
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != ":8080" || c.AdminAddr != ":9090" || c.LogLevel != "info" || c.MTLSMode != "required" {
		t.Errorf("defaults not applied: %+v", c)
	}
	if c.MaxBodyBytes != 1<<20 || c.StatusIntervalS != 60 || c.ShutdownTimeoutS != 15 || c.RateLimitRPS != 20 {
		t.Errorf("numeric defaults not applied: %+v", c)
	}
}

func TestLoadRefusesMissingRequiredVariableNamingIt(t *testing.T) {
	m := validAPI()
	delete(m, "PG_URL")
	var c API
	err := Load(&c, env(m))
	if err == nil {
		t.Fatal("Load accepted a config without PG_URL")
	}
	fes := FieldErrors(err)
	if len(fes) != 1 || fes[0].Field != "PG_URL" || fes[0].Reason != "required" {
		t.Fatalf("got %v, want one FieldError naming PG_URL", fes)
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	var c API
	err := Load(&c, env(map[string]string{"LOG_LEVEL": "loud", "STATUS_INTERVAL_S": "0", "AUTHORITY_MTLS_MODE": "maybe"}))
	got := map[string]bool{}
	for _, fe := range FieldErrors(err) {
		got[fe.Field] = true
	}
	for _, want := range []string{"PG_URL", "TS_URL", "NATS_URL", "AUTHORITY_PUBLIC_URL", "LOG_LEVEL", "STATUS_INTERVAL_S", "AUTHORITY_MTLS_MODE"} {
		if !got[want] {
			t.Errorf("no error for %s in %v", want, err)
		}
	}
}

func TestLoadFieldKinds(t *testing.T) {
	type kinds struct {
		S  string        `env:"S"`
		B  bool          `env:"B"`
		I  int           `env:"I" min:"2" max:"5"`
		F  float64       `env:"F" min:"0.5"`
		D  time.Duration `env:"D"`
		L  []string      `env:"L"`
		U  string        `env:"U" kind:"url"`
		Df string        `env:"DF" default:"dflt"`
	}
	var k kinds
	err := Load(&k, env(map[string]string{"S": " x ", "B": "true", "I": "3", "F": "0.75", "D": "1500ms", "L": "a, b,,c", "U": "https://h.example.test/p", "DF": ""}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if k.S != "x" || !k.B || k.I != 3 || k.F != 0.75 || k.D != 1500*time.Millisecond || strings.Join(k.L, "|") != "a|b|c" || k.Df != "dflt" {
		t.Errorf("parsed %+v", k)
	}

	bad := map[string]string{"B": "yes-ish", "I": "9", "F": "NaN", "D": "-1s", "U": "not a url"}
	for name, val := range bad {
		var k kinds
		err := Load(&k, env(map[string]string{name: val}))
		fes := FieldErrors(err)
		if len(fes) != 1 || fes[0].Field != name {
			t.Errorf("%s=%q: got %v, want one error naming %s", name, val, err, name)
		}
	}
	var k2 kinds
	if fes := FieldErrors(Load(&k2, env(map[string]string{"I": "1"}))); len(fes) != 1 || !strings.Contains(fes[0].Reason, "at least 2") {
		t.Errorf("below min: %v", fes)
	}
	if fes := FieldErrors(Load(&k2, env(map[string]string{"I": "x"}))); len(fes) != 1 || fes[0].Reason != "must be an integer" {
		t.Errorf("not an integer: %v", fes)
	}
	if fes := FieldErrors(Load(&k2, env(map[string]string{"U": "/relative"}))); len(fes) != 1 || !strings.Contains(fes[0].Reason, "absolute") {
		t.Errorf("relative url: %v", fes)
	}
}

func TestLoadRefusesUnsupportedTypesAndNonPointers(t *testing.T) {
	type odd struct {
		M map[string]int `env:"M"`
	}
	var o odd
	if fes := FieldErrors(Load(&o, env(map[string]string{"M": "x"}))); len(fes) != 1 || fes[0].Field != "M" {
		t.Errorf("unsupported type: %v", fes)
	}
	if err := Load(odd{}, env(nil)); err == nil {
		t.Error("Load accepted a non-pointer")
	}
}

func TestValidateRefusesOneDatabaseForBothTrees(t *testing.T) {
	m := validAPI()
	m["TS_URL"] = m["PG_URL"]
	var c API
	fes := FieldErrors(Load(&c, env(m)))
	if len(fes) != 1 || fes[0].Field != "TS_URL" {
		t.Fatalf("got %v, want TS_URL refused", fes)
	}
	m = validAPI()
	m["ADMIN_ADDR"] = ":8080"
	var c2 API
	if fes := FieldErrors(Load(&c2, env(m))); len(fes) != 1 || fes[0].Field != "ADMIN_ADDR" {
		t.Fatalf("got %v, want ADMIN_ADDR refused", fes)
	}
	mig := &Migrate{}
	if fes := FieldErrors(Load(mig, env(map[string]string{"PG_URL": "postgres://a/x", "TS_URL": "postgres://a/x"}))); len(fes) != 1 || fes[0].Field != "TS_URL" {
		t.Fatalf("migrate: got %v", fes)
	}
	mig = &Migrate{}
	if err := Load(mig, env(map[string]string{"PG_URL": "postgres://a/x", "TS_URL": "postgres://a/y"})); err != nil {
		t.Fatalf("migrate with two databases: %v", err)
	}
}

func TestStringRedactsSecrets(t *testing.T) {
	var c API
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatal(err)
	}
	s := c.String()
	for _, secret := range []string{"pw-relational", "pw-telemetry", "nats://nats"} {
		if strings.Contains(s, secret) {
			t.Errorf("String leaks %q: %s", secret, s)
		}
	}
	for _, want := range []string{"PG_URL=<redacted>", "TS_URL=<redacted>", "AUTHORITY_PUBLIC_URL=https://authority.example.test", "API_ADDR=:8080"} {
		if !strings.Contains(s, want) {
			t.Errorf("String lacks %q: %s", want, s)
		}
	}
	var empty Detect
	if !strings.Contains(empty.String(), "TS_URL= ") {
		t.Errorf("an unset secret should show as empty, not redacted: %s", empty.String())
	}
}

func TestHelpListsEveryVariableWithoutSecretDefaults(t *testing.T) {
	h := Help(&API{})
	for _, want := range []string{"PG_URL (required; secret)", "API_ADDR (default :8080)", "AUTHORITY_MTLS_MODE (default required; one of required, off)", "OTEL_EXPORTER_OTLP_ENDPOINT", "HTTP_RATE_LIMIT_MAX_CLIENTS"} {
		if !strings.Contains(h, want) {
			t.Errorf("Help lacks %q:\n%s", want, h)
		}
	}
}

func TestEveryProcessConfigLoadsFromTheExampleShape(t *testing.T) {
	m := validAPI()
	for _, c := range []interface {
		CommonConfig
		String() string
	}{&API{}, &RIDIngest{}, &DPPoller{}, &MannedIngest{}, &Detect{}, &TSDBWriter{}, &PictureWS{}} {
		if err := Load(c, env(m)); err != nil {
			t.Errorf("%T: %v", c, err)
		}
		if c.CommonBlock().AdminAddr != ":9090" {
			t.Errorf("%T: common block not loaded", c)
		}
		if c.String() == "" {
			t.Errorf("%T: empty String", c)
		}
	}
}

func TestFieldErrorsOfNonFieldErrors(t *testing.T) {
	if FieldErrors(nil) != nil {
		t.Error("nil error has field errors")
	}
	if FieldErrors(errors.New("plain")) != nil {
		t.Error("plain error has field errors")
	}
	wrapped := errors.Join(&core.FieldError{Field: "A", Reason: "r"}, errors.New("plain"))
	if fes := FieldErrors(wrapped); len(fes) != 1 || fes[0].Field != "A" {
		t.Errorf("got %v", fes)
	}
}

// E-02: the issuer with no key configured refuses to start, naming the
// variable; beside it the accepted configuration.
func TestAPIRefusesAMissingSigningKeyNamingTheVariable(t *testing.T) {
	m := validAPI()
	delete(m, "SIGNING_KEY_FILES")
	var c API
	fes := FieldErrors(Load(&c, env(m)))
	if len(fes) != 1 || fes[0].Field != "SIGNING_KEY_FILES" || fes[0].Reason != "required" {
		t.Fatalf("got %v, want SIGNING_KEY_FILES required", fes)
	}
	var ok API
	if err := Load(&ok, env(validAPI())); err != nil || len(ok.SigningKeyFiles) != 1 {
		t.Fatalf("accepted twin: %v %v", err, ok.SigningKeyFiles)
	}
}

func TestAPIAudiencesMustHoldTheOwnHost(t *testing.T) {
	var c API
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatal(err)
	}
	if c.OwnHost() != "authority.example.test" || strings.Join(c.AudienceList(), ",") != "authority.example.test" {
		t.Fatalf("own host %q audiences %v", c.OwnHost(), c.AudienceList())
	}
	if c.Issuer() != "https://authority.example.test" {
		t.Fatalf("issuer default %q", c.Issuer())
	}
	m := validAPI()
	m["AUTHORITY_AUDIENCES"] = "authority.example.test,authority"
	m["ISSUER_URL"] = "https://issuer.example.test/"
	var lab API
	if err := Load(&lab, env(m)); err != nil {
		t.Fatalf("own host plus a lab alias: %v", err)
	}
	if lab.Issuer() != "https://issuer.example.test" || len(lab.AudienceList()) != 2 {
		t.Fatalf("issuer %q audiences %v", lab.Issuer(), lab.AudienceList())
	}
	for _, bad := range []string{"authority", "authority.example.test,https://x.example.test", "authority.example.test,Upper.example.test"} {
		m["AUTHORITY_AUDIENCES"] = bad
		var c API
		fes := FieldErrors(Load(&c, env(m)))
		if len(fes) == 0 || fes[0].Field != "AUTHORITY_AUDIENCES" {
			t.Errorf("%q: got %v", bad, fes)
		}
	}
	m = validAPI()
	m["ISSUER_URL"] = "https://issuer.example.test/?x=1"
	var q API
	if fes := FieldErrors(Load(&q, env(m))); len(fes) != 1 || fes[0].Field != "ISSUER_URL" {
		t.Errorf("issuer with a query: %v", fes)
	}
}

func TestArgon2BoundsAreTheOWASPMinimum(t *testing.T) {
	m := validAPI()
	m["ARGON2_MEMORY_KIB"] = "8192"
	var c API
	if fes := FieldErrors(Load(&c, env(m))); len(fes) != 1 || fes[0].Field != "ARGON2_MEMORY_KIB" {
		t.Fatalf("below the minimum: %v", fes)
	}
	var d API
	if err := Load(&d, env(validAPI())); err != nil || d.Argon2MemoryKiB != 19456 || d.Argon2Time != 2 || d.Argon2Threads != 1 {
		t.Fatalf("defaults: %v %+v", err, d.Argon2)
	}
}

func TestAPIPairsAreBothOrNeither(t *testing.T) {
	for _, half := range []map[string]string{
		{"CISP_ISSUER_URL": "https://cisp.example.test"},
		{"LAB_JWKS_URL": "https://lab.example.test/jwks"},
		{"BOOTSTRAP_ADMIN_USERNAME": "admin"},
	} {
		m := validAPI()
		for k, v := range half {
			m[k] = v
		}
		var c API
		if fes := FieldErrors(Load(&c, env(m))); len(fes) != 1 {
			t.Errorf("%v: %v", half, fes)
		}
	}
	m := validAPI()
	m["CISP_ISSUER_URL"], m["CISP_JWKS_URL"] = "https://cisp.example.test", "https://cisp.example.test/.well-known/jwks.json"
	m["BOOTSTRAP_ADMIN_USERNAME"], m["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = "admin", "/run/keys/admin"
	var c API
	if err := Load(&c, env(m)); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
	if l := c.List(); len(l) != 1 || l["https://cisp.example.test"] == "" {
		t.Fatalf("peers %v", l)
	}
}

func TestTrustedProxiesMustParse(t *testing.T) {
	m := validAPI()
	m["AUTHORITY_TRUSTED_PROXIES"] = "10.0.0.0/8, 172.18.0.2"
	var c API
	if err := Load(&c, env(m)); err != nil || len(c.TrustedProxies) != 2 {
		t.Fatalf("accepted twin: %v %v", err, c.TrustedProxies)
	}
	m["AUTHORITY_TRUSTED_PROXIES"] = "10.0.0.0/8,caddy"
	var bad API
	if fes := FieldErrors(Load(&bad, env(m))); len(fes) != 1 || fes[0].Field != "AUTHORITY_TRUSTED_PROXIES" {
		t.Fatalf("got %v", fes)
	}
}

// WP-3: the MTOM bands are ascending positive grams; the defaults are
// the 2019/945 class limits.
func TestRegistryMTOMBandsMustAscend(t *testing.T) {
	var c API
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatal(err)
	}
	if b, err := c.MTOMBounds(); err != nil || len(b) != 4 || b[0] != 250 || b[3] != 25000 {
		t.Fatalf("defaults: %v %v", b, err)
	}
	for _, bad := range []string{"900,250", "0,250", "250,x", "250,250"} {
		m := validAPI()
		m["REGISTRY_MTOM_BANDS_G"] = bad
		var c API
		if err := Load(&c, env(m)); err == nil || !strings.Contains(err.Error(), "REGISTRY_MTOM_BANDS_G") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	m := validAPI()
	m["REGISTRY_MTOM_BANDS_G"] = "500,2000"
	var ok API
	if err := Load(&ok, env(m)); err != nil {
		t.Fatalf("twin refused: %v", err)
	}
}

// WP-13: picture-ws's configuration: the defaults (the allowed origin is
// AUTHORITY_PUBLIC_URL's, the JWKS this issuer's) beside each refusal
// naming its variable (E-01).
func TestPictureWSConfigDefaultsAndRefusals(t *testing.T) {
	var c PictureWS
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatal(err)
	}
	if got := c.Origins(); len(got) != 1 || got[0] != "https://authority.example.test" {
		t.Fatalf("origins %v", got)
	}
	if c.JWKS() != "https://authority.example.test/.well-known/jwks.json" || c.AudienceList()[0] != "authority.example.test" {
		t.Fatalf("jwks %s audiences %v", c.JWKS(), c.AudienceList())
	}
	if c.SessionRecheckS != 15 || c.ThrottleAboveTracks != 200 || c.ThrottleHz != 2 || c.StatusIntervalMS != 2000 {
		t.Fatalf("defaults %+v", c.PictureTuning)
	}
	m := validAPI()
	m["PICTURE_ALLOWED_ORIGINS"] = "https://Console.Example.test:443/, http://localhost:3000"
	c = PictureWS{}
	if err := Load(&c, env(m)); err != nil {
		t.Fatal(err)
	}
	if got := c.Origins(); len(got) != 2 || got[0] != "https://console.example.test" || got[1] != "http://localhost:3000" {
		t.Fatalf("normalised origins %v", got)
	}
	for name, change := range map[string]map[string]string{
		"PICTURE_ALLOWED_ORIGINS": {"PICTURE_ALLOWED_ORIGINS": "https://console.example.test/app"},
		"AUTHORITY_AUDIENCES":     {"AUTHORITY_AUDIENCES": "other.example.test"},
		"PICTURE_ALERT_FORGET_S":  {"PICTURE_ALERT_FORGET_S": "10", "PICTURE_ALERT_SILENT_S": "10"},
		"PICTURE_SESSION_URL":     {"PICTURE_SESSION_URL": ""},
		"ADMIN_ADDR":              {"ADMIN_ADDR": ":8083"},
	} {
		m := validAPI()
		for k, v := range change {
			m[k] = v
		}
		c = PictureWS{}
		err := Load(&c, env(m))
		found := false
		for _, fe := range FieldErrors(err) {
			found = found || fe.Field == name
		}
		if !found {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, ok := OriginOf("ftp://x.example.test"); ok {
		t.Fatal("an ftp origin")
	}
	if o, ok := OriginOf("http://[::1]:8080"); !ok || o != "http://[::1]:8080" {
		t.Fatalf("ipv6 origin %q", o)
	}
}
