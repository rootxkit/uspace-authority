package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fileURL(dir string) string {
	if runtime.GOOS == "windows" {
		return "file:///" + filepath.ToSlash(dir)
	}
	return "file://" + filepath.ToSlash(dir)
}

// WP-27, spec 08 Q8: the defaults are the spec's (90 days online, 2
// years archive, 5 years alerts, incidents indefinite, audit 10 years),
// pending GCAA; changing them is configuration, never code.
func TestRetentionDefaultsAreTheSpecQ8Defaults(t *testing.T) {
	var c API
	if err := Load(&c, env(validAPI())); err != nil {
		t.Fatal(err)
	}
	r := c.Retention
	if r.RetentionOnlineDays != 90 || r.RetentionArchiveYears != 2 || r.RetentionViolationsYears != 5 ||
		r.RetentionIncidents != "indefinite" || r.RetentionAuditYears != 10 {
		t.Fatalf("defaults %+v", r)
	}
	if r.ArchiveURL != "" || r.RetentionBatchRows != 1000 || r.RetentionEveryS != 86400 {
		t.Fatalf("job defaults %+v", r)
	}
	if !strings.Contains(Help(&c), "pending GCAA") {
		t.Fatal("the help does not say the periods are pending GCAA")
	}
}

// The floor (30 days online, 2021/664 Art. 15(1)(g)) and the shapes the
// tags cannot say: each refusal beside its acceptance (E-01).
func TestRetentionRefusesWhatIsOutsideItsBounds(t *testing.T) {
	cases := []struct {
		name, value string
		ok          bool
	}{
		{"RETENTION_ONLINE_DAYS", "29", false},
		{"RETENTION_ONLINE_DAYS", "30", true},
		{"RETENTION_ARCHIVE_YEARS", "0", false},
		{"RETENTION_ARCHIVE_YEARS", "1", true},
		{"RETENTION_INCIDENTS", "5", false},
		{"RETENTION_INCIDENTS", "indefinite", true},
		{"RETENTION_AUDIT_YEARS", "0", false},
		{"RETENTION_BATCH_ROWS", "10001", false},
		{"RETENTION_BATCH_ROWS", "10000", true},
		{"ARCHIVE_URL", "s3://bucket/prefix", false},
		{"ARCHIVE_URL", "file:relative", false},
		{"ARCHIVE_URL", fileURL(t.TempDir()), true},
	}
	for _, c := range cases {
		m := validAPI()
		m[c.name] = c.value
		var cfg API
		err := Load(&cfg, env(m))
		if c.ok != (err == nil) {
			t.Errorf("%s=%s: %v", c.name, c.value, err)
		}
		if err != nil && !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s=%s: the refusal does not name the variable: %v", c.name, c.value, err)
		}
	}
	m := validAPI()
	m["RETENTION_ONLINE_DAYS"], m["RETENTION_ARCHIVE_YEARS"] = "800", "2"
	var cfg API
	if err := Load(&cfg, env(m)); err == nil || !strings.Contains(err.Error(), "RETENTION_ARCHIVE_YEARS") {
		t.Fatalf("an archive shorter than the online window: %v", err)
	}
}
