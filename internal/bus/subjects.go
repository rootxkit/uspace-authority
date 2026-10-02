package bus

import (
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// Wildcard subjects of the streams (docs/PLAN.md §6).
const (
	SubjectTrkAll    = "trk.v1.>"
	SubjectManAll    = "man.v1.>"
	SubjectAlrtAll   = "alrt.v1.>"
	SubjectIdentAll  = "ident.v1.>"
	SubjectCisAll    = "cis.v1.>"
	SubjectSrcAll    = "src.v1.>"
	SubjectIngestAll = "ingest.v1.>"
	SubjectTswAll    = "tsw.v1.>"
)

// Fixed subjects (docs/PLAN.md §6).
const (
	// SubjectCtlSources is the push of every source-control state.
	SubjectCtlSources = "ctl.sources"
	// SubjectCtlPolicy is the push of the active policy.
	SubjectCtlPolicy = "ctl.policy"
	// SubjectRegistryChanged tells the readers to re-read the registry
	// projection now.
	SubjectRegistryChanged = "registry.v1.changed"
	// SubjectZonesChanged tells the readers to re-read the zones.
	SubjectZonesChanged = "zones.v1.changed"
)

// maxTokenLen bounds one token: ids from outside never make a subject
// unbounded.
const maxTokenLen = 128

// Token returns s when NATS reads it as exactly one literal subject
// token, and otherwise a *core.FieldError naming field: an empty token,
// a dot (a second token), "*" or ">" (a wildcard), white space or a
// control character, or more than 128 bytes.
func Token(field, s string) (string, error) {
	if s == "" {
		return "", &core.FieldError{Field: field, Reason: "empty subject token"}
	}
	if len(s) > maxTokenLen {
		return "", core.Fieldf(field, "subject token longer than %d bytes", maxTokenLen)
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r == '.' || r == '*' || r == '>' {
			return "", core.Fieldf(field, "%q is not one literal subject token", s)
		}
	}
	return s, nil
}

func subject(prefix string, parts ...[2]string) (string, error) {
	var b strings.Builder
	b.WriteString(prefix)
	for _, p := range parts {
		tok, err := Token(p[0], p[1])
		if err != nil {
			return "", err
		}
		b.WriteByte('.')
		b.WriteString(tok)
	}
	return b.String(), nil
}

// Subjects builds every subject of docs/PLAN.md §6. Cell arguments are
// the subject-token form of internal/cell.
var Subjects subjects

type subjects struct{}

// Trk is trk.v1.<cell3>.<cell5>.<track_id>.
func (subjects) Trk(cell3, cell5, trackID string) (string, error) {
	return subject("trk.v1", [2]string{"cell3", cell3}, [2]string{"cell5", cell5}, [2]string{"track_id", trackID})
}

// Man is man.v1.<cell3>.<cell5>.<icao24>.
func (subjects) Man(cell3, cell5, icao24 string) (string, error) {
	return subject("man.v1", [2]string{"cell3", cell3}, [2]string{"cell5", cell5}, [2]string{"icao24", icao24})
}

// Alrt is alrt.v1.<kind>.<cell5>.<violation_id>.
func (subjects) Alrt(kind, cell5, violationID string) (string, error) {
	return subject("alrt.v1", [2]string{"kind", kind}, [2]string{"cell5", cell5}, [2]string{"violation_id", violationID})
}

// Ident is ident.v1.<track_id>.
func (subjects) Ident(trackID string) (string, error) {
	return subject("ident.v1", [2]string{"track_id", trackID})
}

// Cis is cis.v1.<dataset>.
func (subjects) Cis(dataset string) (string, error) {
	return subject("cis.v1", [2]string{"dataset", dataset})
}

// Src is src.v1.<type>.<instance>, a source's status every 2 s.
func (subjects) Src(sourceType, instance string) (string, error) {
	return subject("src.v1", [2]string{"source_type", sourceType}, [2]string{"instance_id", instance})
}

// Ingest is ingest.v1.<cell3>, the work queue of one cell3.
func (subjects) Ingest(cell3 string) (string, error) {
	return subject("ingest.v1", [2]string{"cell3", cell3})
}

// Tsw is tsw.v1.<table>, rows towards tsdb-writer.
func (subjects) Tsw(table string) (string, error) {
	return subject("tsw.v1", [2]string{"table", table})
}
