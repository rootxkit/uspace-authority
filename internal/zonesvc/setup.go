package zonesvc

import (
	"log/slog"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Setup is what Assemble needs from the process.
type Setup struct {
	DB    *pg.DB
	Audit *audit.Writer
	// Projector is api's pool on the projection tables (shared with the
	// registry projection).
	Projector *ts.Projector
	Publisher Publisher
	Meta      Meta
	Logger    *slog.Logger
}

// Parts is the assembled zone service.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
}

// Assemble builds the zone service on the relational database and the
// projection pool. Daylight events come from ground.Daylight (core's
// ed318.NOAADaylight, WP-11). The provider's name and language
// must be what ED-318 holds (a text of at most 200 characters, a
// language tag of 1 to 5).
func Assemble(s Setup) (*Parts, error) {
	if n := utf8.RuneCountInString(s.Meta.ProviderName); n > maxNameCh {
		return nil, core.Fieldf("ZONES_PROVIDER_NAME", "longer than %d characters", maxNameCh)
	}
	if n := len(s.Meta.ProviderLang); n < 1 || n > 5 {
		return nil, core.Fieldf("ZONES_PROVIDER_LANG", "must be a language tag of 1 to 5 characters (en-GB)")
	}
	counters := &core.Counters{}
	pub := s.Publisher
	if pub == nil {
		pub = NopPublisher{}
	}
	svc := &Service{
		Store: PG{DB: s.DB, Audit: s.Audit}, Projection: TSProjection{P: s.Projector}, Publisher: pub,
		Daylight: ground.Daylight(), Meta: s.Meta, Counters: counters, Logger: s.Logger,
	}
	return &Parts{Service: svc, Handler: Handler{Service: svc}, Counters: counters}, nil
}
