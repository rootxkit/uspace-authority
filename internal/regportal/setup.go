package regportal

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/occurrences"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

// Setup is what Assemble needs from the process.
type Setup struct {
	DB          *pg.DB
	Audit       *audit.Writer
	Registry    *registry.Service
	Occurrences Occurrences
	PublicPart  occurrences.PublicPartFunc
	PIIKeyID    string
	PIIKeyFile  string
	// HashKeyFile is the registry hash key's file: the portal key must
	// differ from it and from the PII key.
	HashKeyFile string
	PortalKey   string
	Config      Config
	SMTP        SMTP
	// MailPasswordFile holds the SMTP password, when SMTP.User is set.
	MailPasswordFile string
	CheckPerMin      int
	CheckBurst       int
	CheckMaxIPs      int
	Logger           *slog.Logger
	Limiter          *logging.Limiter
}

// Parts is the assembled portal.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
}

func readSecret(variable, path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return "", core.Fieldf(variable, "%q cannot be read", path)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", core.Fieldf(variable, "%q cannot be read", path)
	}
	return strings.TrimSpace(string(b)), nil
}

// Assemble builds the portal. With both flags off it needs no key and
// no mailer: the public check runs, every other operation is 404. With
// a flag on, the portal key (distinct from the PII and registry hash
// keys), the catalogues and a mailer whose configuration checks are
// required, or api does not start.
func Assemble(s Setup) (*Parts, error) {
	counters := &core.Counters{}
	svc := &Service{
		DB: s.DB, Audit: s.Audit, Registry: s.Registry, Occurrences: s.Occurrences, PublicPart: s.PublicPart,
		Config: s.Config, Counters: counters, Logger: s.Logger, Limiter: s.Limiter,
	}
	if s.Config.Applications || s.Config.OperatorReports {
		key, err := LoadKey("REGISTRY_PORTAL_KEY_FILE", s.PortalKey)
		if err != nil {
			return nil, err
		}
		for _, other := range [][2]string{{"PII_KEY_FILE", s.PIIKeyFile}, {"REGISTRY_HASH_KEY_FILE", s.HashKeyFile}} {
			if other[1] == "" {
				continue
			}
			if k, err := LoadKey(other[0], other[1]); err == nil && bytes.Equal(k, key) {
				return nil, core.Fieldf("REGISTRY_PORTAL_KEY_FILE", "must differ from %s: a link signed with a data key mixes two secrets", other[0])
			}
		}
		if svc.Signer, err = NewSigner(key); err != nil {
			return nil, err
		}
		if svc.Sealer, err = pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile); err != nil {
			return nil, err
		}
		if svc.Catalogue, err = LoadCatalogue(); err != nil {
			return nil, err
		}
		if err := CheckSMTP(s.SMTP); err != nil {
			return nil, err
		}
		m := s.SMTP
		if m.User != "" {
			if m.Password, err = readSecret("REGISTRY_MAIL_PASSWORD_FILE", s.MailPasswordFile); err != nil {
				return nil, err
			}
		}
		if m.Timeout <= 0 {
			m.Timeout = 30 * time.Second
		}
		svc.Mailer = m
	}
	h := Handler{Service: svc, Check: s.Registry}
	if s.CheckPerMin > 0 {
		h.CheckLimit = httpx.NewRateLimiter(float64(s.CheckPerMin)/60, s.CheckBurst, s.CheckMaxIPs, counters)
	}
	return &Parts{Service: svc, Handler: h, Counters: counters}, nil
}
