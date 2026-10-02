package registry

import (
	"net/http"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// transitions is the one status graph of every registry entity: active
// and suspended move between each other; either may be revoked, which
// is final, or expire, which only the expiry job does; an expired
// registration may be renewed (active) or revoked.
var transitions = map[Status][]Status{
	StatusActive:    {StatusSuspended, StatusRevoked, StatusExpired},
	StatusSuspended: {StatusActive, StatusRevoked, StatusExpired},
	StatusExpired:   {StatusActive, StatusRevoked},
	StatusRevoked:   nil,
}

// ValidStatus reports whether s is a registry status.
func ValidStatus(s Status) bool {
	_, ok := transitions[s]
	return ok
}

// CheckTransition refuses a status change the graph does not allow. A
// person may set active, suspended and revoked; expired is the expiry
// job's (bySystem). A suspension or a revocation by a person needs a
// reason.
func CheckTransition(from, to Status, reason string, bySystem bool) error {
	if !ValidStatus(to) {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			core.Fieldf("status", "must be active, suspended or revoked"))
	}
	if to == StatusExpired && !bySystem {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			core.Fieldf("status", "expired is set by the expiry job from valid_until"))
	}
	if !bySystem && (to == StatusSuspended || to == StatusRevoked) && reason == "" {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			core.Fieldf("reason", "required to set %s", to))
	}
	if utf8.RuneCountInString(reason) > maxReasonLen {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			core.Fieldf("reason", "longer than %d characters", maxReasonLen))
	}
	for _, s := range transitions[from] {
		if s == to {
			return nil
		}
	}
	return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "this status change is not allowed",
		core.Fieldf("status", "%s cannot become %s", from, to))
}
