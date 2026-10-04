package authz

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Bounds of a police account's access (WP-19; migration 00021 repeats
// them).
const (
	MaxAllowList  = 32
	maxAllowEntry = 64
)

var agencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$`)

// ReasonAddressNotAllowed is the refusal of a police sign-in or query
// from an address off the account's allow-list (login_refused,
// mfa_refused and police_query_refused reason).
const ReasonAddressNotAllowed = "address_not_allowed"

// ParseAllowList reads an IP allow-list: CIDRs or single addresses (a
// /32 or /128), at most MaxAllowList, each canonical in the result
// (masked, sorted, unique). The error names field and the entry.
func ParseAllowList(field string, entries []string) ([]string, error) {
	if len(entries) > MaxAllowList {
		return nil, core.Fieldf(field, "at most %d entries", MaxAllowList)
	}
	out := make([]string, 0, len(entries))
	for i, e := range entries {
		f := field + "[" + strconv.Itoa(i) + "]"
		e = strings.TrimSpace(e)
		if e == "" || len(e) > maxAllowEntry {
			return nil, core.Fieldf(f, "a CIDR or an address of 1 to %d characters", maxAllowEntry)
		}
		var p netip.Prefix
		if strings.Contains(e, "/") {
			pp, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, core.Fieldf(f, "%q is not a CIDR", clip(e))
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(e)
			if err != nil || a.Zone() != "" {
				return nil, core.Fieldf(f, "%q is not an address", clip(e))
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(0, p.Bits()-96))
		}
		out = append(out, p.String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// AddressAllowed reports whether ip (the client address behind the
// trusted proxies) is inside one of allow. An empty list, an address
// that does not parse and an entry that does not parse admit nothing
// (fail closed).
func AddressAllowed(allow []string, ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, e := range allow {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			continue
		}
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// checkPoliceAccess validates the agency and the allow-list of an
// account of realm, returning the canonical list. A police account
// needs both, a console account neither.
func checkPoliceAccess(realm, agency string, allow []string) (string, []string, error) {
	agency = strings.TrimSpace(agency)
	if realm != apiserver.RealmPolice {
		var errs []error
		if agency != "" {
			errs = append(errs, core.Fieldf("agency", "only a police account names an agency"))
		}
		if len(allow) > 0 {
			errs = append(errs, core.Fieldf("ip_allowlist", "only a police account has an IP allow-list"))
		}
		return "", []string{}, errors.Join(errs...)
	}
	var errs []error
	if !agencyPattern.MatchString(agency) {
		errs = append(errs, core.Fieldf("agency", "required: 1 to 100 of letters, digits, space . _ -, starting with a letter or digit"))
	}
	list, err := ParseAllowList("ip_allowlist", allow)
	if err != nil {
		errs = append(errs, err)
	} else if len(list) == 0 {
		errs = append(errs, core.Fieldf("ip_allowlist", "required: a police account signs in and queries only from the addresses it names"))
	}
	return agency, list, errors.Join(errs...)
}

// SetPoliceAccess replaces the agency and the allow-list of a police
// account and ends its sessions, so the new list applies at once.
func (s *Service) SetPoliceAccess(ctx context.Context, id, agency string, allow []string, actor audit.Actor) (User, error) {
	agency, list, err := checkPoliceAccess(apiserver.RealmPolice, agency, allow)
	if err != nil {
		return User{}, err
	}
	now := s.now()
	var out User
	err = s.Store.InTx(ctx, func(tx Tx) error {
		before, err := tx.UserForUpdate(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return userNotFound(id)
		}
		if err != nil {
			return err
		}
		if before.Realm != apiserver.RealmPolice {
			return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "a console account has no agency or allow-list",
				core.Fieldf("user_id", "the account is of the %s realm", before.Realm))
		}
		if out, err = tx.SetUserPoliceAccess(ctx, id, agency, list, now, actor.ID); err != nil {
			return err
		}
		revoked, err := tx.RevokeUserSessions(ctx, id, now, actor.ID, "police_access_changed")
		if err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "user", EntityID: id, EventType: audit.EventUserPoliceAccessChange,
			Payload: map[string]any{
				"before":           map[string]any{"agency": before.Agency, "ip_allowlist": before.IPAllow},
				"after":            map[string]any{"agency": out.Agency, "ip_allowlist": out.IPAllow},
				"sessions_revoked": revoked,
			},
		})
	})
	return out, err
}
