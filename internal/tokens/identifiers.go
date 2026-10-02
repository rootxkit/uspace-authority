package tokens

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// The calling systems of M24, one client each.
const (
	SystemAuthority = "authority"
	SystemCISP      = "cisp"
	SystemANSP      = "ansp"
	SystemUSSP      = "ussp"
	SystemLab       = "lab"
)

// clientIDPattern is M24's client ids: authority-01, cisp-01, ansp-01,
// lab-01 and ussp-<code>-01, the code being certificates.code (one to
// eight upper-case alphanumerics, M8). Migration 00004_tokens checks the
// same pattern.
var clientIDPattern = regexp.MustCompile(`^(?:(authority|cisp|ansp|lab)-[0-9]{2}|(ussp)-[A-Z0-9]{1,8}-[0-9]{2})$`)

// SystemOf returns the calling system of a client id, or a field error
// on "client_id" when the id is not of M24's form.
func SystemOf(clientID string) (string, error) {
	m := clientIDPattern.FindStringSubmatch(clientID)
	if m == nil {
		return "", core.Fieldf("client_id", "%s is not a client id of the form <system>-<nn> or ussp-<code>-<nn> (M24)", quote(clientID))
	}
	if m[1] != "" {
		return m[1], nil
	}
	return m[2], nil
}

// MaxHostLen bounds an audience host (RFC 1035 name length).
const MaxHostLen = 253

// NormalizeAudience turns the audience or resource parameter of a token
// request into the host that becomes aud (M18): an absolute http or
// https URL gives its host name (no port, no path), a bare host name is
// taken as it is. Hosts are lower-cased. A value that is neither, a host
// with a port, user info, a query or a fragment, an IP literal or an
// invalid DNS name is refused.
func NormalizeAudience(raw string) (string, error) {
	if raw == "" {
		return "", core.Fieldf("audience", "empty")
	}
	if len(raw) > 2048 {
		return "", core.Fieldf("audience", "longer than 2048 bytes")
	}
	host := raw
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", core.Fieldf("audience", "%s is not an absolute http(s) URL or a host name", quote(raw))
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return "", core.Fieldf("audience", "%s carries user info, a query or a fragment", quote(raw))
		}
		host = u.Hostname()
	} else if strings.ContainsAny(raw, ":/?#@") {
		return "", core.Fieldf("audience", "%s is a host with a port or a path; name the host alone or the base URL", quote(raw))
	}
	host = strings.ToLower(host)
	if !validHostName(host) {
		return "", core.Fieldf("audience", "%s is not a DNS host name", quote(raw))
	}
	return host, nil
}

// AudienceOf is the aud for calling a system at baseURL: the host of its
// published base URL (M18). The outbound client uses it.
func AudienceOf(baseURL string) (string, error) {
	if !strings.Contains(baseURL, "://") {
		return "", core.Fieldf("base_url", "%s is not an absolute URL", quote(baseURL))
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", core.Fieldf("base_url", "%s does not parse as an absolute URL", quote(baseURL))
	}
	host := strings.ToLower(u.Hostname())
	if !validHostName(host) {
		return "", core.Fieldf("base_url", "%s has no DNS host name", quote(baseURL))
	}
	return host, nil
}

// validHostName accepts RFC 1123 host names (letters, digits, hyphens;
// labels of 1 to 63 bytes not starting or ending with a hyphen). A
// single label is allowed: a lab alias is a compose service name. IP
// literals are refused: an audience names a published host.
func validHostName(h string) bool {
	if h == "" || len(h) > MaxHostLen || net.ParseIP(h) != nil {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
