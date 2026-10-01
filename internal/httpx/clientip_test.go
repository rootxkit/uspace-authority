package httpx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

func mustProxies(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	p, err := ParseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The client is the rightmost untrusted X-Forwarded-For hop, and only
// when the peer is a trusted proxy; each case beside its twin.
func TestClientIP(t *testing.T) {
	caddy := mustProxies(t, "10.0.0.0/8", "::1")
	cases := []struct {
		name, peer string
		xff        []string
		proxies    []netip.Prefix
		want       string
	}{
		{"no proxies: peer, header ignored", "198.51.100.7:4000", []string{"203.0.113.9"}, nil, "198.51.100.7"},
		{"untrusted peer: header ignored", "198.51.100.7:4000", []string{"203.0.113.9"}, caddy, "198.51.100.7"},
		{"trusted peer: the forwarded client", "10.0.0.2:4000", []string{"203.0.113.9"}, caddy, "203.0.113.9"},
		{"spoofed left part ignored", "10.0.0.2:4000", []string{"1.2.3.4, 203.0.113.9"}, caddy, "203.0.113.9"},
		{"chain of trusted proxies", "10.0.0.2:4000", []string{"203.0.113.9, 10.1.1.1", "10.2.2.2"}, caddy, "203.0.113.9"},
		{"all hops trusted: leftmost", "10.0.0.2:4000", []string{"10.9.9.9"}, caddy, "10.9.9.9"},
		{"unparsable hop: the proxy that wrote it", "10.0.0.2:4000", []string{"garbage, 10.3.3.3"}, caddy, "10.3.3.3"},
		{"unparsable last hop: the peer", "10.0.0.2:4000", []string{"garbage"}, caddy, "10.0.0.2"},
		{"no header: the peer", "10.0.0.2:4000", nil, caddy, "10.0.0.2"},
		{"ipv6 loopback proxy", "[::1]:4000", []string{"2001:db8::7"}, caddy, "2001:db8::7"},
		{"peer without a port", "10.0.0.2", []string{"203.0.113.9"}, caddy, "203.0.113.9"},
	}
	for _, c := range cases {
		if got := ClientIP(c.peer, c.xff, c.proxies); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	long := strings.Repeat("10.5.5.5, ", 100) + "203.0.113.1"
	if got := ClientIP("10.0.0.2:1", []string{"198.51.100.1, " + long}, caddy); got != "203.0.113.1" {
		t.Fatalf("long chain: %q", got)
	}
	if _, err := ParseTrustedProxies([]string{"caddy"}); err == nil {
		t.Fatal("a name accepted as a proxy")
	}
}

// Behind a trusted proxy every client gets its own rate-limit bucket;
// from an untrusted peer X-Forwarded-For buys nothing.
func TestBaselineLimitsByForwardedClient(t *testing.T) {
	c := &core.Counters{}
	h := Baseline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(RemoteIP(r))) }),
		discard(), BaselineDeps{Counters: c, RateLimiter: NewRateLimiter(0.001, 1, 10, c), TrustedProxies: mustProxies(t, "10.0.0.0/8")})
	do := func(peer, xff string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	if code, ip := do("10.0.0.2:1", "203.0.113.1"); code != 200 || ip != "203.0.113.1" {
		t.Fatalf("first client: %d %q", code, ip)
	}
	if code, _ := do("10.0.0.2:1", "203.0.113.2"); code != 200 {
		t.Fatal("a second client behind the proxy shared the first one's bucket")
	}
	if code, _ := do("10.0.0.2:1", "203.0.113.1"); code != 429 {
		t.Fatal("the first client's bucket was not its own")
	}
	if code, _ := do("198.51.100.5:1", "203.0.113.3"); code != 200 {
		t.Fatal("untrusted peer, first request")
	}
	if code, _ := do("198.51.100.5:1", "203.0.113.4"); code != 429 {
		t.Fatal("an untrusted peer escaped its bucket by changing X-Forwarded-For")
	}
}

func FuzzClientIP(f *testing.F) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	f.Add("10.0.0.2:1", "203.0.113.9, 10.1.1.1")
	f.Add("x", ",,,")
	f.Fuzz(func(t *testing.T, peer, xff string) {
		got := ClientIP(peer, []string{xff}, proxies)
		if host, _, err := splitHost(peer); err == nil {
			if a, err := netip.ParseAddr(host); err == nil && !proxies[0].Contains(a.Unmap()) && got != host {
				t.Fatalf("untrusted peer %q yielded %q", peer, got)
			}
		}
	})
}

func splitHost(peer string) (string, string, error) { return net.SplitHostPort(peer) }
