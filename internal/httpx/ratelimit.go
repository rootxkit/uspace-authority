package httpx

import (
	"container/list"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// RateLimiter is a per-client token bucket with a bounded client map
// (E-10): beyond MaxClients the least recently seen client is evicted
// (counted) and starts again with a full bucket.
type RateLimiter struct {
	rate     float64 // tokens per second
	burst    float64
	max      int
	counters *core.Counters
	now      func() time.Time
	key      func(*http.Request) string

	mu      sync.Mutex
	clients map[string]*list.Element
	order   *list.List // front = most recently seen
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// NewRateLimiter returns a limiter of ratePerS sustained requests per
// second and burst per client, remembering at most maxClients. The
// client key is the remote IP; use WithKey for anything else (a
// receiver id, a client id from a verified token).
func NewRateLimiter(ratePerS float64, burst, maxClients int, counters *core.Counters) *RateLimiter {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &RateLimiter{
		rate: ratePerS, burst: float64(burst), max: maxClients, counters: counters,
		now: time.Now, key: RemoteIP,
		clients: make(map[string]*list.Element), order: list.New(),
	}
}

// WithKey sets the client key function.
func (l *RateLimiter) WithKey(fn func(*http.Request) string) *RateLimiter {
	l.key = fn
	return l
}

// RemoteIP is the client address: the one RealIP derived from the
// trusted proxies' X-Forwarded-For when the request passed through it,
// otherwise the host part of r.RemoteAddr.
func RemoteIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Len is the number of clients remembered.
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}

// Allow takes one token from key's bucket. When it is empty it returns
// false and how long until a token is available.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *bucket
	if el, ok := l.clients[key]; ok {
		l.order.MoveToFront(el)
		b = el.Value.(*bucket)
		b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	} else {
		if len(l.clients) >= l.max {
			oldest := l.order.Back()
			l.order.Remove(oldest)
			delete(l.clients, oldest.Value.(*bucket).key)
			l.counters.Inc(CounterLimiterEvict)
		}
		b = &bucket{key: key, tokens: l.burst, last: now}
		l.clients[key] = l.order.PushFront(b)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// Middleware refuses a request over its client's budget with a 429
// problem and Retry-After (whole seconds, at least 1).
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := l.Allow(l.key(r))
		if !ok {
			l.counters.Inc(CounterRateLimited)
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
			NewProblem(http.StatusTooManyRequests, SlugRateLimited, "Too many requests", "the client's request budget is spent").Write(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
