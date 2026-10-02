package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Defaults of a Server.
const (
	DefaultMaxBodyBytes      = 1 << 20
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultMaxHeaderBytes    = 32 << 10
)

// Server is a net/http server with the baseline every listener of this
// system has: header read timeout, read, write and idle timeouts, a
// header size cap, and a Shutdown bounded by a deadline.
//
// The drain closes every connection that has not sent a request yet.
// net/http's Shutdown waits for such a connection until it is more than
// 5 s old, so a client's spare dial (an HTTP transport dials while an
// idle connection frees up and parks the new one unused), a TCP health
// check or a preconnect made a drain bound of 5 s or less overrun with
// nothing in flight, and the process exit 1. Nothing is lost: such a
// connection holds no request, as an idle keep-alive connection does
// not, and net/http closes those at once too.
type Server struct {
	Name   string // "public", "admin": names the listener in logs
	Logger *slog.Logger
	srv    *http.Server

	mu    sync.Mutex
	fresh map[net.Conn]struct{} // accepted, no request read yet (StateNew)
}

// ServerOptions configures NewServer; zero values take the defaults.
type ServerOptions struct {
	Name              string
	Addr              string
	Handler           http.Handler
	Logger            *slog.Logger
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	// NoWriteTimeout is for a listener that serves WebSockets, which
	// manage their own deadlines.
	NoWriteTimeout bool
	IdleTimeout    time.Duration
}

// NewServer returns a Server for opts.
func NewServer(opts ServerOptions) *Server {
	def := func(v, d time.Duration) time.Duration {
		if v <= 0 {
			return d
		}
		return v
	}
	writeTimeout := def(opts.WriteTimeout, DefaultWriteTimeout)
	if opts.NoWriteTimeout {
		writeTimeout = 0
	}
	s := &Server{
		Name:   opts.Name,
		Logger: opts.Logger,
		fresh:  map[net.Conn]struct{}{},
	}
	s.srv = &http.Server{
		Addr:              opts.Addr,
		Handler:           opts.Handler,
		ReadHeaderTimeout: def(opts.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		ReadTimeout:       def(opts.ReadTimeout, DefaultReadTimeout),
		WriteTimeout:      writeTimeout,
		IdleTimeout:       def(opts.IdleTimeout, DefaultIdleTimeout),
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
		ConnState:         s.track,
	}
	s.srv.RegisterOnShutdown(s.closeFresh)
	return s
}

// track keeps the connections that have not sent a request yet.
func (s *Server) track(c net.Conn, state http.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state == http.StateNew {
		s.fresh[c] = struct{}{}
		return
	}
	delete(s.fresh, c)
}

// closeFresh closes the connections that have not sent a request. It
// runs when Shutdown has closed the listeners, so no new one arrives.
func (s *Server) closeFresh() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.fresh))
	for c := range s.fresh {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if len(conns) > 0 && s.Logger != nil {
		s.Logger.Debug("drain closed connections that never sent a request", slog.String("listener", s.Name), slog.Int("connections", len(conns)))
	}
}

// newConns is how many accepted connections have not sent a request.
func (s *Server) newConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.fresh)
}

// HTTPServer exposes the underlying server (tests read its timeouts).
func (s *Server) HTTPServer() *http.Server { return s.srv }

// Listen opens the listener, so a bind error is reported before the
// process says it started.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return nil, fmt.Errorf("%s listener on %s: %w", s.Name, s.srv.Addr, err)
	}
	return ln, nil
}

// Serve serves on ln until ctx is done, then shuts down: in-flight
// requests get until drainTimeout to finish; past it the remaining
// connections are closed and Serve returns an error naming the overrun.
func (s *Server) Serve(ctx context.Context, ln net.Listener, drainTimeout time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- s.srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("%s server: %w", s.Name, err)
	case <-ctx.Done():
	}
	return s.Shutdown(drainTimeout, errc)
}

// Shutdown drains within timeout; errc, if not nil, receives the Serve
// result.
func (s *Server) Shutdown(timeout time.Duration, errc <-chan error) error {
	sctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := s.srv.Shutdown(sctx)
	if err != nil {
		_ = s.srv.Close()
		return fmt.Errorf("%s server drain exceeded %s: %w", s.Name, timeout, err)
	}
	if errc != nil {
		if serr := <-errc; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			return fmt.Errorf("%s server: %w", s.Name, serr)
		}
	}
	return nil
}

// BaselineDeps are the shared parts Baseline needs.
type BaselineDeps struct {
	Counters     *core.Counters
	RateLimiter  *RateLimiter // nil: no rate limit
	MaxBodyBytes int64        // <= 0: DefaultMaxBodyBytes
	// TrustedProxies are the proxies whose X-Forwarded-For names the
	// client (AUTHORITY_TRUSTED_PROXIES); empty means the peer is the
	// client.
	TrustedProxies []netip.Prefix
}

// Baseline wraps h with the middleware every public listener uses, in
// order: route tracking, the client address (RealIP), request id,
// access log, panic recovery, rate limit (when rl is not nil) and the
// default body cap.
func Baseline(h http.Handler, logger *slog.Logger, deps BaselineDeps) http.Handler {
	mws := []func(http.Handler) http.Handler{
		TrackRoute,
		RealIP(deps.TrustedProxies),
		RequestID,
		AccessLog(logger),
		Recover(logger, deps.Counters),
	}
	if deps.RateLimiter != nil {
		mws = append(mws, deps.RateLimiter.Middleware)
	}
	maxBody := deps.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	mws = append(mws, BodyCap(maxBody, deps.Counters))
	return Chain(captureRoute(h), mws...)
}

// NotFound answers every request no route matched with a problem, so
// even a 404 has the contract's shape.
func NotFound(w http.ResponseWriter, r *http.Request) {
	NewProblem(http.StatusNotFound, SlugNotFound, "", "no such endpoint").Write(w, r)
}
