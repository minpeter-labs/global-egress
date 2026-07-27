package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minpeter-labs/global-egress/internal/policy"
	"github.com/minpeter-labs/global-egress/internal/pool"
)

// HTTPServer serves the pool as an HTTP forward proxy.
//
// It handles both proxy styles:
//
//	CONNECT host:443            tunnelled, used for every https:// request
//	GET http://host/path        absolute-URI, used for plain http://
//
// Clients therefore only need HTTP_PROXY/HTTPS_PROXY pointing here.
type HTTPServer struct {
	deps *Deps
}

// NewHTTP builds an HTTP proxy server.
func NewHTTP(deps Deps) *HTTPServer {
	deps.applyDefaults()
	return &HTTPServer{deps: &deps}
}

// Serve accepts connections until the listener is closed.
func (s *HTTPServer) Serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler: s,
		// Proxied sessions can be long-lived, so no global write timeout; idle
		// enforcement happens in the relay instead.
		ReadHeaderTimeout: handshakeTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP implements the proxy.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := s.deps.Logger.With(slog.String("proto", "http"),
		slog.String("client", r.RemoteAddr))

	remote, err := addrFromString(r.RemoteAddr)
	if err == nil {
		if err := s.deps.checkClient(remote); err != nil {
			log.Warn("client rejected", slog.Any("error", err))
			http.Error(w, "client not allowed", http.StatusForbidden)
			return
		}
	}

	username, password, hadCredentials := proxyCredentials(r)
	pol, err := s.deps.authorize(username, password, hadCredentials)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="global-egress"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		// A malformed policy is the client's mistake; say so precisely.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, pol, log)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "global-egress is a forward proxy; configure it as HTTP_PROXY/HTTPS_PROXY",
			http.StatusBadRequest)
		return
	}
	s.handleForward(w, r, pol, log)
}

// handleConnect tunnels an arbitrary TCP stream, which is how HTTPS is proxied.
func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request, pol policy.Policy, log *slog.Logger) {
	host, port, err := splitTargetHostPort(r.Host, 443)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	upstream, lease, err := s.deps.connectUpstream(r.Context(), pol, host, port)
	if err != nil {
		log.Warn("connect failed",
			slog.String("target", r.Host),
			slog.String("policy", pol.String()),
			slog.Any("error", err))
		http.Error(w, err.Error(), statusCodeFor(err))
		return
	}
	defer lease.Release()
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Warn("hijack failed", slog.Any("error", err))
		return
	}
	defer client.Close()

	// Report the chosen egress in the CONNECT response so clients can log or
	// react to the IP they were given.
	var header strings.Builder
	header.WriteString("HTTP/1.1 200 Connection Established\r\n")
	for key, value := range egressHeaders(lease) {
		fmt.Fprintf(&header, "%s: %s\r\n", key, value)
	}
	header.WriteString("\r\n")
	if _, err := client.Write([]byte(header.String())); err != nil {
		return
	}

	// Anything the client pipelined after CONNECT must be forwarded first.
	if buffered != nil && buffered.Reader.Buffered() > 0 {
		if _, err := io.CopyN(upstream, buffered, int64(buffered.Reader.Buffered())); err != nil {
			return
		}
	}

	started := time.Now()
	sent, received := relay(client, upstream, s.deps.IdleTimeout)
	log.Info("session finished",
		slog.String("target", net.JoinHostPort(host, strconv.Itoa(port))),
		slog.String("slot", lease.Slot.ID),
		slog.String("egress_ip", ipString(lease)),
		slog.String("policy", pol.String()),
		slog.Int64("sent", sent),
		slog.Int64("received", received),
		slog.Duration("duration", time.Since(started)))
}

// hopByHopHeaders must not be forwarded to the origin server.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleForward performs a plain http:// request on the client's behalf.
func (s *HTTPServer) handleForward(w http.ResponseWriter, r *http.Request, pol policy.Policy, log *slog.Logger) {
	host, port, err := splitTargetHostPort(r.URL.Host, 80)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "only http:// absolute URIs are supported; use CONNECT for https://",
			http.StatusBadRequest)
		return
	}

	lease, err := s.deps.Pool.Acquire(r.Context(), pol, host)
	if err != nil {
		log.Warn("acquire failed", slog.String("policy", pol.String()), slog.Any("error", err))
		http.Error(w, err.Error(), statusCodeFor(err))
		return
	}
	defer lease.Release()

	if err := s.deps.Guard.CheckPort(port); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.deps.Guard.CheckHost(host); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// One transport per request keeps slot selection honest: a pooled connection
	// would silently pin later requests to an earlier slot.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := lease.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if !lease.Chained {
				if err := s.deps.Guard.CheckResolved(conn.RemoteAddr()); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer transport.CloseIdleConnections()

	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	for _, header := range hopByHopHeaders {
		outbound.Header.Del(header)
	}

	started := time.Now()
	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		log.Warn("upstream request failed",
			slog.String("target", r.URL.String()),
			slog.String("slot", lease.Slot.ID),
			slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	for key, value := range egressHeaders(lease) {
		w.Header().Set(key, value)
	}
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)

	log.Info("request finished",
		slog.String("target", r.URL.String()),
		slog.String("slot", lease.Slot.ID),
		slog.String("egress_ip", ipString(lease)),
		slog.String("policy", pol.String()),
		slog.Int("status", resp.StatusCode),
		slog.Int64("bytes", written),
		slog.Duration("duration", time.Since(started)))
}

// egressHeaders describe the chosen slot to the client.
func egressHeaders(lease *pool.Lease) map[string]string {
	headers := map[string]string{
		"X-Egress-Slot": lease.Slot.ID,
	}
	if lease.Slot.Country != "" {
		headers["X-Egress-Country"] = lease.Slot.Country
	}
	if lease.Slot.City != "" {
		headers["X-Egress-City"] = lease.Slot.City
	}
	if lease.PublicIP.IsValid() {
		headers["X-Egress-IP"] = lease.PublicIP.String()
	}
	if lease.Session != "" {
		headers["X-Egress-Session"] = lease.Session
	}
	return headers
}

// proxyCredentials extracts Basic credentials from Proxy-Authorization, falling
// back to Authorization for clients that confuse the two.
func proxyCredentials(r *http.Request) (username, password string, ok bool) {
	for _, header := range []string{"Proxy-Authorization", "Authorization"} {
		value := r.Header.Get(header)
		if value == "" {
			continue
		}
		scheme, encoded, found := strings.Cut(value, " ")
		if !found || !strings.EqualFold(scheme, "Basic") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			continue
		}
		user, pass, found := strings.Cut(string(raw), ":")
		if !found {
			continue
		}
		return user, pass, true
	}
	return "", "", false
}

// splitTargetHostPort parses "host", "host:port" and "[v6]:port".
func splitTargetHostPort(value string, defaultPort int) (string, int, error) {
	if value == "" {
		return "", 0, errors.New("missing destination host")
	}
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		// No port present, which is normal for an absolute URI host. Fall back to
		// the scheme's default port rather than rejecting the request.
		return strings.Trim(value, "[]"), defaultPort, nil //nolint:nilerr // a missing port is not an error
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid destination port in %q", value)
	}
	return host, port, nil
}

func addrFromString(value string) (net.Addr, error) {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}, nil
}

// statusCodeFor maps pool failures to HTTP status codes.
func statusCodeFor(err error) int {
	switch {
	case errors.Is(err, pool.ErrNoCandidate):
		// The request was understood but no egress matches the policy.
		return http.StatusConflict
	case errors.Is(err, pool.ErrCapacity), errors.Is(err, pool.ErrTunnelBudget):
		// Retryable: an existing tunnel will free up, or the rate window rolls.
		return http.StatusServiceUnavailable
	case errors.Is(err, pool.ErrExhausted):
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}
