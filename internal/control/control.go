// Package control exposes the pool's management API over HTTP.
//
// This is the channel a client uses when it detects that an egress has been
// blocked: it reports the block, the pool puts that slot on cooldown for that
// destination only, and the next request is served from a different IP.
package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/minpeter/global-egress/internal/pool"
)

// Options configures the control server.
type Options struct {
	Pool           *pool.Pool
	Logger         *slog.Logger
	AllowedClients []netip.Prefix
	// Token, when set, must be presented as "Authorization: Bearer <token>".
	Token string
	// Version is reported by /v1/info.
	Version string
	// StartedAt is reported by /v1/info.
	StartedAt time.Time
}

// Server implements the control API.
type Server struct {
	opts Options
	mux  *http.ServeMux
}

// New builds the control server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{opts: opts, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /v1/info", s.handleInfo)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("GET /v1/metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /v1/country-acquisitions", s.handleCountryAcquisitions)
	s.mux.HandleFunc("GET /v1/slots", s.handleSlots)
	s.mux.HandleFunc("GET /v1/entries", s.handleEntries)
	s.mux.HandleFunc("GET /v1/ips", s.handleIPs)
	s.mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
	s.mux.HandleFunc("GET /v1/sessions/{name}", s.handleSession)
	s.mux.HandleFunc("POST /v1/sessions/{name}/rotate", s.handleRotate)
	s.mux.HandleFunc("DELETE /v1/sessions/{name}", s.handleRotate)
	s.mux.HandleFunc("POST /v1/report", s.handleReport)
}

// ServeHTTP applies access control and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.checkClient(r.RemoteAddr); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.opts.Token != "" && !s.tokenOK(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="global-egress"`)
		writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) checkClient(remoteAddr string) error {
	if len(s.opts.AllowedClients) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("cannot parse client address %q", remoteAddr)
	}
	addr = addr.Unmap()
	for _, prefix := range s.opts.AllowedClients {
		if prefix.Addr().Is4() == addr.Is4() && prefix.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("client %s is not allowed", addr)
}

func (s *Server) tokenOK(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(value)), []byte(s.opts.Token)) == 1
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    s.opts.Version,
		"started_at": s.opts.StartedAt,
		"uptime":     time.Since(s.opts.StartedAt).Round(time.Second).String(),
		"slots":      s.opts.Pool.Len(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Pool.Stats())
}

func (s *Server) handleCountryAcquisitions(w http.ResponseWriter, _ *http.Request) {
	countries := s.opts.Pool.CountryAcquisitions()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(countries),
		"countries": countries,
	})
}

func (s *Server) handleSlots(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := pool.SlotFilter{
		Country:  query.Get("country"),
		City:     query.Get("city"),
		OpenOnly: query.Get("open") == "1" || query.Get("open") == "true",
		WithIP:   query.Get("with_ip") == "1" || query.Get("with_ip") == "true",
	}
	slots := s.opts.Pool.Slots(filter)

	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		if limit < len(slots) {
			slots = slots[:limit]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(slots), "slots": slots})
}

// handleEntries reports the shared entry tunnels and the latency measured through
// them, which is what decides regional routing.
func (s *Server) handleEntries(w http.ResponseWriter, _ *http.Request) {
	entries := s.opts.Pool.Entries()
	writeJSON(w, http.StatusOK, map[string]any{"count": len(entries), "entries": entries})
}

func (s *Server) handleIPs(w http.ResponseWriter, _ *http.Request) {
	ips := s.opts.Pool.UniquePublicIPs()
	writeJSON(w, http.StatusOK, map[string]any{"count": len(ips), "ips": ips})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("sess")
	if name == "" {
		writeError(w, http.StatusBadRequest, "query parameter sess is required")
		return
	}
	s.writeSession(w, name)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.writeSession(w, r.PathValue("name"))
}

func (s *Server) writeSession(w http.ResponseWriter, name string) {
	info, ok := s.opts.Pool.Session(name)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("session %q is not bound", name))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "session name is required")
		return
	}
	rotated := s.opts.Pool.Rotate(name)
	s.opts.Logger.Info("session rotated via API",
		slog.String("session", name), slog.Bool("was_bound", rotated))
	writeJSON(w, http.StatusOK, map[string]any{
		"session": name,
		"rotated": rotated,
		"note":    "the next request for this session selects a new slot",
	})
}

// reportRequest is the body of POST /v1/report.
type reportRequest struct {
	// Session is the sticky session that hit the block.
	Session string `json:"session"`
	// Slot names the egress directly, when the caller knows it (for example from
	// the X-Egress-Slot response header).
	Slot string `json:"slot"`
	// Target is the destination that blocked us. A bare host is expected; a full
	// URL is accepted and reduced to its host.
	Target string `json:"target"`
	// Reason is free-form, for operator logs, e.g. "http_403".
	Reason string `json:"reason"`
	// Cooldown overrides the configured default, e.g. "30m".
	Cooldown string `json:"cooldown"`
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var body reportRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if body.Session == "" && body.Slot == "" {
		writeError(w, http.StatusBadRequest, "either session or slot is required")
		return
	}

	var cooldown time.Duration
	if body.Cooldown != "" {
		parsed, err := time.ParseDuration(body.Cooldown)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "cooldown must be a duration such as \"30m\"")
			return
		}
		cooldown = parsed
	}

	result, err := s.opts.Pool.Report(pool.ReportInput{
		Session:  body.Session,
		Slot:     body.Slot,
		Target:   normalizeTarget(body.Target),
		Reason:   body.Reason,
		Cooldown: cooldown,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// normalizeTarget reduces "https://example.com/path" to "example.com" so that
// clients can pass whatever they have at hand.
func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if idx := strings.Index(target, "://"); idx >= 0 {
		target = target[idx+3:]
	}
	if idx := strings.IndexAny(target, "/?#"); idx >= 0 {
		target = target[:idx]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	return strings.ToLower(strings.Trim(target, "[]"))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// ErrClosed is returned by Serve after a graceful shutdown.
var ErrClosed = errors.New("control: server closed")
