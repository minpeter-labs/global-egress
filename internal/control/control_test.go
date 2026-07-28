package control

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/pool"
)

func newTestServer(t *testing.T, opts Options) (*Server, *pool.Pool) {
	t.Helper()
	bundle := &catalog.Bundle{DistinctKeys: 1}
	for _, spec := range []struct{ id, country, city string }{
		{"jp-tyo-wg-001", "jp", "jp-tyo"},
		{"us-lax-wg-001", "us", "us-lax"},
	} {
		bundle.Slots = append(bundle.Slots, catalog.Slot{
			ID:            spec.id,
			Country:       spec.country,
			City:          spec.city,
			PrivateKey:    "R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=",
			PeerPublicKey: "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
			Addresses:     []netip.Addr{netip.MustParseAddr("10.64.0.2")},
			Endpoint:      "198.51.100.1:51820",
		})
	}
	egressPool, err := pool.New(bundle, pool.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	t.Cleanup(egressPool.Close)

	opts.Pool = egressPool
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return New(opts), egressPool
}

func do(t *testing.T, server *Server, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = "10.0.0.5:40000"
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndStats(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	if rec := do(t, server, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d", rec.Code)
	}

	rec := do(t, server, http.MethodGet, "/v1/stats", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/stats status = %d", rec.Code)
	}
	var stats pool.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.Slots != 2 {
		t.Errorf("stats.Slots = %d, want 2", stats.Slots)
	}
}

func TestSlotsFilteringAndLimit(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	var payload struct {
		Count int             `json:"count"`
		Slots []pool.SlotInfo `json:"slots"`
	}
	rec := do(t, server, http.MethodGet, "/v1/slots?country=jp", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 1 || payload.Slots[0].ID != "jp-tyo-wg-001" {
		t.Errorf("unexpected payload %+v", payload)
	}

	rec = do(t, server, http.MethodGet, "/v1/slots?limit=1", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 1 {
		t.Errorf("limit ignored: count = %d", payload.Count)
	}

	if rec := do(t, server, http.MethodGet, "/v1/slots?limit=-4", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("negative limit status = %d, want 400", rec.Code)
	}
}

func TestWhoamiRequiresSession(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	if rec := do(t, server, http.MethodGet, "/v1/whoami", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("missing sess status = %d, want 400", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/whoami?sess=nope", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unbound sess status = %d, want 404", rec.Code)
	}
}

func TestRotateIsIdempotent(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	rec := do(t, server, http.MethodPost, "/v1/sessions/job-1/rotate", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d", rec.Code)
	}
	var payload struct {
		Session string `json:"session"`
		Rotated bool   `json:"rotated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Session != "job-1" || payload.Rotated {
		t.Errorf("unexpected payload %+v (nothing was bound yet)", payload)
	}
}

func TestReportValidation(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	cases := []struct {
		name, body string
		want       int
	}{
		{"not json", "{", http.StatusBadRequest},
		{"neither session nor slot", `{"target":"example.com"}`, http.StatusBadRequest},
		{"bad cooldown", `{"slot":"jp-tyo-wg-001","cooldown":"soon"}`, http.StatusBadRequest},
		{"unknown field", `{"slot":"jp-tyo-wg-001","nope":1}`, http.StatusBadRequest},
		{"unknown slot", `{"slot":"zz-zzz-wg-001"}`, http.StatusNotFound},
		{"valid", `{"slot":"jp-tyo-wg-001","target":"https://example.com/a?b=1","reason":"http_403"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, server, http.MethodPost, "/v1/report", tc.body,
				map[string]string{"Content-Type": "application/json"})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestReportNormalisesTarget(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	rec := do(t, server, http.MethodPost, "/v1/report",
		`{"slot":"jp-tyo-wg-001","target":"HTTPS://Example.COM:443/path"}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var result pool.ReportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != "example.com" {
		t.Errorf("Target = %q, want example.com", result.Target)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"example.com":                  "example.com",
		"https://example.com/a/b":      "example.com",
		"http://example.com:8080/x":    "example.com",
		"EXAMPLE.com":                  "example.com",
		"example.com:443":              "example.com",
		"https://user.example.com?q=1": "user.example.com",
	}
	for input, want := range cases {
		if got := normalizeTarget(input); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClientACL(t *testing.T) {
	server, _ := newTestServer(t, Options{
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.RemoteAddr = "192.168.5.5:1234"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a client outside the ACL", rec.Code)
	}

	if rec := do(t, server, http.MethodGet, "/v1/stats", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an allowed client", rec.Code)
	}
}

func TestBearerToken(t *testing.T) {
	server, _ := newTestServer(t, Options{Token: "s3cret"})

	if rec := do(t, server, http.MethodGet, "/v1/stats", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/stats", "",
		map[string]string{"Authorization": "Bearer wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/stats", "",
		map[string]string{"Authorization": "Bearer s3cret"}); rec.Code != http.StatusOK {
		t.Errorf("valid token status = %d, want 200", rec.Code)
	}
}
