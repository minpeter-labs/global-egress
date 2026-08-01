package nordvpn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrFetch_refresh_does_not_fallback_to_stale_cache(t *testing.T) {
	// Given
	cache := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(cache, fixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// When
	_, _, err := LoadOrFetch(context.Background(), LoadOptions{
		URL:        server.URL,
		CachePath:  cache,
		MaxAge:     0,
		AllowStale: false,
	})

	// Then
	if err == nil {
		t.Fatal("forced refresh silently returned the stale cache")
	}
}

func TestFetch_refuses_cross_host_redirect(t *testing.T) {
	// Given
	secret := testKey(0x40)
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		targetHits++
		_, _ = writer.Write(fixture(t))
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+"/servers", http.StatusFound)
	}))
	defer source.Close()

	// When
	_, err := Fetch(context.Background(), source.URL+"?token="+secret)

	// Then
	if err == nil {
		t.Fatal("Fetch followed a cross-host redirect")
	}
	if targetHits != 0 {
		t.Fatalf("redirect target received %d requests", targetHits)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), source.URL) {
		t.Fatalf("redirect refusal leaked request details: %q", err)
	}
}

func TestServerUnmarshal_resets_flattened_fields(t *testing.T) {
	// Given
	var servers []Server
	if err := json.Unmarshal(fixture(t), &servers); err != nil {
		t.Fatal(err)
	}
	server := servers[0]
	replacement := []byte(`{"hostname":"new.nordvpn.com","station":"203.0.113.9","status":"online","load":1}`)

	// When
	if err := json.Unmarshal(replacement, &server); err != nil {
		t.Fatal(err)
	}

	// Then
	if server.PublicKey != "" || server.Country != "" || server.CityName != "" || len(server.groups) != 0 {
		t.Fatalf("stale flattened state survived decode: %#v", server)
	}
}
