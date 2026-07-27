package mullvad

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleJSON = `[
  {"hostname":"us-lax-wg-001","country_code":"us","city_code":"lax","city_name":"Los Angeles",
   "socks_name":"us-lax-wg-socks5-001.relays.mullvad.net","socks_port":1080,"active":true,
   "owned":false,"ipv4_addr_in":"1.2.3.4","type":"wireguard"},
  {"hostname":"jp-tyo-wg-001","country_code":"jp","city_code":"tyo","city_name":"Tokyo",
   "socks_name":"jp-tyo-wg-socks5-001.relays.mullvad.net","socks_port":0,"active":true,
   "owned":true,"ipv4_addr_in":"5.6.7.8","type":"wireguard"},
  {"hostname":"de-fra-wg-009","country_code":"de","city_code":"fra","city_name":"Frankfurt",
   "socks_name":"de-fra-wg-socks5-009.relays.mullvad.net","socks_port":1080,"active":false,
   "owned":false,"ipv4_addr_in":"9.9.9.9","type":"wireguard"},
  {"hostname":"no-socks-wg-001","country_code":"se","city_code":"sto","city_name":"Stockholm",
   "socks_name":"","socks_port":0,"active":true,"owned":false,"ipv4_addr_in":"8.8.8.8",
   "type":"wireguard"}
]`

func TestUsableFiltersInactiveAndProxyless(t *testing.T) {
	t.Parallel()
	list, err := parse([]byte(sampleJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	usable := list.Usable()
	if len(usable) != 2 {
		t.Fatalf("Usable() = %d relays, want 2 (inactive and proxyless dropped)", len(usable))
	}
	// Sorted by slot ID for stable output.
	if usable[0].SlotID() != "jp-tyo-wg-socks5-001" {
		t.Errorf("first usable relay = %q", usable[0].SlotID())
	}
	if got := list.Countries(); len(got) != 2 {
		t.Errorf("Countries() = %v, want 2", got)
	}
	if got := list.Cities(); len(got) != 2 || got[0] != "jp-tyo" {
		t.Errorf("Cities() = %v", got)
	}
}

func TestRelayAccessors(t *testing.T) {
	t.Parallel()
	list, err := parse([]byte(sampleJSON))
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]Relay{}
	for _, relay := range list.Relays {
		byHost[relay.Hostname] = relay
	}

	lax := byHost["us-lax-wg-001"]
	if lax.City() != "us-lax" {
		t.Errorf("City() = %q", lax.City())
	}
	if lax.SocksAddr() != "us-lax-wg-socks5-001.relays.mullvad.net:1080" {
		t.Errorf("SocksAddr() = %q", lax.SocksAddr())
	}
	if lax.SlotID() != "us-lax-wg-socks5-001" {
		t.Errorf("SlotID() = %q", lax.SlotID())
	}

	// A missing port must fall back to the default rather than produce ":0".
	tyo := byHost["jp-tyo-wg-001"]
	if tyo.SocksAddr() != "jp-tyo-wg-socks5-001.relays.mullvad.net:1080" {
		t.Errorf("SocksAddr() with port 0 = %q", tyo.SocksAddr())
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := parse([]byte(`[]`)); err == nil {
		t.Error("expected an error for an empty list")
	}
	if _, err := parse([]byte(`not json`)); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func TestSaveAndLoad(t *testing.T) {
	t.Parallel()
	list, err := parse([]byte(sampleJSON))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "relays.json")
	if err := list.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(loaded.Relays) != len(list.Relays) {
		t.Errorf("round trip changed the list: %d vs %d", len(loaded.Relays), len(list.Relays))
	}
	if loaded.FetchedAt.IsZero() {
		t.Error("FetchedAt should come from the file modification time")
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleJSON))
	}))
	defer server.Close()

	list, err := Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(list.Relays) != 4 {
		t.Errorf("Fetch returned %d relays, want 4", len(list.Relays))
	}
}

func TestFetchBadStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	if _, err := Fetch(context.Background(), server.URL); err == nil {
		t.Error("expected an error for a 500 response")
	}
}

func TestLoadOrFetchUsesFreshCache(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relays.json")
	if err := os.WriteFile(path, []byte(sampleJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	// An unreachable URL proves the cache was used rather than the network.
	list, fetched, err := LoadOrFetch(context.Background(), "http://127.0.0.1:1", path, time.Hour)
	if err != nil {
		t.Fatalf("LoadOrFetch: %v", err)
	}
	if fetched {
		t.Error("a fresh cache should not trigger a fetch")
	}
	if len(list.Relays) != 4 {
		t.Errorf("got %d relays", len(list.Relays))
	}
}

func TestLoadOrFetchFallsBackToStaleCache(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relays.json")
	if err := os.WriteFile(path, []byte(sampleJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	// Zero maxAge forces a fetch attempt; it fails, so the stale cache must win.
	list, fetched, err := LoadOrFetch(context.Background(), "http://127.0.0.1:1", path, 0)
	if err != nil {
		t.Fatalf("LoadOrFetch: %v", err)
	}
	if fetched {
		t.Error("fetched should be false when the network failed")
	}
	if len(list.Relays) != 4 {
		t.Errorf("got %d relays", len(list.Relays))
	}
}

func TestLoadOrFetchNoCacheNoNetwork(t *testing.T) {
	t.Parallel()
	_, _, err := LoadOrFetch(context.Background(), "http://127.0.0.1:1",
		filepath.Join(t.TempDir(), "absent.json"), time.Hour)
	if err == nil {
		t.Error("expected an error with neither cache nor network")
	}
}
