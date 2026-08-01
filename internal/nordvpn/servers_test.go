package nordvpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", "servers.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return blob
}

func TestUsableExcludesDedicatedIP(t *testing.T) {
	t.Parallel()
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	usable := list.Usable()
	if len(usable) != 2 {
		names := make([]string, 0, len(usable))
		for _, s := range usable {
			names = append(names, s.Hostname)
		}
		t.Fatalf("Usable() = %d servers %v, want 2 (Dedicated IP and Double VPN dropped)", len(usable), names)
	}
	for _, server := range usable {
		if server.hasGroup(groupDedicatedIP) {
			t.Errorf("Usable() kept dedicated-IP server %q, which the account cannot connect to", server.Hostname)
		}
	}
}

func TestServerCarriesWireGuardPublicKeyAndEndpoint(t *testing.T) {
	t.Parallel()
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, server := range list.Usable() {
		if server.PublicKey == "" {
			t.Errorf("%s: PublicKey is empty", server.Hostname)
		}
		if want := server.Station + ":51820"; server.Endpoint() != want {
			t.Errorf("%s: Endpoint() = %q, want %q", server.Hostname, server.Endpoint(), want)
		}
	}
}

func TestGeographyLabels(t *testing.T) {
	t.Parallel()
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byHost := map[string]Server{}
	for _, s := range list.Usable() {
		byHost[s.Hostname] = s
	}
	kr, ok := byHost["kr100.nordvpn.com"]
	if !ok {
		t.Fatalf("kr100 missing from usable set")
	}
	if kr.Country != "kr" {
		t.Errorf("Country = %q, want %q", kr.Country, "kr")
	}
	if kr.City() != "kr-seoul" {
		t.Errorf("City() = %q, want %q", kr.City(), "kr-seoul")
	}
	if kr.SlotID() != "kr100" {
		t.Errorf("SlotID() = %q, want %q", kr.SlotID(), "kr100")
	}
	if got := list.Countries(); len(got) != 2 {
		t.Errorf("Countries() = %v, want 2", got)
	}
}

func TestParseRejectsEmptyList(t *testing.T) {
	t.Parallel()
	if _, err := parse([]byte(`[]`)); err == nil {
		t.Fatal("parse([]) returned no error, want one")
	}
}

// Secrets must never reach an error string: the catalog these servers feed is
// built with an account private key, and errors travel into logs.
func TestErrorsRedactEndpointAndSecrets(t *testing.T) {
	t.Parallel()
	secret := testKey(0x40)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	secretURL := server.URL + "/v1/servers?token=" + secret
	_, err := Fetch(context.Background(), secretURL)
	if err == nil {
		t.Fatal("Fetch against a 401 returned no error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked the token: %q", err)
	}
	if strings.Contains(err.Error(), server.URL) {
		t.Errorf("error leaked the endpoint URL: %q", err)
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	_, err = Fetch(context.Background(), badJSON.URL+"?token="+secret)
	if err == nil {
		t.Fatal("Fetch against malformed JSON returned no error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), badJSON.URL) {
		t.Errorf("parse error leaked request details: %q", err)
	}
}

func TestLoadOrFetchPrefersFreshCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cache := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(cache, fixture(t), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(fixture(t))
	}))
	defer server.Close()

	list, fetched, err := LoadOrFetch(context.Background(), server.URL, cache, time.Hour)
	if err != nil {
		t.Fatalf("LoadOrFetch: %v", err)
	}
	if fetched || hits != 0 {
		t.Errorf("fresh cache still hit the network (fetched=%v hits=%d)", fetched, hits)
	}
	if len(list.Usable()) != 2 {
		t.Errorf("cached list produced %d usable servers, want 2", len(list.Usable()))
	}
}

func TestSaveWritesPrivateFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "servers.json")

	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := list.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The server list is not itself secret, but it sits next to material that is,
	// so it inherits the strict mode rather than 0644.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("Save wrote mode %o, want 600", perm)
	}
	var roundTrip []Server
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if err := json.Unmarshal(blob, &roundTrip); err != nil {
		t.Fatalf("saved file is not valid JSON: %v", err)
	}
}

// testKey builds a key-shaped base64 string at run time. Writing one as a literal
// would be indistinguishable from a real WireGuard key to a secret scanner, and to
// a contributor copying the fixture somewhere real.
func testKey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
