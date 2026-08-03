package main

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minpeter/global-egress/internal/catalog"
)

// The NordLynx key file is the account's VPN identity. A world-readable key is an
// operator mistake the tool must refuse rather than quietly accept.
func TestReadPrivateKeyRejectsLoosePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nordlynx.key")
	key := testKey(0x11)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readPrivateKeyFile(path); err == nil {
		t.Fatal("readPrivateKeyFile accepted a 0644 key file, want a refusal")
	} else if strings.Contains(err.Error(), key) {
		t.Errorf("refusal leaked the key: %q", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("readPrivateKeyFile on a 0600 file: %v", err)
	}
	if got != key {
		t.Error("readPrivateKeyFile did not return the key it read")
	}
}

// A missing or empty key file must fail without echoing the path's contents.
func TestReadPrivateKeyRejectsEmptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKeyFile(path); err == nil {
		t.Fatal("readPrivateKeyFile accepted an empty key file")
	}
}

func TestCatalogFileNamesCarryGeography(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	slots := []catalog.Slot{{
		ID:            "kr101",
		Country:       "kr",
		City:          "kr-seoul",
		PrivateKey:    testKey(0x11),
		Addresses:     []netip.Addr{netip.MustParseAddr("10.5.0.2")},
		DNS:           []netip.Addr{netip.MustParseAddr("103.86.96.100")},
		MTU:           catalog.DefaultMTU,
		PeerPublicKey: testKey(0x22),
		Endpoint:      "89.147.101.116:51820",
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Source:        "kr101.nordvpn.com",
	}}
	if _, err := writeCatalog(dir, slots); err != nil {
		t.Fatalf("writeCatalog: %v", err)
	}

	// The catalog parser recovers geography from the file name, so a name the
	// regexp cannot read silently drops cc= and city= filtering.
	bundle, err := catalog.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(bundle.Slots) != 1 {
		t.Fatalf("LoadDir returned %d slots, want 1", len(bundle.Slots))
	}
	got := bundle.Slots[0]
	if got.Country != "kr" {
		t.Errorf("round-tripped Country = %q, want %q", got.Country, "kr")
	}
	if got.City != "kr-seoul" {
		t.Errorf("round-tripped City = %q, want %q", got.City, "kr-seoul")
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

func TestWriteCatalogReplacesObsoleteFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := writeCatalog(dir, []catalog.Slot{newTestSlot("kr999", "kr", "kr-seoul")}); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	stale := filepath.Join(dir, "kr-seoul-kr999.conf")

	slots := []catalog.Slot{newTestSlot("kr101", "kr", "kr-seoul")}
	if _, err := writeCatalog(dir, slots); err != nil {
		t.Fatalf("writeCatalog: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("a server that is no longer selected stayed in the catalog: %v", err)
	}
}

func TestWriteCatalogTightensLoosePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	slot := newTestSlot("kr101", "kr", "kr-seoul")
	if _, err := writeCatalog(dir, []catalog.Slot{slot}); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "kr-seoul-kr101.conf")
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := writeCatalog(dir, []catalog.Slot{slot}); err != nil {
		t.Fatalf("writeCatalog: %v", err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("catalog dir left at mode %o, want 700", perm)
	}
	fileInfo, err := os.Stat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("key-bearing file left at mode %o, want 600", perm)
	}
}

func TestWriteCatalogRejectsPathEscape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	evil := newTestSlot("../../etc/evil", "kr", "kr-seoul")
	if _, err := writeCatalog(dir, []catalog.Slot{evil}); err == nil {
		t.Fatal("writeCatalog accepted an ID that escapes the catalog directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "etc", "evil.conf")); err == nil {
		t.Fatal("writeCatalog wrote outside the catalog directory")
	}
}

// A city whose name contains a hyphen must survive the round trip through the
// file name, or cc=/city= selection disagrees with the provider metadata.
func TestMultiWordCityRoundTrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	slot := newTestSlot("us13647", "us", "us-saint-louis")
	if _, err := writeCatalog(dir, []catalog.Slot{slot}); err != nil {
		t.Fatalf("writeCatalog: %v", err)
	}
	bundle, err := catalog.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got := bundle.Slots[0].City; got != "us-saint-louis" {
		t.Errorf("City round-tripped as %q, want %q", got, "us-saint-louis")
	}
}

func newTestSlot(id, country, city string) catalog.Slot {
	return catalog.Slot{
		ID:            id,
		Country:       country,
		City:          city,
		PrivateKey:    testKey(0x11),
		Addresses:     []netip.Addr{netip.MustParseAddr("10.5.0.2")},
		DNS:           []netip.Addr{netip.MustParseAddr("103.86.96.100")},
		MTU:           catalog.DefaultMTU,
		PeerPublicKey: testKey(0x22),
		Endpoint:      "203.0.113.10:51820",
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Source:        id + ".nordvpn.com",
	}
}
