package catalog

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const sampleConf = `[Interface]
# Device: Fast Pike
PrivateKey = R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=
Address = 10.64.232.4/32,fc00:bbbb:bbbb:bb01::1:e803/128
DNS = 10.64.0.1

[Peer]
PublicKey = ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 198.51.100.2:51820
`

func TestParseConf(t *testing.T) {
	slot, err := ParseConf("us-lax-wg-001.conf", []byte(sampleConf))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}

	if slot.ID != "us-lax-wg-001" {
		t.Errorf("ID = %q, want us-lax-wg-001", slot.ID)
	}
	if slot.Country != "us" {
		t.Errorf("Country = %q, want us", slot.Country)
	}
	if slot.City != "us-lax" {
		t.Errorf("City = %q, want us-lax", slot.City)
	}
	if slot.Device != "Fast Pike" {
		t.Errorf("Device = %q, want Fast Pike", slot.Device)
	}
	if got := len(slot.Addresses); got != 2 {
		t.Errorf("len(Addresses) = %d, want 2 (v4 and v6)", got)
	}
	if got := len(slot.DNS); got != 1 || slot.DNS[0].String() != "10.64.0.1" {
		t.Errorf("DNS = %v, want [10.64.0.1]", slot.DNS)
	}
	if got := len(slot.AllowedIPs); got != 2 {
		t.Errorf("len(AllowedIPs) = %d, want 2", got)
	}
	if slot.Endpoint != "198.51.100.2:51820" {
		t.Errorf("Endpoint = %q", slot.Endpoint)
	}
	if slot.EndpointHost() != "198.51.100.2" {
		t.Errorf("EndpointHost = %q", slot.EndpointHost())
	}
	if slot.MTU != DefaultMTU {
		t.Errorf("MTU = %d, want %d", slot.MTU, DefaultMTU)
	}
}

func TestParseConfDefaultsAllowedIPs(t *testing.T) {
	conf := `[Interface]
PrivateKey = R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=
Address = 10.64.0.2/32

[Peer]
PublicKey = ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=
Endpoint = 198.51.100.7:51820
`
	slot, err := ParseConf("jp-tyo-wg-002.conf", []byte(conf))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if len(slot.AllowedIPs) != 2 {
		t.Fatalf("expected a default full-tunnel AllowedIPs, got %v", slot.AllowedIPs)
	}
}

func TestParseConfRejectsIncomplete(t *testing.T) {
	cases := map[string]string{
		"no private key": "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = k\nEndpoint = 1.2.3.4:1\n",
		"no address":     "[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = k\nEndpoint = 1.2.3.4:1\n",
		"no endpoint":    "[Interface]\nPrivateKey = k\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = k\n",
		"bad endpoint":   "[Interface]\nPrivateKey = k\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = k\nEndpoint = nope\n",
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConf("x-yyy-wg-001.conf", []byte(conf)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseConfIgnoresInlineComments(t *testing.T) {
	conf := `[Interface]
PrivateKey = R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=
Address = 10.64.0.2/32
MTU = 1380 # smaller for this provider

[Peer]
PublicKey = ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=
Endpoint = 198.51.100.7:51820
AllowedIPs = 0.0.0.0/0
`
	slot, err := ParseConf("de-fra-wg-001.conf", []byte(conf))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if slot.MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", slot.MTU)
	}
}

func TestLoadDirAndZip(t *testing.T) {
	dir := t.TempDir()
	names := []string{"us-lax-wg-001.conf", "jp-tyo-wg-001.conf", "notes.txt"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(sampleConf), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	bundle, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(bundle.Slots) != 2 {
		t.Fatalf("len(Slots) = %d, want 2 (non-.conf files ignored)", len(bundle.Slots))
	}
	if bundle.Slots[0].ID != "jp-tyo-wg-001" {
		t.Errorf("slots are not sorted: %q first", bundle.Slots[0].ID)
	}
	if bundle.DistinctKeys != 1 {
		t.Errorf("DistinctKeys = %d, want 1", bundle.DistinctKeys)
	}
	if got := bundle.Countries(); len(got) != 2 {
		t.Errorf("Countries() = %v, want 2 entries", got)
	}

	// Same content, packaged as a zip.
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"us-lax-wg-001.conf", "nested/jp-tyo-wg-001.conf"} {
		f, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(sampleConf)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "bundle.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	zipBundle, err := LoadZip(zipPath)
	if err != nil {
		t.Fatalf("LoadZip: %v", err)
	}
	if len(zipBundle.Slots) != 2 {
		t.Fatalf("len(Slots) = %d, want 2", len(zipBundle.Slots))
	}

	extractDir := filepath.Join(dir, "extracted")
	written, err := ExtractZip(zipPath, extractDir)
	if err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	if written != 2 {
		t.Fatalf("ExtractZip wrote %d files, want 2", written)
	}
	info, err := os.Stat(filepath.Join(extractDir, "us-lax-wg-001.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("extracted file mode = %o, want 600 (it holds a private key)", perm)
	}
}

func TestLoadDirRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "us-lax-wg-001.conf"), []byte(sampleConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "us-lax-wg-001.CONF"), []byte(sampleConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected duplicate slot IDs to be rejected")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no .conf files")
	}
}
