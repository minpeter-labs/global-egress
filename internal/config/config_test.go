package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "config.yaml", `
catalog:
  path: wireguard
listen:
  socks5: 10.0.0.70:1080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Relative paths resolve against the config file's directory.
	if want := filepath.Join(dir, "wireguard"); cfg.Catalog.Path != want {
		t.Errorf("Catalog.Path = %q, want %q", cfg.Catalog.Path, want)
	}
	if cfg.Pool.SessionTTL != 10*time.Minute {
		t.Errorf("SessionTTL = %s, want the 10m default", cfg.Pool.SessionTTL)
	}
	if cfg.Pool.MaxActive != 25 {
		t.Errorf("MaxActive = %d, want the default 25", cfg.Pool.MaxActive)
	}
	if cfg.Listen.HTTP != "127.0.0.1:3128" {
		t.Errorf("Listen.HTTP = %q, want the default", cfg.Listen.HTTP)
	}
	if got := cfg.InventoryPath(); !strings.HasSuffix(got, "inventory.json") {
		t.Errorf("InventoryPath = %q", got)
	}
}

func TestLoadReadsSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pw", "  hunter2\n")
	write(t, dir, "token", "tok3n\n")
	path := write(t, dir, "config.yaml", `
catalog:
  path: /var/lib/global-egress/wireguard
access:
  password_file: pw
  control_token_file: token
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Access.Password != "hunter2" {
		t.Errorf("Password = %q, want the trimmed file content", cfg.Access.Password)
	}
	if cfg.Access.ControlToken != "tok3n" {
		t.Errorf("ControlToken = %q", cfg.Access.ControlToken)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "config.yaml", `
catalog:
  path: x
poool:
  max_active: 5
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown field (typos must not be silently ignored)")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestValidate(t *testing.T) {
	base := func() Config {
		cfg := Default()
		cfg.Catalog.Path = "/tmp/wg"
		return cfg
	}

	cases := map[string]func(*Config){
		"no catalog":           func(c *Config) { c.Catalog.Path = "" },
		"no listeners":         func(c *Config) { c.Listen.SOCKS5 = ""; c.Listen.HTTP = "" },
		"bad client cidr":      func(c *Config) { c.Access.AllowedClients = []string{"nope"} },
		"bad denied cidr":      func(c *Config) { c.Destinations.DeniedCIDRs = []string{"nope"} },
		"negative max_active":  func(c *Config) { c.Pool.MaxActive = -1 },
		"preopen over budget":  func(c *Config) { c.Pool.MaxActive = 2; c.Pool.Preopen = 3 },
		"bad log level":        func(c *Config) { c.Log.Level = "loud" },
		"bad log format":       func(c *Config) { c.Log.Format = "yaml" },
		"invalid allowed port": func(c *Config) { c.Destinations.AllowedPorts = []int{0} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		cfg := base()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}

func TestAllowedClientPrefixes(t *testing.T) {
	cfg := Default()
	cfg.Access.AllowedClients = []string{"10.0.0.0/24", " ::1/128 "}
	prefixes, err := cfg.AllowedClientPrefixes()
	if err != nil {
		t.Fatalf("AllowedClientPrefixes: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("len = %d, want 2", len(prefixes))
	}
	if prefixes[0].String() != "10.0.0.0/24" {
		t.Errorf("prefix[0] = %s", prefixes[0])
	}
}

func TestInventoryPathWithoutStateDir(t *testing.T) {
	cfg := Default()
	cfg.StateDir = ""
	if got := cfg.InventoryPath(); got != "" {
		t.Errorf("InventoryPath = %q, want empty when state_dir is unset", got)
	}
}
