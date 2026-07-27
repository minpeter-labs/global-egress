// Package config loads and validates the service configuration.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/minpeter-labs/global-egress/internal/netguard"
)

// Mode selects where exit addresses come from.
type Mode string

const (
	// ModeWireGuard gives every slot its own tunnel. Simple and self-contained,
	// but each slot costs a provider key association, which is rate-limited.
	ModeWireGuard Mode = "wireguard"
	// ModeRelaySocks keeps a few entry tunnels up and exits through the SOCKS
	// proxy on each provider relay. Many more addresses, near-instant rotation,
	// and almost no key associations.
	ModeRelaySocks Mode = "relay-socks"
)

// Config is the on-disk configuration.
type Config struct {
	// Mode selects the egress strategy. Defaults to relay-socks.
	Mode Mode `yaml:"mode"`
	// Relays configures the provider relay list used by relay-socks mode.
	Relays RelayConfig `yaml:"relays"`
	// Entries selects which tunnels relay-socks mode rides on.
	Entries EntryConfig `yaml:"entries"`
	// Catalog points at the WireGuard bundle: either a directory of .conf files
	// or a .zip archive.
	Catalog CatalogConfig `yaml:"catalog"`
	// Listen holds the listener addresses.
	Listen ListenConfig `yaml:"listen"`
	// Access controls who may use the proxy.
	Access AccessConfig `yaml:"access"`
	// Pool tunes slot selection and lifecycle.
	Pool PoolConfig `yaml:"pool"`
	// Destinations restricts where traffic may go.
	Destinations DestinationConfig `yaml:"destinations"`
	// StateDir holds the measured-IP inventory.
	StateDir string `yaml:"state_dir"`
	// Log configures logging.
	Log LogConfig `yaml:"log"`
}

// RelayConfig locates the provider relay list.
type RelayConfig struct {
	// URL is the relay list endpoint.
	URL string `yaml:"url"`
	// Cache is where the list is stored; relative paths resolve under state_dir.
	Cache string `yaml:"cache"`
	// Refresh is how long a cached list is trusted before refetching.
	Refresh time.Duration `yaml:"refresh"`
}

// EntryConfig selects the entry tunnels for relay-socks mode.
type EntryConfig struct {
	// Slots names catalog slots to use as entries, e.g. ["jp-tyo-wg-001"].
	// Prefer listing these explicitly: the best entry depends on where this
	// service runs, which cannot be derived from the catalog.
	Slots []string `yaml:"slots"`
	// Auto picks this many entries spread across regions when Slots is empty.
	Auto int `yaml:"auto"`
}

// CatalogConfig locates the WireGuard configuration bundle.
type CatalogConfig struct {
	Path string `yaml:"path"`
}

// ListenConfig holds listener addresses. An empty value disables that listener.
type ListenConfig struct {
	SOCKS5  string `yaml:"socks5"`
	HTTP    string `yaml:"http"`
	Control string `yaml:"control"`
}

// AccessConfig controls authentication and the client ACL.
type AccessConfig struct {
	// AllowedClients are CIDRs permitted to use the proxy and control API.
	AllowedClients []string `yaml:"allowed_clients"`
	// Password, when set, is required from proxy clients. The username always
	// carries the selection policy, never an identity.
	Password string `yaml:"password"`
	// PasswordFile reads the password from a file instead of the config.
	PasswordFile string `yaml:"password_file"`
	// RequireAuth rejects proxy clients that present no credentials.
	RequireAuth bool `yaml:"require_auth"`
	// ControlToken, when set, is required as a Bearer token on the control API.
	ControlToken string `yaml:"control_token"`
	// ControlTokenFile reads the control token from a file.
	ControlTokenFile string `yaml:"control_token_file"`
}

// PoolConfig tunes the pool.
type PoolConfig struct {
	// MaxActive caps simultaneously open tunnels. Zero means "no limit", which
	// is only advisable after measuring memory use per slot.
	MaxActive int `yaml:"max_active"`
	// Preopen brings this many tunnels up at startup so the first requests do
	// not pay for a handshake.
	Preopen int `yaml:"preopen"`
	// MaxConnsPerExit caps concurrent connections through one exit, so load is
	// spread over relays instead of concentrated on one. Zero disables it.
	MaxConnsPerExit int `yaml:"max_conns_per_exit"`
	// MaxConcurrentConns caps concurrent connections across the pool. Zero
	// disables it.
	MaxConcurrentConns int `yaml:"max_concurrent_conns"`
	// SessionTTL is the default sticky-session lifetime.
	SessionTTL time.Duration `yaml:"session_ttl"`
	// BatchTTL is how long a unique-IP batch is remembered.
	BatchTTL time.Duration `yaml:"batch_ttl"`
	// Cooldown is the default per-target cooldown applied by a report.
	Cooldown time.Duration `yaml:"cooldown"`
	// IdleTimeout closes tunnels unused for this long.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	// HandshakeTimeout bounds bringing a tunnel up.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
	// DialAttempts is how many slots a request tries before failing.
	DialAttempts int `yaml:"dial_attempts"`
	// FailureBackoff is the base backoff for a failing slot.
	FailureBackoff time.Duration `yaml:"failure_backoff"`
	// NewTunnelsPerWindow caps how many tunnels may be opened per
	// NewTunnelWindow. Providers restrict how fast one key may associate with
	// new relays, so this protects the key from being blocked. Zero disables it.
	NewTunnelsPerWindow int `yaml:"new_tunnels_per_window"`
	// NewTunnelWindow is the period NewTunnelsPerWindow applies to.
	NewTunnelWindow time.Duration `yaml:"new_tunnel_window"`
	// EntryExploreRate is the share of requests that deliberately use the
	// second-best entry, so alternatives keep being measured. Zero uses the
	// built-in default.
	EntryExploreRate float64 `yaml:"entry_explore_rate"`
	// StableEntryRouting always uses the best known entry, trading self-correcting
	// routing for predictability.
	StableEntryRouting bool `yaml:"stable_entry_routing"`
	// DialTimeout bounds connecting to the destination through a tunnel.
	DialTimeout time.Duration `yaml:"dial_timeout"`
	// RelayIdleTimeout closes relayed connections after inactivity.
	RelayIdleTimeout time.Duration `yaml:"relay_idle_timeout"`
	// IPCheckURL is the echo endpoint used to learn a slot's public IP.
	// Setting it to "" disables IP measurement, and with it unique-IP batches.
	IPCheckURL string `yaml:"ip_check_url"`
	// IPCheckTimeout bounds one measurement.
	IPCheckTimeout time.Duration `yaml:"ip_check_timeout"`
	// IPRefreshInterval is how long a measured IP is trusted.
	IPRefreshInterval time.Duration `yaml:"ip_refresh_interval"`
	// IPCheckConcurrency caps simultaneous measurements.
	IPCheckConcurrency int `yaml:"ip_check_concurrency"`
}

// DestinationConfig restricts destinations.
type DestinationConfig struct {
	// DeniedCIDRs replaces the built-in private-range denylist when non-nil.
	DeniedCIDRs []string `yaml:"denied_cidrs"`
	// AllowedPorts, when non-empty, is an allowlist of destination ports.
	AllowedPorts []int `yaml:"allowed_ports"`
}

// LogConfig configures logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is "text" or "json".
	Format string `yaml:"format"`
}

// Default returns a configuration with every optional value populated.
func Default() Config {
	return Config{
		Mode: ModeRelaySocks,
		Relays: RelayConfig{
			URL:     "https://api.mullvad.net/www/relays/wireguard/",
			Cache:   "relays.json",
			Refresh: 24 * time.Hour,
		},
		Entries: EntryConfig{Auto: 2},
		Listen: ListenConfig{
			SOCKS5:  "127.0.0.1:1080",
			HTTP:    "127.0.0.1:3128",
			Control: "127.0.0.1:8080",
		},
		Access: AccessConfig{
			AllowedClients: []string{"127.0.0.1/32", "::1/128"},
		},
		Pool: PoolConfig{
			MaxActive:           25,
			Preopen:             0,
			SessionTTL:          10 * time.Minute,
			BatchTTL:            15 * time.Minute,
			Cooldown:            15 * time.Minute,
			IdleTimeout:         10 * time.Minute,
			HandshakeTimeout:    12 * time.Second,
			DialAttempts:        3,
			FailureBackoff:      30 * time.Second,
			NewTunnelsPerWindow: 120,
			NewTunnelWindow:     10 * time.Minute,
			DialTimeout:         30 * time.Second,
			RelayIdleTimeout:    5 * time.Minute,
			IPCheckURL:          "https://am.i.mullvad.net/ip",
			IPCheckTimeout:      15 * time.Second,
			IPRefreshInterval:   6 * time.Hour,
			IPCheckConcurrency:  4,
		},
		StateDir: "/var/lib/global-egress",
		Log:      LogConfig{Level: "info", Format: "text"},
	}
}

// Load reads a YAML configuration file on top of the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.finalize(filepath.Dir(path)); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// finalize resolves file references and validates the result.
func (c *Config) finalize(baseDir string) error {
	if c.Access.PasswordFile != "" {
		value, err := readSecret(resolvePath(baseDir, c.Access.PasswordFile))
		if err != nil {
			return err
		}
		c.Access.Password = value
	}
	if c.Access.ControlTokenFile != "" {
		value, err := readSecret(resolvePath(baseDir, c.Access.ControlTokenFile))
		if err != nil {
			return err
		}
		c.Access.ControlToken = value
	}
	if c.Catalog.Path != "" {
		c.Catalog.Path = resolvePath(baseDir, c.Catalog.Path)
	}
	if c.StateDir != "" {
		c.StateDir = resolvePath(baseDir, c.StateDir)
	}
	return c.Validate()
}

// Validate checks the configuration for obvious mistakes.
func (c *Config) Validate() error {
	if c.Catalog.Path == "" {
		return fmt.Errorf("config: catalog.path is required")
	}
	switch c.Mode {
	case ModeWireGuard, ModeRelaySocks:
	default:
		return fmt.Errorf("config: mode %q is not %q or %q", c.Mode, ModeWireGuard, ModeRelaySocks)
	}
	if c.Mode == ModeRelaySocks {
		if len(c.Entries.Slots) == 0 && c.Entries.Auto <= 0 {
			return fmt.Errorf("config: relay-socks mode needs entries.slots or entries.auto")
		}
		if c.Relays.Refresh < 0 {
			return fmt.Errorf("config: relays.refresh must not be negative")
		}
	}
	if c.Listen.SOCKS5 == "" && c.Listen.HTTP == "" {
		return fmt.Errorf("config: at least one of listen.socks5 or listen.http must be set")
	}
	if _, err := c.AllowedClientPrefixes(); err != nil {
		return err
	}
	if _, err := netguard.New(c.Destinations.DeniedCIDRs, c.Destinations.AllowedPorts); err != nil {
		return err
	}
	if c.Pool.MaxActive < 0 {
		return fmt.Errorf("config: pool.max_active must not be negative")
	}
	if c.Pool.Preopen < 0 {
		return fmt.Errorf("config: pool.preopen must not be negative")
	}
	if c.Pool.MaxConnsPerExit < 0 {
		return fmt.Errorf("config: pool.max_conns_per_exit must not be negative")
	}
	if c.Pool.MaxConcurrentConns < 0 {
		return fmt.Errorf("config: pool.max_concurrent_conns must not be negative")
	}
	if c.Pool.EntryExploreRate < 0 || c.Pool.EntryExploreRate >= 1 {
		return fmt.Errorf("config: pool.entry_explore_rate must be in [0, 1)")
	}
	if c.Pool.NewTunnelsPerWindow < 0 {
		return fmt.Errorf("config: pool.new_tunnels_per_window must not be negative")
	}
	if c.Pool.NewTunnelWindow < 0 {
		return fmt.Errorf("config: pool.new_tunnel_window must not be negative")
	}
	if c.Pool.MaxActive > 0 && c.Pool.Preopen > c.Pool.MaxActive {
		return fmt.Errorf("config: pool.preopen (%d) exceeds pool.max_active (%d)",
			c.Pool.Preopen, c.Pool.MaxActive)
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level %q is not one of debug, info, warn, error", c.Log.Level)
	}
	switch strings.ToLower(c.Log.Format) {
	case "text", "json":
	default:
		return fmt.Errorf("config: log.format %q is not text or json", c.Log.Format)
	}
	return nil
}

// AllowedClientPrefixes parses the client ACL.
func (c *Config) AllowedClientPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range c.Access.AllowedClients {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("config: invalid access.allowed_clients entry %q: %w", raw, err)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// RelayCachePath resolves the relay list cache location.
func (c *Config) RelayCachePath() string {
	if c.Relays.Cache == "" {
		return ""
	}
	if filepath.IsAbs(c.Relays.Cache) {
		return c.Relays.Cache
	}
	if c.StateDir == "" {
		return c.Relays.Cache
	}
	return filepath.Join(c.StateDir, c.Relays.Cache)
}

// InventoryPath is where measured public IPs are persisted.
func (c *Config) InventoryPath() string {
	if c.StateDir == "" {
		return ""
	}
	return filepath.Join(c.StateDir, "inventory.json")
}

func resolvePath(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func readSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: read secret %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
