// Package relaylist reads the provider's list of relays and the SOCKS proxy each
// one exposes.
//
// This is the second, cheaper source of exit addresses. A WireGuard bundle gives
// one exit IP per tunnel, and every tunnel costs a key association that providers
// rate-limit. The relay list instead describes a SOCKS proxy on every relay,
// reachable from inside any tunnel, so a single tunnel can exit from hundreds of
// addresses without opening anything new.
package relaylist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultURL is Mullvad's public WireGuard relay list.
const DefaultURL = "https://api.mullvad.net/www/relays/wireguard/"

// DefaultSocksPort is used when the list omits a port.
const DefaultSocksPort = 1080

// Relay is one provider relay and its SOCKS proxy.
type Relay struct {
	// Hostname is the relay name, e.g. "us-lax-wg-001".
	Hostname string `json:"hostname"`
	// Country is the ISO-3166-1 alpha-2 code, e.g. "us".
	Country string `json:"country_code"`
	// CityCode is the provider's city code, e.g. "lax".
	CityCode string `json:"city_code"`
	// CityName is the human readable city, e.g. "Los Angeles".
	CityName string `json:"city_name"`
	// SocksName is the DNS name of the relay's SOCKS proxy. It resolves only
	// inside the provider network, which is why a tunnel is still required.
	SocksName string `json:"socks_name"`
	// SocksPort is the proxy port.
	SocksPort int `json:"socks_port"`
	// Active reports whether the provider considers the relay usable.
	Active bool `json:"active"`
	// Owned distinguishes provider-owned hardware from rented servers.
	Owned bool `json:"owned"`
	// IPv4AddrIn is the relay's entry address, i.e. where a tunnel connects. It
	// is not the address traffic exits from.
	IPv4AddrIn string `json:"ipv4_addr_in"`
}

// City returns the "<country>-<city>" label used throughout the project, e.g.
// "us-lax", matching the labels derived from WireGuard config file names.
func (r Relay) City() string {
	if r.Country == "" || r.CityCode == "" {
		return ""
	}
	return r.Country + "-" + r.CityCode
}

// SocksAddr returns the "host:port" of the relay's SOCKS proxy.
func (r Relay) SocksAddr() string {
	port := r.SocksPort
	if port == 0 {
		port = DefaultSocksPort
	}
	// Strip a port the provider may already have baked into the name.
	host := r.SocksName
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		if _, err := fmt.Sscanf(host[idx+1:], "%d", new(int)); err == nil {
			host = host[:idx]
		}
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// SlotID returns a stable identifier for the relay's SOCKS exit. It is derived
// from the SOCKS name so that it never collides with a WireGuard slot ID.
func (r Relay) SlotID() string {
	host := r.SocksName
	if idx := strings.Index(host, "."); idx > 0 {
		host = host[:idx]
	}
	if host == "" {
		host = r.Hostname + "-socks"
	}
	return host
}

// List is a set of relays.
type List struct {
	Relays    []Relay
	FetchedAt time.Time
}

// Usable returns the relays that are active and expose a SOCKS proxy, sorted by
// slot ID.
func (l *List) Usable() []Relay {
	out := make([]Relay, 0, len(l.Relays))
	for _, relay := range l.Relays {
		if !relay.Active || relay.SocksName == "" {
			continue
		}
		out = append(out, relay)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SlotID() < out[j].SlotID() })
	return out
}

// Countries returns the sorted set of country codes.
func (l *List) Countries() []string {
	seen := map[string]struct{}{}
	for _, relay := range l.Usable() {
		seen[relay.Country] = struct{}{}
	}
	return sortedKeys(seen)
}

// Cities returns the sorted set of city labels.
func (l *List) Cities() []string {
	seen := map[string]struct{}{}
	for _, relay := range l.Usable() {
		if city := relay.City(); city != "" {
			seen[city] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Fetch downloads the relay list. url may be empty to use DefaultURL.
func Fetch(ctx context.Context, url string) (*List, error) {
	if url == "" {
		url = DefaultURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "global-egress/relaylist")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relaylist: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relaylist: fetch %s: unexpected status %s", url, resp.Status)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("relaylist: read %s: %w", url, err)
	}
	return parse(blob)
}

func parse(blob []byte) (*List, error) {
	var relays []Relay
	if err := json.Unmarshal(blob, &relays); err != nil {
		return nil, fmt.Errorf("relaylist: parse: %w", err)
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("relaylist: list is empty")
	}
	return &List{Relays: relays, FetchedAt: time.Now()}, nil
}

// Save writes the list to path so a restart does not need the network.
func (l *List) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("relaylist: create cache dir: %w", err)
	}
	blob, err := json.MarshalIndent(l.Relays, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return fmt.Errorf("relaylist: write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("relaylist: replace cache: %w", err)
	}
	return nil
}

// LoadFile reads a previously saved list.
func LoadFile(path string) (*List, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("relaylist: read %s: %w", path, err)
	}
	list, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(path); statErr == nil {
		list.FetchedAt = info.ModTime()
	}
	return list, nil
}

// LoadOrFetch prefers a fresh cache file, falls back to the network, and falls
// back again to a stale cache if the network is unavailable. The returned bool
// reports whether the network was used.
func LoadOrFetch(ctx context.Context, url, cachePath string, maxAge time.Duration) (*List, bool, error) {
	if cachePath != "" && maxAge > 0 {
		if list, err := LoadFile(cachePath); err == nil {
			if time.Since(list.FetchedAt) < maxAge {
				return list, false, nil
			}
		}
	}

	list, fetchErr := Fetch(ctx, url)
	if fetchErr == nil {
		if cachePath != "" {
			// A cache write failure must not stop the service from starting.
			_ = list.Save(cachePath)
		}
		return list, true, nil
	}

	if cachePath != "" {
		if list, err := LoadFile(cachePath); err == nil {
			return list, false, nil
		}
	}
	return nil, false, fetchErr
}
