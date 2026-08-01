package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/nordvpn"
)

// readPrivateKeyFile loads a NordLynx private key from disk.
//
// The mode check is not decoration: this one file is the account's entire VPN
// identity, and a bundle directory written by "import" is already held to 0700
// for the same reason. Neither the key nor the file contents appear in any error
// returned here.
func readPrivateKeyFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("nordvpn key: cannot stat the key file (%T)", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("nordvpn key: %s is mode %o; it holds the account key, so it must be 0600", path, perm)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("nordvpn key: cannot read the key file (%T)", err)
	}
	key := strings.TrimSpace(string(blob))
	if key == "" {
		return "", fmt.Errorf("nordvpn key: %s is empty", path)
	}
	return key, nil
}

// runNordVPN builds a catalog from NordVPN's server list.
//
// NordVPN's servers become WireGuard slots: its SOCKS5 proxies are a small
// separate pool rather than one per relay, so they are no substitute for the
// catalog. The catalog is written as ordinary .conf files, which keeps every other
// subcommand - inspect, probe, serve - unchanged and provider-agnostic.
func runNordVPN(ctx context.Context, args []string) error {
	fs := newFlagSet("nordvpn")
	url := fs.String("url", nordvpn.DefaultURL, "server list endpoint")
	cache := fs.String("cache", "", "server list cache file to read and update")
	refresh := fs.Bool("refresh", false, "always fetch, ignoring the cache")
	keyPath := fs.String("key", "", "file holding the NordLynx private key (mode 0600)")
	dir := fs.String("dir", "", "write the catalog into this directory instead of listing servers")
	country := fs.String("country", "", "only use servers in this country code")
	limit := fs.Int("limit", 0, "keep at most this many servers, lowest load first (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	maxAge := 24 * time.Hour
	if *refresh {
		maxAge = 0
	}
	list, fetched, err := nordvpn.LoadOrFetch(ctx, *url, *cache, maxAge)
	if err != nil {
		return err
	}

	servers := list.Usable()
	if *country != "" {
		filtered := servers[:0:0]
		for _, server := range servers {
			if strings.EqualFold(server.Country, *country) {
				filtered = append(filtered, server)
			}
		}
		servers = filtered
	}
	// A busy server is a slow exit, and the provider publishes the number, so
	// trimming by load beats trimming by name.
	if *limit > 0 && len(servers) > *limit {
		sort.SliceStable(servers, func(i, j int) bool { return servers[i].Load < servers[j].Load })
		servers = servers[:*limit]
	}
	if len(servers) == 0 {
		return fmt.Errorf("nordvpn: no usable servers matched")
	}

	if *dir == "" {
		printServerSummary(list, servers, fetched)
		return nil
	}

	if *keyPath == "" {
		return fmt.Errorf("-key is required when writing a catalog")
	}
	privateKey, err := readPrivateKeyFile(*keyPath)
	if err != nil {
		return err
	}

	selected := &nordvpn.List{Servers: servers, FetchedAt: list.FetchedAt}
	slots, err := selected.Slots(privateKey)
	if err != nil {
		return err
	}
	written, err := writeCatalog(*dir, slots)
	if err != nil {
		return err
	}

	fmt.Printf("wrote %d configuration files into %s\n", written, *dir)
	fmt.Printf("\nThese files contain a private key. Keep %s at mode 0700.\n", *dir)
	return nil
}

// writeCatalog renders slots as wg-quick configuration files, the same shape the
// catalog loader already reads.
//
// The catalog is replaced rather than merged: a narrower -country or -limit has to
// shrink it, or inspect, probe and serve would keep serving servers the operator
// just deselected. Files are written through a 0600 temporary file and renamed, so
// a rerun cannot leave a key-bearing file at looser permissions than it needs.
func writeCatalog(dir string, slots []catalog.Slot) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("nordvpn: create catalog dir: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone, and this one holds
	// private keys.
	if err := os.Chmod(dir, 0o700); err != nil {
		return 0, fmt.Errorf("nordvpn: secure catalog dir failed (%T)", err)
	}

	keep := make(map[string]struct{}, len(slots))
	written := 0
	for _, slot := range slots {
		name, err := catalogFileName(slot)
		if err != nil {
			return written, err
		}
		if err := writePrivateFile(filepath.Join(dir, name), renderConf(slot)); err != nil {
			return written, err
		}
		keep[name] = struct{}{}
		written++
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return written, fmt.Errorf("nordvpn: read catalog dir failed (%T)", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".conf") {
			continue
		}
		if _, ok := keep[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return written, fmt.Errorf("nordvpn: remove obsolete catalog entry failed (%T)", err)
		}
	}
	return written, nil
}

// writePrivateFile writes through a 0600 temporary file and renames, so readers
// never see a half-written config and an existing loose mode cannot survive.
func writePrivateFile(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return fmt.Errorf("nordvpn: write catalog entry failed (%T)", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("nordvpn: secure catalog entry failed (%T)", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("nordvpn: replace catalog entry failed (%T)", err)
	}
	return nil
}

// catalogFileName names a slot so the catalog parser can recover its geography.
//
// That parser reads the country and city back out of the file name - Mullvad
// bundles arrive as "us-lax-wg-001.conf" - by taking everything up to the second
// hyphen, so a multi-word city like "us-saint-louis" would come back as
// "us-saint". The city is written with its inner hyphens folded to underscores,
// which the parser accepts as part of one city component and which reverses
// cleanly. A name that would escape the catalog directory is refused rather than
// sanitised, because the only way to get one is a compromised server list.
func catalogFileName(slot catalog.Slot) (string, error) {
	base := slot.ID
	if slot.Country != "" && slot.City != "" {
		city := strings.TrimPrefix(slot.City, slot.Country+"-")
		base = fmt.Sprintf("%s-%s-%s", slot.Country, strings.ReplaceAll(city, "-", "_"), slot.ID)
	}
	name := base + ".conf"
	if name != filepath.Base(name) || strings.Contains(base, "..") || strings.ContainsRune(base, filepath.Separator) {
		return "", fmt.Errorf("nordvpn: refusing suspicious catalog entry name")
	}
	return name, nil
}

// renderConf writes one slot in wg-quick syntax.
func renderConf(slot catalog.Slot) string {
	addresses := make([]string, 0, len(slot.Addresses))
	for _, addr := range slot.Addresses {
		addresses = append(addresses, addr.String())
	}
	resolvers := make([]string, 0, len(slot.DNS))
	for _, addr := range slot.DNS {
		resolvers = append(resolvers, addr.String())
	}
	allowed := make([]string, 0, len(slot.AllowedIPs))
	for _, prefix := range slot.AllowedIPs {
		allowed = append(allowed, prefix.String())
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Server: %s\n", slot.Source)
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", slot.PrivateKey)
	fmt.Fprintf(&sb, "Address = %s\n", strings.Join(addresses, ", "))
	fmt.Fprintf(&sb, "DNS = %s\n", strings.Join(resolvers, ", "))
	fmt.Fprintf(&sb, "MTU = %d\n\n", slot.MTU)
	sb.WriteString("[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", slot.PeerPublicKey)
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&sb, "Endpoint = %s\n", slot.Endpoint)
	return sb.String()
}

func printServerSummary(list *nordvpn.List, servers []nordvpn.Server, fetched bool) {
	byCountry := map[string]int{}
	byCity := map[string]int{}
	for _, server := range servers {
		byCountry[server.Country]++
		byCity[server.City()]++
	}

	source := "cache"
	if fetched {
		source = "network"
	}
	fmt.Printf("server list from %s", source)
	if !list.FetchedAt.IsZero() {
		fmt.Printf(", fetched %s ago", time.Since(list.FetchedAt).Round(time.Minute))
	}
	fmt.Printf("\n\nusable servers: %d\n", len(servers))
	fmt.Printf("countries:      %d\n", len(byCountry))
	fmt.Printf("cities:         %d\n", len(byCity))

	type kv struct {
		key string
		n   int
	}
	top := make([]kv, 0, len(byCity))
	for city, n := range byCity {
		top = append(top, kv{city, n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].n != top[j].n {
			return top[i].n > top[j].n
		}
		return top[i].key < top[j].key
	})
	fmt.Println("\nlargest cities:")
	for i, entry := range top {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-12s %d\n", entry.key, entry.n)
	}
}
