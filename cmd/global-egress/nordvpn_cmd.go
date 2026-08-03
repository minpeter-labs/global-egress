package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

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

	loadOptions := nordvpn.LoadOptions{
		URL:        *url,
		CachePath:  *cache,
		MaxAge:     24 * time.Hour,
		AllowStale: true,
	}
	if *refresh {
		loadOptions.MaxAge = 0
		loadOptions.AllowStale = false
	}
	list, fetched, err := nordvpn.LoadOrFetch(ctx, loadOptions)
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
