package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/minpeter-labs/global-egress/internal/mullvad"
)

// runRelays inspects (and optionally refreshes) the provider relay list, which is
// where relay-socks mode gets its exit addresses.
func runRelays(ctx context.Context, args []string) error {
	fs := newFlagSet("relays")
	url := fs.String("url", mullvad.DefaultURL, "relay list endpoint")
	cache := fs.String("cache", "", "cache file to read and update")
	refresh := fs.Bool("refresh", false, "always fetch, ignoring the cache")
	country := fs.String("country", "", "only list this country code")
	listAll := fs.Bool("list", false, "list every relay instead of a summary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	maxAge := 24 * time.Hour
	if *refresh {
		maxAge = 0
	}
	list, fetched, err := mullvad.LoadOrFetch(ctx, *url, *cache, maxAge)
	if err != nil {
		return err
	}

	relays := list.Usable()
	if *country != "" {
		filtered := relays[:0:0]
		for _, relay := range relays {
			if strings.EqualFold(relay.Country, *country) {
				filtered = append(filtered, relay)
			}
		}
		relays = filtered
	}

	if *listAll {
		for _, relay := range relays {
			fmt.Printf("%-28s %-8s %-22s %s\n",
				relay.SlotID(), relay.Country, relay.City(), relay.SocksAddr())
		}
		return nil
	}

	byCountry := map[string]int{}
	byCity := map[string]int{}
	for _, relay := range relays {
		byCountry[relay.Country]++
		byCity[relay.City()]++
	}

	source := "cache"
	if fetched {
		source = "network"
	}
	fmt.Printf("relay list from %s", source)
	if !list.FetchedAt.IsZero() {
		fmt.Printf(", fetched %s ago", time.Since(list.FetchedAt).Round(time.Minute))
	}
	fmt.Printf("\n\nusable exits: %d\n", len(relays))
	fmt.Printf("countries:    %d\n", len(byCountry))
	fmt.Printf("cities:       %d\n", len(byCity))

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
		fmt.Printf("  %-10s %d\n", entry.key, entry.n)
	}

	fmt.Println("\nEach exit is one SOCKS proxy with its own address, reachable from")
	fmt.Println("inside any entry tunnel. Rotating between them costs a TCP connection,")
	fmt.Println("not a WireGuard handshake.")
	if *cache == "" {
		fmt.Fprintln(os.Stderr, "\nnote: pass -cache to keep a local copy for offline starts")
	}
	return nil
}
