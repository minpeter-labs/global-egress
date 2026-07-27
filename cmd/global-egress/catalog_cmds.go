package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/minpeter-labs/global-egress/internal/catalog"
	"github.com/minpeter-labs/global-egress/internal/pool"
)

// runImport extracts a provider bundle into the catalog directory.
func runImport(args []string) error {
	fs := newFlagSet("import")
	zipPath := fs.String("zip", "", "provider WireGuard bundle (.zip)")
	dir := fs.String("dir", "/var/lib/global-egress/wireguard", "catalog directory to write .conf files into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *zipPath == "" {
		return fmt.Errorf("-zip is required")
	}

	written, err := catalog.ExtractZip(*zipPath, *dir)
	if err != nil {
		return err
	}
	bundle, err := catalog.LoadDir(*dir)
	if err != nil {
		return err
	}

	fmt.Printf("imported %d configuration files into %s\n", written, *dir)
	printBundleSummary(bundle)
	fmt.Printf("\nThese files contain a private key. Keep %s at mode 0700.\n", *dir)
	return nil
}

// runInspect summarises a catalog without touching the network.
func runInspect(args []string) error {
	fs := newFlagSet("inspect")
	path := fs.String("catalog", "", "catalog directory or .zip bundle")
	asJSON := fs.Bool("json", false, "print the slot list as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("-catalog is required")
	}

	bundle, err := catalog.Load(*path)
	if err != nil {
		return err
	}

	if *asJSON {
		type slotView struct {
			ID       string `json:"id"`
			Country  string `json:"country"`
			City     string `json:"city"`
			Endpoint string `json:"endpoint"`
		}
		views := make([]slotView, 0, len(bundle.Slots))
		for _, s := range bundle.Slots {
			views = append(views, slotView{s.ID, s.Country, s.City, s.Endpoint})
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(views)
	}

	printBundleSummary(bundle)
	return nil
}

func printBundleSummary(bundle *catalog.Bundle) {
	byCity := map[string]int{}
	byCountry := map[string]int{}
	for _, slot := range bundle.Slots {
		byCity[slot.City]++
		byCountry[slot.Country]++
	}

	fmt.Printf("\nslots:      %d\n", len(bundle.Slots))
	fmt.Printf("countries:  %d\n", len(byCountry))
	fmt.Printf("cities:     %d\n", len(byCity))
	if len(bundle.Devices) > 0 {
		fmt.Printf("devices:    %s\n", strings.Join(bundle.Devices, ", "))
	}
	fmt.Printf("keys:       %d distinct private key(s)\n", bundle.DistinctKeys)
	if bundle.DistinctKeys == 1 {
		fmt.Println("            (one provider device shared by every server, which is the")
		fmt.Println("             normal layout for a downloaded \"all servers\" bundle)")
	}

	type cityCount struct {
		city  string
		count int
	}
	counts := make([]cityCount, 0, len(byCity))
	for city, count := range byCity {
		counts = append(counts, cityCount{city, count})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].count != counts[j].count {
			return counts[i].count > counts[j].count
		}
		return counts[i].city < counts[j].city
	})

	fmt.Println("\nlargest cities:")
	for i, entry := range counts {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-10s %d\n", entry.city, entry.count)
	}
	fmt.Println("\nNote: the number of slots is an upper bound on usable exit IPs.")
	fmt.Println("Providers share one public address between several servers, so run")
	fmt.Println("\"global-egress probe\" to learn how many distinct IPs actually exist.")
}

// runProbe measures the public IP of each slot and persists the inventory.
func runProbe(ctx context.Context, args []string) error {
	fs := newFlagSet("probe")
	path := fs.String("catalog", "", "catalog directory or .zip bundle")
	statePath := fs.String("state", "", "inventory file to update (optional)")
	url := fs.String("url", "https://am.i.mullvad.net/ip", "echo endpoint returning the caller's public IP")
	concurrency := fs.Int("concurrency", 8, "simultaneous tunnels")
	interval := fs.Duration("interval", 0,
		"minimum spacing between tunnel setups; providers rate-limit handshakes per key, "+
			"so use e.g. 750ms when sweeping a large bundle")
	limit := fs.Int("limit", 0, "stop after N slots (0 = all)")
	country := fs.String("country", "", "only probe this country code")
	city := fs.String("city", "", "only probe this city label, e.g. us-lax")
	slots := fs.String("slots", "", "comma-separated slot ids to probe (for retrying failures)")
	slotsFile := fs.String("slots-file", "", "file containing slot ids, comma or newline separated")
	handshakeTimeout := fs.Duration("handshake-timeout", 12*time.Second,
		"how long to wait for a WireGuard handshake before giving up on a slot")
	verbose := fs.Bool("verbose", false, "log every measurement as it completes")
	logLevelFlag := fs.String("log-level", "", "log level: debug, info, warn, error (debug includes WireGuard device logs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("-catalog is required")
	}

	bundle, err := catalog.Load(*path)
	if err != nil {
		return err
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelInfo
	}
	switch strings.ToLower(*logLevelFlag) {
	case "":
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		return fmt.Errorf("-log-level must be debug, info, warn or error")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	egressPool, err := pool.New(bundle, pool.Options{
		Logger:             logger,
		IPCheckURL:         *url,
		IPCheckConcurrency: *concurrency,
		HandshakeTimeout:   *handshakeTimeout,
	})
	if err != nil {
		return err
	}

	selected, err := collectSlotIDs(*slots, *slotsFile)
	if err != nil {
		return err
	}
	defer egressPool.Close()

	if *statePath != "" {
		if restored, err := egressPool.LoadInventory(*statePath); err != nil {
			logger.Warn("could not load inventory", slog.Any("error", err))
		} else if restored > 0 {
			fmt.Fprintf(os.Stderr, "restored %d previously measured slots\n", restored)
		}
	}

	started := time.Now()
	done := 0
	results := egressPool.Probe(ctx, pool.ProbeOptions{
		Concurrency: *concurrency,
		Limit:       *limit,
		Country:     *country,
		City:        *city,
		Slots:       selected,
		Interval:    *interval,
		OnResult: func(result pool.ProbeResult) {
			done++
			if result.Err != "" {
				fmt.Printf("%-4d %-16s %-18s FAIL  %s\n", done, result.Slot, "-", firstLine(result.Err))
				return
			}
			fmt.Printf("%-4d %-16s %-18s ok    %s\n", done, result.Slot, result.PublicIP,
				result.Latency.Round(time.Millisecond))
		},
	})

	ok := 0
	unique := map[string]struct{}{}
	perIP := map[string][]string{}
	for _, result := range results {
		if result.Err != "" || result.PublicIP == "" {
			continue
		}
		ok++
		unique[result.PublicIP] = struct{}{}
		perIP[result.PublicIP] = append(perIP[result.PublicIP], result.Slot)
	}

	fmt.Printf("\nprobed %d slots in %s\n", len(results), time.Since(started).Round(time.Second))
	fmt.Printf("reachable:      %d\n", ok)
	fmt.Printf("failed:         %d\n", len(results)-ok)
	fmt.Printf("unique IPs:     %d\n", len(unique))
	if ok > 0 {
		fmt.Printf("IPs per slot:   %.2f\n", float64(len(unique))/float64(ok))
	}

	shared := 0
	for _, slots := range perIP {
		if len(slots) > 1 {
			shared++
		}
	}
	if shared > 0 {
		fmt.Printf("shared IPs:     %d addresses are used by more than one slot\n", shared)
	}

	if *statePath != "" {
		if err := egressPool.SaveInventory(*statePath); err != nil {
			return err
		}
		fmt.Printf("\ninventory written to %s\n", *statePath)
	}
	return ctx.Err()
}

// collectSlotIDs merges the -slots flag and -slots-file into one list.
func collectSlotIDs(inline, path string) ([]string, error) {
	raw := inline
	if path != "" {
		blob, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read -slots-file: %w", err)
		}
		if raw != "" {
			raw += ","
		}
		raw += string(blob)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out, nil
}

func firstLine(value string) string {
	if idx := strings.IndexByte(value, '\n'); idx >= 0 {
		value = value[:idx]
	}
	if len(value) > 90 {
		value = value[:90] + "..."
	}
	return value
}
