package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/minpeter/global-egress/internal/catalog"
)

const (
	nordVPNManifestName   = ".global-egress-nordvpn"
	nordVPNManifestHeader = "global-egress-provider=nordvpn"
)

// writeCatalog renders a complete private snapshot beside the live catalog,
// then replaces the owned directory with rollback on commit failure.
func writeCatalog(dir string, slots []catalog.Slot) (int, error) {
	names := make([]string, 0, len(slots))
	for _, slot := range slots {
		name, err := catalogFileName(slot)
		if err != nil {
			return 0, err
		}
		names = append(names, name)
	}
	if err := validateCatalogOwnership(dir); err != nil {
		return 0, err
	}

	parent := filepath.Dir(filepath.Clean(dir))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return 0, fmt.Errorf("nordvpn: create catalog parent: %w", err)
	}
	stage, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".nordvpn-stage-*")
	if err != nil {
		return 0, fmt.Errorf("nordvpn: create catalog staging dir failed (%T)", err)
	}
	defer func() {
		_ = os.RemoveAll(stage)
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return 0, fmt.Errorf("nordvpn: secure catalog staging dir failed (%T)", err)
	}

	for index, slot := range slots {
		if err := writePrivateFile(filepath.Join(stage, names[index]), renderConf(slot)); err != nil {
			return 0, err
		}
	}
	sort.Strings(names)
	manifest := nordVPNManifestHeader + "\n" + strings.Join(names, "\n") + "\n"
	if err := writePrivateFile(filepath.Join(stage, nordVPNManifestName), manifest); err != nil {
		return 0, err
	}
	if err := replaceCatalogSnapshot(dir, stage); err != nil {
		return 0, err
	}
	return len(slots), nil
}

func validateCatalogOwnership(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nordvpn: read catalog dir failed (%T)", err)
	}
	if len(entries) == 0 {
		return nil
	}

	manifest, err := os.ReadFile(filepath.Join(dir, nordVPNManifestName))
	if err != nil {
		return fmt.Errorf("nordvpn: refusing non-empty catalog directory without NordVPN ownership")
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) == 0 || lines[0] != nordVPNManifestHeader {
		return fmt.Errorf("nordvpn: refusing catalog directory with an invalid ownership manifest")
	}
	owned := make(map[string]struct{}, len(lines)-1)
	for _, name := range lines[1:] {
		owned[name] = struct{}{}
	}
	for _, entry := range entries {
		if entry.Name() == nordVPNManifestName {
			continue
		}
		if entry.IsDir() {
			return fmt.Errorf("nordvpn: refusing catalog directory containing unowned entries")
		}
		if _, ok := owned[entry.Name()]; !ok {
			return fmt.Errorf("nordvpn: refusing catalog directory containing unowned entries")
		}
	}
	return nil
}

func replaceCatalogSnapshot(dir, stage string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Rename(stage, dir); err != nil {
			return fmt.Errorf("nordvpn: install catalog snapshot failed (%T)", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("nordvpn: stat catalog dir failed (%T)", err)
	}

	backup := stage + ".previous"
	if err := os.Rename(dir, backup); err != nil {
		return fmt.Errorf("nordvpn: preserve previous catalog failed (%T)", err)
	}
	if err := os.Rename(stage, dir); err != nil {
		if rollbackErr := os.Rename(backup, dir); rollbackErr != nil {
			return fmt.Errorf(
				"nordvpn: install catalog snapshot failed (%T); rollback failed (%T)",
				err,
				rollbackErr,
			)
		}
		return fmt.Errorf("nordvpn: install catalog snapshot failed (%T)", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("nordvpn: previous catalog cleanup failed (%T)", err)
	}
	return nil
}

// writePrivateFile writes through a 0600 temporary file and renames, so readers
// never see a half-written config.
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

// catalogFileName uses underscores for inner city hyphens so the loader can
// recover a multi-word city from its filename.
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

	var builder strings.Builder
	fmt.Fprintf(&builder, "# Server: %s\n", slot.Source)
	builder.WriteString("[Interface]\n")
	fmt.Fprintf(&builder, "PrivateKey = %s\n", slot.PrivateKey)
	fmt.Fprintf(&builder, "Address = %s\n", strings.Join(addresses, ", "))
	fmt.Fprintf(&builder, "DNS = %s\n", strings.Join(resolvers, ", "))
	fmt.Fprintf(&builder, "MTU = %d\n\n", slot.MTU)
	builder.WriteString("[Peer]\n")
	fmt.Fprintf(&builder, "PublicKey = %s\n", slot.PeerPublicKey)
	fmt.Fprintf(&builder, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&builder, "Endpoint = %s\n", slot.Endpoint)
	return builder.String()
}
