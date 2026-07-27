// Package catalog turns a bundle of WireGuard configuration files into a list
// of egress slot specifications.
//
// The expected input is the archive a VPN provider hands out for "all servers",
// for example Mullvad's WireGuard zip. Such a bundle typically contains one
// .conf per server, all sharing a single [Interface] section (same private key,
// same tunnel address) and differing only in the [Peer] section.
//
// The parser does not assume that layout: every slot carries its own copy of
// the interface settings, so bundles that mix multiple devices/keys also work.
package catalog

import (
	"archive/zip"
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DefaultMTU is used when a configuration file does not specify one.
// 1420 is the value Mullvad and wg-quick use for IPv4+IPv6 WireGuard tunnels.
const DefaultMTU = 1420

// Slot is a single selectable egress: one WireGuard peer plus everything needed
// to bring up a userspace tunnel towards it.
type Slot struct {
	// ID is the bundle-unique slot name, derived from the file name,
	// e.g. "us-lax-wg-001".
	ID string
	// Country is the ISO-3166-1 alpha-2 code parsed from the file name, e.g. "us".
	// Empty when the file name does not follow the <country>-<city>-... convention.
	Country string
	// City is the "<country>-<city>" label parsed from the file name, e.g. "us-lax".
	// Empty when the file name does not follow the convention.
	City string
	// Device is the provider's device/profile label, taken from a
	// "# Device: <name>" comment when present.
	Device string

	// PrivateKey is the local key in base64 form.
	PrivateKey string
	// Addresses are the tunnel-side local addresses.
	Addresses []netip.Addr
	// DNS lists resolvers reachable inside the tunnel.
	DNS []netip.Addr
	// MTU is the tunnel MTU.
	MTU int

	// PeerPublicKey is the remote key in base64 form.
	PeerPublicKey string
	// PeerPresharedKey is optional; empty when unused.
	PeerPresharedKey string
	// Endpoint is the remote "host:port".
	Endpoint string
	// AllowedIPs are the prefixes routed into the tunnel.
	AllowedIPs []netip.Prefix

	// Source is the path (or archive member name) the slot was parsed from.
	Source string
}

// EndpointHost returns the host portion of the peer endpoint.
func (s Slot) EndpointHost() string {
	host, _, err := splitHostPort(s.Endpoint)
	if err != nil {
		return s.Endpoint
	}
	return host
}

// Bundle is a parsed collection of slots.
type Bundle struct {
	Slots []Slot
	// Devices lists the distinct device labels seen in the bundle.
	Devices []string
	// DistinctKeys is the number of distinct private keys in the bundle. More
	// than one means the bundle mixes several provider devices, which usually
	// has licensing/concurrency implications worth surfacing to the operator.
	DistinctKeys int
}

// Countries returns the sorted set of country codes present in the bundle.
func (b *Bundle) Countries() []string {
	return distinct(b.Slots, func(s Slot) string { return s.Country })
}

// Cities returns the sorted set of city labels present in the bundle.
func (b *Bundle) Cities() []string { return distinct(b.Slots, func(s Slot) string { return s.City }) }

func distinct(slots []Slot, key func(Slot) string) []string {
	seen := make(map[string]struct{}, len(slots))
	for _, s := range slots {
		if v := key(s); v != "" {
			seen[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Load reads a bundle from either a .zip archive or a directory of .conf files.
func Load(path string) (*Bundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return LoadDir(path)
	}
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return LoadZip(path)
	}
	return nil, fmt.Errorf("catalog: %s is neither a directory nor a .zip archive", path)
}

// LoadDir parses every *.conf file directly inside dir.
func LoadDir(dir string) (*Bundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("catalog: read dir %s: %w", dir, err)
	}
	var slots []Slot
	for _, entry := range entries {
		if entry.IsDir() || !isConfName(entry.Name()) {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("catalog: read %s: %w", full, err)
		}
		slot, err := ParseConf(entry.Name(), raw)
		if err != nil {
			return nil, fmt.Errorf("catalog: parse %s: %w", full, err)
		}
		slot.Source = full
		slots = append(slots, slot)
	}
	return newBundle(slots, dir)
}

// LoadZip parses every *.conf member of a zip archive, at any depth.
func LoadZip(path string) (*Bundle, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: open zip %s: %w", path, err)
	}
	defer archive.Close()

	var slots []Slot
	for _, member := range archive.File {
		if member.FileInfo().IsDir() || !isConfName(member.Name) {
			continue
		}
		raw, err := readZipMember(member)
		if err != nil {
			return nil, fmt.Errorf("catalog: read %s from %s: %w", member.Name, path, err)
		}
		slot, err := ParseConf(filepath.Base(member.Name), raw)
		if err != nil {
			return nil, fmt.Errorf("catalog: parse %s: %w", member.Name, err)
		}
		slot.Source = member.Name
		slots = append(slots, slot)
	}
	return newBundle(slots, path)
}

func readZipMember(member *zip.File) ([]byte, error) {
	rc, err := member.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Configuration files are a few hundred bytes; cap the read so a hostile
	// archive cannot exhaust memory.
	return io.ReadAll(io.LimitReader(rc, 1<<20))
}

// ExtractZip writes every *.conf member of a zip archive into dir with 0600
// permissions and returns the number of files written. Existing files are
// overwritten. The files contain private keys, so dir is created with 0700.
func ExtractZip(zipPath, dir string) (int, error) {
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, fmt.Errorf("catalog: open zip %s: %w", zipPath, err)
	}
	defer archive.Close()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("catalog: create %s: %w", dir, err)
	}

	written := 0
	for _, member := range archive.File {
		if member.FileInfo().IsDir() || !isConfName(member.Name) {
			continue
		}
		name := filepath.Base(member.Name)
		// Reject anything that would escape dir even after Base().
		if name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
			return written, fmt.Errorf("catalog: refusing suspicious member name %q", member.Name)
		}
		raw, err := readZipMember(member)
		if err != nil {
			return written, fmt.Errorf("catalog: read %s: %w", member.Name, err)
		}
		if _, err := ParseConf(name, raw); err != nil {
			return written, fmt.Errorf("catalog: parse %s: %w", member.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			return written, fmt.Errorf("catalog: write %s: %w", name, err)
		}
		written++
	}
	if written == 0 {
		return 0, fmt.Errorf("catalog: %s contains no .conf members", zipPath)
	}
	return written, nil
}

func newBundle(slots []Slot, source string) (*Bundle, error) {
	if len(slots) == 0 {
		return nil, fmt.Errorf("catalog: no .conf files found in %s", source)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].ID < slots[j].ID })

	seen := make(map[string]string, len(slots))
	keys := make(map[string]struct{})
	devices := make(map[string]struct{})
	for _, s := range slots {
		if prev, dup := seen[s.ID]; dup {
			return nil, fmt.Errorf("catalog: duplicate slot id %q (%s and %s)", s.ID, prev, s.Source)
		}
		seen[s.ID] = s.Source
		keys[s.PrivateKey] = struct{}{}
		if s.Device != "" {
			devices[s.Device] = struct{}{}
		}
	}

	deviceList := make([]string, 0, len(devices))
	for d := range devices {
		deviceList = append(deviceList, d)
	}
	sort.Strings(deviceList)

	return &Bundle{Slots: slots, Devices: deviceList, DistinctKeys: len(keys)}, nil
}

var (
	// e.g. "us-lax-wg-001" or "gb-lon-wg-305"
	slotNameRe = regexp.MustCompile(`^([a-z]{2})-([a-z0-9]+)-`)
	deviceRe   = regexp.MustCompile(`(?i)^#\s*device\s*:\s*(.+?)\s*$`)
)

func isConfName(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".conf")
}

// ParseConf parses a single wg-quick style configuration file. name is used to
// derive the slot ID and geography labels.
func ParseConf(name string, raw []byte) (Slot, error) {
	slot := Slot{
		ID:  strings.TrimSuffix(strings.TrimSuffix(name, ".conf"), ".CONF"),
		MTU: DefaultMTU,
	}
	if m := slotNameRe.FindStringSubmatch(slot.ID); m != nil {
		slot.Country = m[1]
		slot.City = m[1] + "-" + m[2]
	}

	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if m := deviceRe.FindStringSubmatch(line); m != nil && slot.Device == "" {
				slot.Device = m[1]
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Slot{}, fmt.Errorf("malformed line %q", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		// Strip trailing inline comments, which wg-quick tolerates.
		if idx := strings.IndexAny(value, "#;"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}

		var err error
		switch section {
		case "interface":
			err = slot.setInterfaceField(key, value)
		case "peer":
			err = slot.setPeerField(key, value)
		default:
			// Ignore keys outside a known section.
		}
		if err != nil {
			return Slot{}, fmt.Errorf("%s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Slot{}, err
	}
	if err := slot.validate(); err != nil {
		return Slot{}, err
	}
	if len(slot.AllowedIPs) == 0 {
		slot.AllowedIPs = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	return slot, nil
}

func (s *Slot) setInterfaceField(key, value string) error {
	switch key {
	case "privatekey":
		s.PrivateKey = value
	case "address":
		addrs, err := parseAddrList(value)
		if err != nil {
			return err
		}
		s.Addresses = append(s.Addresses, addrs...)
	case "dns":
		addrs, err := parseAddrList(value)
		if err != nil {
			return err
		}
		s.DNS = append(s.DNS, addrs...)
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid MTU %q", value)
		}
		if mtu < 576 || mtu > 65535 {
			return fmt.Errorf("MTU %d out of range", mtu)
		}
		s.MTU = mtu
	}
	return nil
}

func (s *Slot) setPeerField(key, value string) error {
	switch key {
	case "publickey":
		s.PeerPublicKey = value
	case "presharedkey":
		s.PeerPresharedKey = value
	case "endpoint":
		if _, _, err := splitHostPort(value); err != nil {
			return err
		}
		s.Endpoint = value
	case "allowedips":
		for _, field := range splitList(value) {
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				// Accept a bare address as a host route.
				addr, addrErr := netip.ParseAddr(field)
				if addrErr != nil {
					return fmt.Errorf("invalid AllowedIPs entry %q", field)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			s.AllowedIPs = append(s.AllowedIPs, prefix.Masked())
		}
	}
	return nil
}

func (s *Slot) validate() error {
	var problems []string
	if s.ID == "" {
		problems = append(problems, "empty slot id")
	}
	if s.PrivateKey == "" {
		problems = append(problems, "missing [Interface] PrivateKey")
	}
	if len(s.Addresses) == 0 {
		problems = append(problems, "missing [Interface] Address")
	}
	if s.PeerPublicKey == "" {
		problems = append(problems, "missing [Peer] PublicKey")
	}
	if s.Endpoint == "" {
		problems = append(problems, "missing [Peer] Endpoint")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// splitList splits a comma or space separated list, dropping empty fields.
func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parseAddrList(value string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, field := range splitList(value) {
		// Accept both "10.0.0.1/32" and "10.0.0.1".
		if prefix, err := netip.ParsePrefix(field); err == nil {
			out = append(out, prefix.Addr())
			continue
		}
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", field)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no addresses in %q", value)
	}
	return out, nil
}

// splitHostPort accepts "host:port" and "[v6]:port".
func splitHostPort(value string) (host, port string, err error) {
	idx := strings.LastIndex(value, ":")
	if idx <= 0 || idx == len(value)-1 {
		return "", "", fmt.Errorf("invalid endpoint %q", value)
	}
	host, port = value[:idx], value[idx+1:]
	host = strings.Trim(host, "[]")
	if _, convErr := strconv.Atoi(port); convErr != nil {
		return "", "", fmt.Errorf("invalid endpoint port in %q", value)
	}
	return host, port, nil
}
