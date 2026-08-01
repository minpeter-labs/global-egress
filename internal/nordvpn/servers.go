// Package nordvpn talks to NordVPN: it reads their server list and turns it into
// the handful of fields the pool needs.
//
// This is a sibling of internal/mullvad, and it exists for the same reason: the
// provider-specific parts of a bundle live in one package, and nothing outside it
// imports a provider type. Two things here are NordVPN's, not WireGuard's:
//
//   - the server list schema and endpoint, where a server's WireGuard public key
//     arrives as technology metadata rather than as a field
//   - the group taxonomy, which decides what an ordinary subscription may use
//
// NordVPN does run SOCKS5 proxies, but not the way relay-socks mode needs: they
// are a separate pool of a few dozen endpoints in three countries rather than one
// proxy per relay, they are publicly reachable, and they authenticate with RFC
// 1929 credentials, where Mullvad's resolve only inside a tunnel and take none. So
// this package feeds WireGuard mode: one exit address per server, keyed by the
// account's own NordLynx private key, which this package never sees.
package nordvpn

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultPort is the UDP port NordLynx peers listen on.
const DefaultPort = 51820

// wireGuardTechnology is the identifier NordVPN uses for NordLynx in the server
// list, and publicKeyMetadata is the metadata entry that carries the peer key.
const (
	wireGuardTechnology = "wireguard_udp"
	publicKeyMetadata   = "public_key"
)

// groupDedicatedIP marks servers reserved for the dedicated-IP add-on. An
// ordinary subscription is refused by them, so they are dropped rather than
// offered as slots that can never come up.
const groupDedicatedIP = "Dedicated IP"

// groupStandard marks the ordinary servers. Double VPN and Onion Over VPN also
// exist, and they work differently enough - two hops, or a Tor gateway - that a
// rotating egress pool should not silently mix them in.
const groupStandard = "Standard VPN servers"

// Server is one NordVPN server, reduced to what an egress slot needs.
type Server struct {
	// Hostname is the provider name, e.g. "kr100.nordvpn.com".
	Hostname string `json:"hostname"`
	// Station is the address a tunnel connects to.
	Station string `json:"station"`
	// Status reports whether the provider considers the server usable.
	Status string `json:"status"`
	// Load is the provider's own utilisation percentage, used to prefer quiet
	// servers when picking entries.
	Load int `json:"load"`
	// PublicKey is the peer's WireGuard key in base64 form, lifted out of the
	// technology metadata by UnmarshalJSON.
	PublicKey string `json:"-"`
	// Country is the ISO-3166-1 alpha-2 code, lowercased, e.g. "kr".
	Country string `json:"-"`
	// CityName is the provider's DNS-safe city label, e.g. "seoul".
	CityName string `json:"-"`

	groups []string
}

// serverJSON mirrors the provider's nesting. Keeping it separate from Server is
// what lets the exported type stay flat.
type serverJSON struct {
	Hostname     string                 `json:"hostname"`
	Station      string                 `json:"station"`
	Status       string                 `json:"status"`
	Load         int                    `json:"load"`
	Locations    []serverLocationJSON   `json:"locations"`
	Groups       []serverGroupJSON      `json:"groups"`
	Technologies []serverTechnologyJSON `json:"technologies"`
}

type serverLocationJSON struct {
	Country serverCountryJSON `json:"country"`
}

type serverCountryJSON struct {
	Code string         `json:"code"`
	City serverCityJSON `json:"city"`
}

type serverCityJSON struct {
	DNSName string `json:"dns_name"`
	Name    string `json:"name"`
}

type serverGroupJSON struct {
	Title string `json:"title"`
}

type serverTechnologyJSON struct {
	Identifier string               `json:"identifier"`
	Pivot      serverPivotJSON      `json:"pivot"`
	Metadata   []serverMetadataJSON `json:"metadata"`
}

type serverPivotJSON struct {
	Status string `json:"status"`
}

type serverMetadataJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// UnmarshalJSON flattens the provider's nested shape: the public key lives in
// technology metadata, and the geography two levels inside a locations array.
func (s *Server) UnmarshalJSON(blob []byte) error {
	var raw serverJSON
	if err := json.Unmarshal(blob, &raw); err != nil {
		return err
	}

	*s = Server{}
	s.Hostname = raw.Hostname
	s.Station = raw.Station
	s.Status = raw.Status
	s.Load = raw.Load

	for _, tech := range raw.Technologies {
		if tech.Identifier != wireGuardTechnology {
			continue
		}
		// A technology the provider marks offline is not usable even when the
		// server as a whole is up.
		if tech.Pivot.Status != "" && tech.Pivot.Status != "online" {
			continue
		}
		for _, entry := range tech.Metadata {
			if entry.Name == publicKeyMetadata {
				s.PublicKey = entry.Value
			}
		}
	}

	if len(raw.Locations) > 0 {
		country := raw.Locations[0].Country
		s.Country = strings.ToLower(country.Code)
		city := country.City.DNSName
		if city == "" {
			city = strings.ToLower(strings.ReplaceAll(country.City.Name, " ", "-"))
		}
		s.CityName = strings.ReplaceAll(city, "_", "-")
	}

	s.groups = make([]string, 0, len(raw.Groups))
	for _, group := range raw.Groups {
		s.groups = append(s.groups, group.Title)
	}
	return nil
}

// MarshalJSON writes the provider's shape back, so a cache file written by Save
// can be read by parse without a second schema.
func (s Server) MarshalJSON() ([]byte, error) {
	var raw serverJSON
	raw.Hostname = s.Hostname
	raw.Station = s.Station
	raw.Status = s.Status
	raw.Load = s.Load
	raw.Locations = make([]serverLocationJSON, 1)
	raw.Locations[0].Country.Code = s.Country
	raw.Locations[0].Country.City.DNSName = s.CityName
	for _, group := range s.groups {
		raw.Groups = append(raw.Groups, serverGroupJSON{Title: group})
	}
	if s.PublicKey != "" {
		tech := serverTechnologyJSON{Identifier: wireGuardTechnology}
		tech.Pivot.Status = "online"
		tech.Metadata = append(tech.Metadata, serverMetadataJSON{
			Name:  publicKeyMetadata,
			Value: s.PublicKey,
		})
		raw.Technologies = append(raw.Technologies, tech)
	}
	return json.Marshal(raw)
}

// hasGroup reports whether the server carries the given provider group.
func (s Server) hasGroup(title string) bool {
	for _, group := range s.groups {
		if group == title {
			return true
		}
	}
	return false
}

// Groups returns the provider group titles, for display.
func (s Server) Groups() []string {
	out := make([]string, len(s.groups))
	copy(out, s.groups)
	return out
}

// City returns the "<country>-<city>" label used throughout the project, e.g.
// "kr-seoul", matching the labels derived from WireGuard config file names.
func (s Server) City() string {
	if s.Country == "" || s.CityName == "" {
		return ""
	}
	return s.Country + "-" + s.CityName
}

// SlotID returns a stable identifier for the server, derived from the hostname so
// that it survives a change of address.
func (s Server) SlotID() string {
	host := s.Hostname
	if idx := strings.Index(host, "."); idx > 0 {
		host = host[:idx]
	}
	return host
}

// Endpoint returns the "host:port" a tunnel connects to.
func (s Server) Endpoint() string {
	return fmt.Sprintf("%s:%d", s.Station, DefaultPort)
}

// List is a set of servers.
type List struct {
	Servers   []Server
	FetchedAt time.Time
}

// Usable returns the servers an ordinary subscription can actually reach: online,
// carrying a WireGuard key and an address, and belonging to the standard group.
// The result is sorted by slot ID for stable output.
func (l *List) Usable() []Server {
	out := make([]Server, 0, len(l.Servers))
	for _, server := range l.Servers {
		if server.Status != "" && server.Status != "online" {
			continue
		}
		if server.PublicKey == "" || server.Station == "" {
			continue
		}
		if server.hasGroup(groupDedicatedIP) || !server.hasGroup(groupStandard) {
			continue
		}
		out = append(out, server)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SlotID() < out[j].SlotID() })
	return out
}

// Countries returns the sorted set of country codes among the usable servers.
func (l *List) Countries() []string {
	seen := map[string]struct{}{}
	for _, server := range l.Usable() {
		if server.Country != "" {
			seen[server.Country] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// Cities returns the sorted set of city labels among the usable servers.
func (l *List) Cities() []string {
	seen := map[string]struct{}{}
	for _, server := range l.Usable() {
		if city := server.City(); city != "" {
			seen[city] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
