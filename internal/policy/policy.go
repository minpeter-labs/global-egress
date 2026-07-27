// Package policy parses the egress selection policy that clients express
// through the proxy username.
//
// Encoding the policy in the username is the trick commercial proxy providers
// use, and it works with virtually every HTTP/SOCKS client without special
// support:
//
//	http://cc=jp;sess=job-1;ttl=600:<password>@egress.example:3128
//	socks5://uniq=batch-7:<password>@egress.example:1080
//
// Recognised directives:
//
//	cc=jp|us      restrict to these country codes
//	city=us-lax   restrict to these city labels
//	slot=id       pin one specific slot (mainly for debugging)
//	sess=name     sticky: reuse the same slot for this session
//	ttl=600       session lifetime in seconds (or Go duration, e.g. "10m")
//	uniq=batch    never reuse a public IP within this batch
//	not=1.2.3.4   exclude these public IPs
//
// Multiple values for cc, city and not are separated by "|". Directives are
// separated by ";" or ",". An empty username means "no constraints".
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Policy is a parsed client selection request.
type Policy struct {
	// Countries restricts selection to these ISO-3166-1 alpha-2 codes.
	Countries []string
	// Cities restricts selection to these "<country>-<city>" labels.
	Cities []string
	// Slot pins selection to one slot ID.
	Slot string
	// Session, when set, makes selection sticky under that name.
	Session string
	// TTL overrides the configured session lifetime. Zero means "use the default".
	TTL time.Duration
	// UniqueBatch, when set, forbids reusing a public IP already handed out
	// within that batch.
	UniqueBatch string
	// ExcludeIPs lists public IPs the client refuses.
	ExcludeIPs []netip.Addr
}

// IsZero reports whether the policy carries no constraints at all.
func (p Policy) IsZero() bool {
	return len(p.Countries) == 0 && len(p.Cities) == 0 && p.Slot == "" &&
		p.Session == "" && p.TTL == 0 && p.UniqueBatch == "" && len(p.ExcludeIPs) == 0
}

// String renders the policy in the same syntax it is parsed from, which makes
// it safe and useful for logging (it never contains the password).
func (p Policy) String() string {
	var parts []string
	if len(p.Countries) > 0 {
		parts = append(parts, "cc="+strings.Join(p.Countries, "|"))
	}
	if len(p.Cities) > 0 {
		parts = append(parts, "city="+strings.Join(p.Cities, "|"))
	}
	if p.Slot != "" {
		parts = append(parts, "slot="+p.Slot)
	}
	if p.Session != "" {
		parts = append(parts, "sess="+p.Session)
	}
	if p.TTL > 0 {
		parts = append(parts, "ttl="+p.TTL.String())
	}
	if p.UniqueBatch != "" {
		parts = append(parts, "uniq="+p.UniqueBatch)
	}
	for _, ip := range p.ExcludeIPs {
		parts = append(parts, "not="+ip.String())
	}
	if len(parts) == 0 {
		return "(any)"
	}
	return strings.Join(parts, ";")
}

// MaxUsernameLen bounds the username we are willing to parse.
const MaxUsernameLen = 512

// Parse converts a proxy username into a Policy. An empty username yields an
// unconstrained policy. Unknown directives are rejected so that typos surface
// immediately instead of silently widening the selection.
func Parse(username string) (Policy, error) {
	var p Policy
	username = strings.TrimSpace(username)
	if username == "" {
		return p, nil
	}
	if len(username) > MaxUsernameLen {
		return p, fmt.Errorf("policy: username too long (%d > %d)", len(username), MaxUsernameLen)
	}

	// A username with no "=" is treated as an opaque account name rather than a
	// policy, so plain "user:pass" credentials keep working.
	if !strings.Contains(username, "=") {
		return p, nil
	}

	fields := strings.FieldsFunc(username, func(r rune) bool { return r == ';' || r == ',' })
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return Policy{}, fmt.Errorf("policy: directive %q is not key=value", field)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return Policy{}, fmt.Errorf("policy: directive %q has an empty value", key)
		}

		switch key {
		case "cc", "country":
			p.Countries = appendLower(p.Countries, value)
		case "city":
			p.Cities = appendLower(p.Cities, value)
		case "slot":
			p.Slot = value
		case "sess", "session":
			p.Session = value
		case "ttl":
			ttl, err := parseTTL(value)
			if err != nil {
				return Policy{}, err
			}
			p.TTL = ttl
		case "uniq", "unique":
			p.UniqueBatch = value
		case "not", "exclude":
			for _, item := range strings.Split(value, "|") {
				addr, err := netip.ParseAddr(strings.TrimSpace(item))
				if err != nil {
					return Policy{}, fmt.Errorf("policy: not=%q is not an IP address", item)
				}
				p.ExcludeIPs = append(p.ExcludeIPs, addr)
			}
		default:
			return Policy{}, fmt.Errorf("policy: unknown directive %q", key)
		}
	}

	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p *Policy) validate() error {
	for _, cc := range p.Countries {
		if len(cc) != 2 {
			return fmt.Errorf("policy: cc=%q is not a 2-letter country code", cc)
		}
	}
	for _, city := range p.Cities {
		if !strings.Contains(city, "-") {
			return fmt.Errorf("policy: city=%q should look like \"us-lax\"", city)
		}
	}
	if p.TTL < 0 {
		return fmt.Errorf("policy: ttl must not be negative")
	}
	sort.Strings(p.Countries)
	sort.Strings(p.Cities)
	return nil
}

func appendLower(dst []string, value string) []string {
	for _, item := range strings.Split(value, "|") {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			dst = append(dst, item)
		}
	}
	return dst
}

// parseTTL accepts bare seconds ("600") and Go durations ("10m").
func parseTTL(value string) (time.Duration, error) {
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("policy: ttl=%q must not be negative", value)
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("policy: ttl=%q is neither seconds nor a duration", value)
	}
	if d < 0 {
		return 0, fmt.Errorf("policy: ttl=%q must not be negative", value)
	}
	return d, nil
}
