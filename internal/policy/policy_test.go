package policy

import (
	"testing"
	"time"
)

func TestParseEmptyAndPlainUsername(t *testing.T) {
	t.Parallel()
	for _, username := range []string{"", "   ", "someaccount"} {
		pol, err := Parse(username)
		if err != nil {
			t.Fatalf("Parse(%q): %v", username, err)
		}
		if !pol.IsZero() {
			t.Errorf("Parse(%q) = %v, want an unconstrained policy", username, pol)
		}
	}
}

func TestParseDirectives(t *testing.T) {
	t.Parallel()
	pol, err := Parse("cc=JP|us;city=us-lax;sess=job-1;ttl=600;uniq=batch-7;not=1.2.3.4|5.6.7.8")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(pol.Countries), 2; got != want {
		t.Fatalf("len(Countries) = %d, want %d", got, want)
	}
	// Values are lower-cased and sorted so that logging and comparison are stable.
	if pol.Countries[0] != "jp" || pol.Countries[1] != "us" {
		t.Errorf("Countries = %v, want [jp us]", pol.Countries)
	}
	if len(pol.Cities) != 1 || pol.Cities[0] != "us-lax" {
		t.Errorf("Cities = %v", pol.Cities)
	}
	if pol.Session != "job-1" {
		t.Errorf("Session = %q", pol.Session)
	}
	if pol.TTL != 10*time.Minute {
		t.Errorf("TTL = %s, want 10m", pol.TTL)
	}
	if pol.UniqueBatch != "batch-7" {
		t.Errorf("UniqueBatch = %q", pol.UniqueBatch)
	}
	if len(pol.ExcludeIPs) != 2 {
		t.Errorf("ExcludeIPs = %v, want 2 entries", pol.ExcludeIPs)
	}
	if pol.IsZero() {
		t.Error("IsZero() = true for a populated policy")
	}
}

func TestParseTTLAcceptsDuration(t *testing.T) {
	t.Parallel()
	pol, err := Parse("ttl=90s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.TTL != 90*time.Second {
		t.Errorf("TTL = %s, want 90s", pol.TTL)
	}
}

func TestParseCommaSeparator(t *testing.T) {
	t.Parallel()
	pol, err := Parse("cc=de,sess=x")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pol.Countries) != 1 || pol.Session != "x" {
		t.Errorf("unexpected policy %v", pol)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown directive":    "contry=jp",
		"empty value":          "cc=",
		"bad country":          "cc=japan",
		"bad city":             "city=lax",
		"not an ip":            "not=example.com",
		"negative ttl":         "ttl=-5",
		"unparsable ttl":       "ttl=soon",
		"missing key or value": "cc=jp;=x",
	}
	for name, username := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(username); err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", username)
			}
		})
	}
}

func TestParseRejectsOverlongUsername(t *testing.T) {
	t.Parallel()
	long := make([]byte, MaxUsernameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	// Include "=" so it is treated as a policy rather than an account name.
	if _, err := Parse("cc=" + string(long)); err == nil {
		t.Fatal("expected an error for an overlong username")
	}
}

func TestStringRoundTrips(t *testing.T) {
	t.Parallel()
	const input = "cc=jp;sess=job-1;ttl=10m;uniq=b1;not=1.2.3.4"
	pol, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reparsed, err := Parse(pol.String())
	if err != nil {
		t.Fatalf("Parse(String()): %v", err)
	}
	if reparsed.String() != pol.String() {
		t.Errorf("round trip changed the policy: %q -> %q", pol.String(), reparsed.String())
	}
}

func TestStringForEmptyPolicy(t *testing.T) {
	t.Parallel()
	var pol Policy
	if got := pol.String(); got != "(any)" {
		t.Errorf("String() = %q, want (any)", got)
	}
}
