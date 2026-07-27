package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/minpeter-labs/global-egress/internal/pool"
)

func TestCheckClient(t *testing.T) {
	deps := &Deps{AllowedClients: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("::1/128"),
	}}

	allowed := []string{"10.0.0.7:5000", "[::1]:5000"}
	for _, addr := range allowed {
		if err := deps.checkClient(mustAddr(t, addr)); err != nil {
			t.Errorf("checkClient(%s) = %v, want allowed", addr, err)
		}
	}
	denied := []string{"192.168.0.5:5000", "127.0.0.1:5000"}
	for _, addr := range denied {
		if err := deps.checkClient(mustAddr(t, addr)); err == nil {
			t.Errorf("checkClient(%s) allowed a client outside the ACL", addr)
		}
	}

	// An empty ACL allows everyone, which is why serve warns about it.
	open := &Deps{}
	if err := open.checkClient(mustAddr(t, "203.0.113.9:1")); err != nil {
		t.Errorf("empty ACL should allow all, got %v", err)
	}
}

func mustAddr(t *testing.T, value string) net.Addr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestAuthorize(t *testing.T) {
	t.Run("no password configured", func(t *testing.T) {
		deps := &Deps{}
		pol, err := deps.authorize("cc=jp", "", false)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if len(pol.Countries) != 1 || pol.Countries[0] != "jp" {
			t.Errorf("policy not parsed from username: %v", pol)
		}
	})

	t.Run("password required", func(t *testing.T) {
		deps := &Deps{Password: "hunter2"}
		if _, err := deps.authorize("cc=jp", "wrong", true); !errors.Is(err, errUnauthorized) {
			t.Errorf("wrong password error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=jp", "", false); !errors.Is(err, errUnauthorized) {
			t.Errorf("missing credentials error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=jp", "hunter2", true); err != nil {
			t.Errorf("correct password rejected: %v", err)
		}
	})

	t.Run("require auth without password", func(t *testing.T) {
		deps := &Deps{RequireAuth: true}
		if _, err := deps.authorize("", "", false); !errors.Is(err, errUnauthorized) {
			t.Errorf("error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=us", "anything", true); err != nil {
			t.Errorf("credentials present should pass: %v", err)
		}
	})

	t.Run("malformed policy", func(t *testing.T) {
		deps := &Deps{}
		if _, err := deps.authorize("contry=jp", "", false); err == nil {
			t.Error("expected a policy parse error")
		}
	})
}

func TestProxyCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("cc=jp;sess=a:pw"))
	req.Header.Set("Proxy-Authorization", "Basic "+encoded)

	user, pass, ok := proxyCredentials(req)
	if !ok || user != "cc=jp;sess=a" || pass != "pw" {
		t.Fatalf("got (%q, %q, %v)", user, pass, ok)
	}

	// Clients that send Authorization instead are tolerated.
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.Header.Set("Authorization", "Basic "+encoded)
	if _, _, ok := proxyCredentials(req2); !ok {
		t.Error("Authorization header was ignored")
	}

	req3 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, _, ok := proxyCredentials(req3); ok {
		t.Error("credentials reported for a request without any")
	}

	req4 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req4.Header.Set("Proxy-Authorization", "Bearer xyz")
	if _, _, ok := proxyCredentials(req4); ok {
		t.Error("non-Basic scheme accepted")
	}
}

func TestSplitTargetHostPort(t *testing.T) {
	cases := []struct {
		in       string
		defPort  int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com:443", 80, "example.com", 443, false},
		{"example.com", 80, "example.com", 80, false},
		{"[2606:4700::1111]:8443", 80, "2606:4700::1111", 8443, false},
		{"example.com:0", 80, "", 0, true},
		{"example.com:99999", 80, "", 0, true},
		{"", 80, "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitTargetHostPort(tc.in, tc.defPort)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitTargetHostPort(%q) succeeded, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitTargetHostPort(%q) = %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitTargetHostPort(%q) = (%q, %d), want (%q, %d)",
				tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestStatusCodeFor(t *testing.T) {
	cases := map[error]int{
		pool.ErrNoCandidate: http.StatusConflict,
		pool.ErrCapacity:    http.StatusServiceUnavailable,
		pool.ErrExhausted:   http.StatusBadGateway,
		errors.New("other"): http.StatusBadGateway,
	}
	for err, want := range cases {
		if got := statusCodeFor(err); got != want {
			t.Errorf("statusCodeFor(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestReplyCodeFor(t *testing.T) {
	cases := map[error]byte{
		nil:                                      repSuccess,
		pool.ErrNoCandidate:                      repNotAllowed,
		pool.ErrCapacity:                         repNotAllowed,
		pool.ErrExhausted:                        repHostUnreachable,
		context.DeadlineExceeded:                 repHostUnreachable,
		errors.New("connection refused by peer"): repConnectionRefused,
		errors.New("something else"):             repGeneralFailure,
	}
	for err, want := range cases {
		if got := replyCodeFor(err); got != want {
			t.Errorf("replyCodeFor(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestIPString(t *testing.T) {
	if got := ipString(nil); got != "unknown" {
		t.Errorf("ipString(nil) = %q", got)
	}
	lease := &pool.Lease{}
	if got := ipString(lease); got != "unknown" {
		t.Errorf("ipString(unmeasured) = %q, want unknown", got)
	}
	lease.PublicIP = netip.MustParseAddr("203.0.113.4")
	if got := ipString(lease); got != "203.0.113.4" {
		t.Errorf("ipString = %q", got)
	}
}
