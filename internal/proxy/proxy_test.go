package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/minpeter-labs/global-egress/internal/policy"
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

func TestRequirePolicyRejectsDirectivelessRequests(t *testing.T) {
	// The directives ride in the proxy username. Clients that drop the credentials
	// when the password is empty still get a working response from an arbitrary
	// exit, which is indistinguishable from success. RequirePolicy makes that loud.
	deps := &Deps{RequirePolicy: true}

	if _, err := deps.authorize("", "", false); !errors.Is(err, errPolicyRequired) {
		t.Errorf("no credentials: error = %v, want errPolicyRequired", err)
	}
	if _, err := deps.authorize("someaccount", "pw", true); !errors.Is(err, errPolicyRequired) {
		t.Errorf("credentials without directives: error = %v, want errPolicyRequired", err)
	}
	if _, err := deps.authorize("cc=jp", "x", true); err != nil {
		t.Errorf("a real policy was rejected: %v", err)
	}
}

func TestRequirePolicyOffKeepsTheDefaultBehaviour(t *testing.T) {
	deps := &Deps{}
	pol, err := deps.authorize("", "", false)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !pol.IsZero() {
		t.Error("expected an unconstrained policy")
	}
}

func TestEgressHeadersReportTheAppliedPolicy(t *testing.T) {
	// A client cannot otherwise tell that its directives were dropped in transit.
	lease := &pool.Lease{Slot: pool.Spec{ID: "jp-tyo-wg-socks5-001", Country: "jp", City: "jp-tyo"}}

	pol, err := policy.Parse("cc=jp;sess=job-1")
	if err != nil {
		t.Fatal(err)
	}
	headers := egressHeaders(lease, pol)
	if got := headers["X-Egress-Policy"]; got != "cc=jp;sess=job-1" {
		t.Errorf("X-Egress-Policy = %q", got)
	}

	// And the empty case has to be visible too, not absent.
	headers = egressHeaders(lease, policy.Policy{})
	if got := headers["X-Egress-Policy"]; got != "(any)" {
		t.Errorf("X-Egress-Policy for an empty policy = %q, want (any)", got)
	}
}

// TestSOCKS5RejectsWhenPolicyRequired covers the protocol that has no header to fall
// back on: for SOCKS5 the refusal is the only thing standing between a caller that
// dropped its credentials and a silently wrong exit.
func TestSOCKS5RejectsWhenPolicyRequired(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Pool is nil on purpose: the rejection must happen during negotiation, before
	// anything tries to select an exit.
	server := NewSOCKS5(Deps{
		RequirePolicy: true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()

	negotiate := func(username string) byte {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

		// Offer username/password, which is how a policy would be carried.
		if _, err := conn.Write([]byte{socksVersion, 1, methodUserPass}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read greeting reply: %v", err)
		}
		if reply[1] != methodUserPass {
			t.Fatalf("server chose method 0x%02x, want username/password", reply[1])
		}

		request := []byte{userPassVersion, byte(len(username))}
		request = append(request, username...)
		request = append(request, 1, 'x')
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("write credentials: %v", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			t.Fatalf("read auth reply: %v", err)
		}
		return authReply[1]
	}

	if status := negotiate(""); status == 0x00 {
		t.Error("a request with no directives was accepted")
	}
	if status := negotiate("cc=jp"); status != 0x00 {
		t.Errorf("a request carrying cc=jp was rejected with status 0x%02x", status)
	}
}
