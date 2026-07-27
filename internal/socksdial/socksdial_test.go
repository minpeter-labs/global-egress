package socksdial

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeProxy is a minimal SOCKS5 server that records what the dialer asked for.
type fakeProxy struct {
	listener net.Listener
	// method is the authentication method the proxy selects.
	method byte
	// reply is the CONNECT reply code.
	reply byte
	// requested receives the destination the client asked for.
	requested chan string
}

func startFakeProxy(t *testing.T, method, reply byte) *fakeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &fakeProxy{
		listener:  listener,
		method:    method,
		reply:     reply,
		requested: make(chan string, 4),
	}
	t.Cleanup(func() { _ = listener.Close() })
	go proxy.serve()
	return proxy
}

func (p *fakeProxy) addr() string { return p.listener.Addr().String() }

func (p *fakeProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *fakeProxy) handle(conn net.Conn) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{version, p.method}); err != nil {
		return
	}
	if p.method != methodNoAuth {
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	var destination string
	switch request[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		destination = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		_, _ = io.ReadFull(conn, buf)
		destination = net.IP(buf).String()
	case atypDomain:
		length := make([]byte, 1)
		_, _ = io.ReadFull(conn, length)
		buf := make([]byte, int(length[0]))
		_, _ = io.ReadFull(conn, buf)
		destination = string(buf)
	}
	port := make([]byte, 2)
	_, _ = io.ReadFull(conn, port)
	p.requested <- destination

	// Reply with a bound IPv4 address, then echo so the test can prove the
	// stream is positioned at the payload.
	_, _ = conn.Write([]byte{version, p.reply, 0x00, atypIPv4, 127, 0, 0, 1, 0x1f, 0x90})
	if p.reply != replySuccess {
		return
	}
	_, _ = io.Copy(conn, conn)
}

func TestDialDomainTarget(t *testing.T) {
	proxy := startFakeProxy(t, methodNoAuth, replySuccess)
	dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: proxy.addr(), Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-proxy.requested:
		// The name must reach the proxy unresolved: DNS belongs at the exit.
		if got != "example.com" {
			t.Errorf("proxy asked for %q, want example.com", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never received a request")
	}

	// The bound address must have been consumed, leaving the payload stream.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", buf)
	}
}

func TestDialIPTargets(t *testing.T) {
	for _, target := range []string{"203.0.113.9:80", "[2606:4700::1111]:443"} {
		proxy := startFakeProxy(t, methodNoAuth, replySuccess)
		dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: proxy.addr()}
		conn, err := dialer.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatalf("DialContext(%s): %v", target, err)
		}
		_ = conn.Close()
		select {
		case got := <-proxy.requested:
			if got == "" {
				t.Errorf("proxy received an empty destination for %s", target)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("proxy never received %s", target)
		}
	}
}

func TestDialRejectedByProxy(t *testing.T) {
	proxy := startFakeProxy(t, methodNoAuth, 0x05) // connection refused
	dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: proxy.addr()}

	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected an error when the proxy refuses")
	}
	if got := err.Error(); !contains(got, "connection refused") {
		t.Errorf("error = %q, want it to mention the refusal reason", got)
	}
}

func TestDialProxyDemandsAuth(t *testing.T) {
	proxy := startFakeProxy(t, 0x02, replySuccess) // username/password
	dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: proxy.addr()}

	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected an error when the proxy requires authentication")
	}
}

func TestDialValidation(t *testing.T) {
	dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: "127.0.0.1:1"}
	cases := []struct{ network, address string }{
		{"udp", "example.com:53"},
		{"tcp", "example.com"},
		{"tcp", "example.com:0"},
		{"tcp", "example.com:99999"},
	}
	for _, tc := range cases {
		if _, err := dialer.DialContext(context.Background(), tc.network, tc.address); err == nil {
			t.Errorf("DialContext(%q, %q) succeeded, want an error", tc.network, tc.address)
		}
	}

	noBase := &Dialer{ProxyAddr: "127.0.0.1:1"}
	if _, err := noBase.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Error("expected an error without a base dialer")
	}
}

func TestDialBaseFailurePropagates(t *testing.T) {
	sentinel := errors.New("tunnel down")
	dialer := &Dialer{Base: failingDialer{sentinel}, ProxyAddr: "10.124.0.1:1080"}
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap %v", err, sentinel)
	}
}

type failingDialer struct{ err error }

func (f failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, f.err
}

func TestLongHostNameRejected(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := buildConnect(string(long), 80); err == nil {
		t.Fatal("expected an error for a host name longer than 255 bytes")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
