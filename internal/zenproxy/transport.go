package zenproxy

import (
	"net"
	"net/http"
	"net/url"
	"time"
)

type transportFactory func(policy string) http.RoundTripper

func proxyTransportFactory(forwardProxy *url.URL, password string) transportFactory {
	return func(policy string) http.RoundTripper {
		proxyURL := *forwardProxy
		proxyURL.User = url.UserPassword(policy, password)
		return &http.Transport{
			Proxy:                 http.ProxyURL(&proxyURL),
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
			ExpectContinueTimeout: time.Second,
		}
	}
}

func closeIdleConnections(transport http.RoundTripper) {
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
