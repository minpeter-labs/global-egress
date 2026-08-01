package nordvpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultURL lists every server that offers WireGuard.
const DefaultURL = "https://api.nordvpn.com/v1/servers" +
	"?limit=9000&filters[servers_technologies][identifier]=wireguard_udp"

var (
	errCrossHostRedirect = errors.New("nordvpn: cross-host redirect refused")
	errTooManyRedirects  = errors.New("nordvpn: too many redirects")
)

// LoadOptions controls cache freshness and whether a network failure may return
// an older cache.
type LoadOptions struct {
	URL        string
	CachePath  string
	MaxAge     time.Duration
	AllowStale bool
}

// Fetch downloads the server list. Errors name neither the URL nor the body.
func Fetch(ctx context.Context, url string) (*List, error) {
	if url == "" {
		url = DefaultURL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("nordvpn: create server request failed (%T)", err)
	}
	request.Header.Set("User-Agent", "global-egress/serverlist")

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errTooManyRedirects
			}
			source := via[0].URL
			if next.URL.Scheme != source.Scheme || next.URL.Host != source.Host {
				return errCrossHostRedirect
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("nordvpn: server fetch failed (%T)", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nordvpn: server fetch returned status %d", response.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("nordvpn: server response read failed (%T)", err)
	}
	return parse(blob)
}

func parse(blob []byte) (*List, error) {
	var servers []Server
	if err := json.Unmarshal(blob, &servers); err != nil {
		return nil, fmt.Errorf("nordvpn: parse server list failed (%T)", err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("nordvpn: server list is empty")
	}
	return &List{Servers: servers, FetchedAt: time.Now()}, nil
}

// Save writes the list to a private cache file.
func (l *List) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("nordvpn: create cache dir: %w", err)
	}
	blob, err := json.MarshalIndent(l.Servers, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("nordvpn: write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("nordvpn: replace cache: %w", err)
	}
	return nil
}

// LoadFile reads a previously saved list.
func LoadFile(path string) (*List, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nordvpn: read cache failed (%T)", err)
	}
	list, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(path); statErr == nil {
		list.FetchedAt = info.ModTime()
	}
	return list, nil
}

// LoadOrFetch prefers a fresh cache, then the network, and only returns stale
// data when AllowStale explicitly permits it.
func LoadOrFetch(ctx context.Context, options LoadOptions) (*List, bool, error) {
	if options.CachePath != "" && options.MaxAge > 0 {
		if list, err := LoadFile(options.CachePath); err == nil {
			if time.Since(list.FetchedAt) < options.MaxAge {
				return list, false, nil
			}
		}
	}

	list, fetchErr := Fetch(ctx, options.URL)
	if fetchErr == nil {
		if options.CachePath != "" {
			if err := list.Save(options.CachePath); err != nil {
				return nil, false, fmt.Errorf("nordvpn: save fetched cache: %w", err)
			}
		}
		return list, true, nil
	}

	if options.AllowStale && options.CachePath != "" {
		if list, err := LoadFile(options.CachePath); err == nil {
			return list, false, nil
		}
	}
	return nil, false, fetchErr
}
