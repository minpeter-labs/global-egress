package nordvpn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrFetch_keeps_fetched_list_when_the_cache_is_unwritable(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(fixture(t))
	}))
	defer server.Close()
	regularFileWhereCacheDirShouldBe := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(regularFileWhereCacheDirShouldBe, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}

	// When
	list, fresh, err := LoadOrFetch(context.Background(), LoadOptions{
		URL:       server.URL,
		CachePath: filepath.Join(regularFileWhereCacheDirShouldBe, "servers.json"),
	})
	// Then
	if err != nil {
		t.Fatalf("unwritable cache discarded a successful fetch: %v", err)
	}
	if !fresh {
		t.Fatal("fetched list was not reported as fresh")
	}
	if list == nil || len(list.Servers) == 0 {
		t.Fatal("fetched list is empty")
	}
}
