package nordvpn

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A 44-character base64 literal is the exact shape of a WireGuard key. Secret
// scanners flag them on sight, and a contributor copying a test fixture into a
// real config would not notice the difference, so the tests build their key
// material at run time instead of hardcoding it.
func TestNoKeyShapedLiteralsInSource(t *testing.T) {
	t.Parallel()
	keyShaped := regexp.MustCompile(`"[A-Za-z0-9+/]{43}="`)

	roots := []string{".", filepath.Join("..", "..", "cmd", "global-egress")}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				return nil
			}
			blob, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if match := keyShaped.Find(blob); match != nil {
				t.Errorf("%s carries a key-shaped literal %s; build it at run time instead", path, match)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// The fixture cannot derive its values at run time, so its keys spell out
	// what they are: decoding them yields readable text, not random bytes.
	blob, err := os.ReadFile(filepath.Join("testdata", "servers.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var servers []Server
	if err := json.Unmarshal(blob, &servers); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for _, server := range servers {
		raw, err := base64.StdEncoding.DecodeString(server.PublicKey)
		if err != nil {
			t.Errorf("%s: fixture key is not base64", server.Hostname)
			continue
		}
		if !strings.Contains(string(raw), "NOT-REAL") {
			t.Errorf("%s: fixture key does not announce itself as fake", server.Hostname)
		}
	}
}
