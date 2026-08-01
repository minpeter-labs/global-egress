package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/minpeter/global-egress/internal/catalog"
)

func TestWriteCatalog_refuses_unowned_directory(t *testing.T) {
	// Given
	dir := t.TempDir()
	foreignPath := filepath.Join(dir, "se-sto-wg-001.conf")
	const foreignContent = "foreign-provider-catalog"
	if err := os.WriteFile(foreignPath, []byte(foreignContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// When
	_, err := writeCatalog(dir, []catalog.Slot{newTestSlot("kr101", "kr", "kr-seoul")})

	// Then
	if err == nil {
		t.Fatal("writeCatalog accepted an unowned non-empty directory")
	}
	content, readErr := os.ReadFile(foreignPath)
	if readErr != nil {
		t.Fatalf("foreign catalog file was removed: %v", readErr)
	}
	if string(content) != foreignContent {
		t.Fatalf("foreign catalog file changed to %q", content)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "kr-seoul-kr101.conf")); !os.IsNotExist(statErr) {
		t.Fatalf("NordVPN file appeared after refusal: %v", statErr)
	}
}

func TestWriteCatalog_failure_leaves_previous_snapshot_intact(t *testing.T) {
	// Given
	dir := t.TempDir()
	original := newTestSlot("kr101", "kr", "kr-seoul")
	if _, err := writeCatalog(dir, []catalog.Slot{original}); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	path := filepath.Join(dir, "kr-seoul-kr101.conf")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := original
	updated.Endpoint = "198.51.100.7:51820"
	invalid := newTestSlot("../../etc/evil", "kr", "kr-seoul")

	// When
	_, err = writeCatalog(dir, []catalog.Slot{updated, invalid})

	// Then
	if err == nil {
		t.Fatal("writeCatalog accepted an invalid later slot")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("previous snapshot disappeared: %v", readErr)
	}
	if string(after) != string(before) {
		t.Fatal("previous snapshot changed before the batch failed")
	}
}
