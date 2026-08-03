package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestWriteCatalog_invalid_slot_fails_before_touching_the_live_snapshot(t *testing.T) {
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

func TestReplaceCatalogSnapshot_rolls_the_previous_snapshot_back_when_the_swap_fails(t *testing.T) {
	// Given
	dir := filepath.Join(t.TempDir(), "nordvpn-wireguard")
	if _, err := writeCatalog(dir, []catalog.Slot{newTestSlot("kr101", "kr", "kr-seoul")}); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	path := filepath.Join(dir, "kr-seoul-kr101.conf")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	missingStage := filepath.Join(filepath.Dir(dir), ".nordvpn-stage-never-rendered")

	// When
	err = replaceCatalogSnapshot(dir, missingStage)

	// Then
	if err == nil {
		t.Fatal("replaceCatalogSnapshot reported success without a staged snapshot")
	}
	if strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback did not restore the previous snapshot: %v", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("previous snapshot was not rolled back: %v", readErr)
	}
	if string(after) != string(before) {
		t.Fatalf("rolled back snapshot changed to %q", after)
	}
	if _, statErr := os.Stat(missingStage + ".previous"); !os.IsNotExist(statErr) {
		t.Fatalf("backup directory survived the rollback: %v", statErr)
	}
}
