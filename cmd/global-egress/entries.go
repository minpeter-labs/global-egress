package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/georoute"
)

// resolveEntries turns the configured entry names into catalog slots.
//
// Entries are the only tunnels relay-socks mode keeps open, so getting them right
// matters more than any other setting: every request pays the trip to its entry.
// Naming them explicitly is preferred, because the best entry depends on where
// this service runs, which the catalog cannot know.
func resolveEntries(bundle *catalog.Bundle, names []string, auto int) ([]catalog.Slot, error) {
	byID := make(map[string]catalog.Slot, len(bundle.Slots))
	for _, slot := range bundle.Slots {
		byID[slot.ID] = slot
	}

	if len(names) > 0 {
		out := make([]catalog.Slot, 0, len(names))
		seen := make(map[string]struct{}, len(names))
		for _, raw := range names {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			slot, ok := byID[name]
			if !ok {
				return nil, fmt.Errorf("entries.slots: %q is not in the catalog", name)
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, slot)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("entries.slots contained no usable names")
		}
		return out, nil
	}

	if auto <= 0 {
		return nil, fmt.Errorf("no entries configured")
	}
	return autoEntries(bundle, auto), nil
}

// autoEntries picks entries spread across regions, so a single regional outage
// cannot take every entry with it. Within a region the lowest slot ID wins, which
// keeps the choice stable across restarts.
func autoEntries(bundle *catalog.Bundle, count int) []catalog.Slot {
	byRegion := map[georoute.Region][]catalog.Slot{}
	for _, slot := range bundle.Slots {
		region := georoute.RegionOf(slot.Country)
		byRegion[region] = append(byRegion[region], slot)
	}

	regions := make([]georoute.Region, 0, len(byRegion))
	for region, slots := range byRegion {
		sort.Slice(slots, func(i, j int) bool { return slots[i].ID < slots[j].ID })
		byRegion[region] = slots
		regions = append(regions, region)
	}
	// Largest regions first: they are the best served and most likely to be
	// reliable, and ties break by name for determinism.
	sort.Slice(regions, func(i, j int) bool {
		if len(byRegion[regions[i]]) != len(byRegion[regions[j]]) {
			return len(byRegion[regions[i]]) > len(byRegion[regions[j]])
		}
		return regions[i] < regions[j]
	})

	var out []catalog.Slot
	for round := 0; len(out) < count; round++ {
		progressed := false
		for _, region := range regions {
			slots := byRegion[region]
			if round >= len(slots) {
				continue
			}
			out = append(out, slots[round])
			progressed = true
			if len(out) == count {
				return out
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
