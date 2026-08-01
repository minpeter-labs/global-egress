package nordvpn

import (
	"strings"
	"testing"

	"github.com/minpeter/global-egress/internal/catalog"
)

func TestSlotsCarryAccountKeyAndPeerSettings(t *testing.T) {
	t.Parallel()
	testPrivateKey := testKey(0x11)
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	slots, err := list.Slots(testPrivateKey)
	if err != nil {
		t.Fatalf("Slots: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("Slots() = %d, want 2 (only usable servers)", len(slots))
	}

	for _, slot := range slots {
		if slot.PrivateKey != testPrivateKey {
			t.Errorf("%s: PrivateKey not carried through", slot.ID)
		}
		if slot.MTU != catalog.DefaultMTU {
			t.Errorf("%s: MTU = %d, want %d", slot.ID, slot.MTU, catalog.DefaultMTU)
		}
		if len(slot.Addresses) != 1 || slot.Addresses[0].String() != tunnelAddress {
			t.Errorf("%s: Addresses = %v, want [%s]", slot.ID, slot.Addresses, tunnelAddress)
		}
		if len(slot.DNS) != 2 {
			t.Errorf("%s: DNS = %v, want the two NordVPN resolvers", slot.ID, slot.DNS)
		}
		if len(slot.AllowedIPs) != 2 {
			t.Errorf("%s: AllowedIPs = %v, want a default route pair", slot.ID, slot.AllowedIPs)
		}
		if slot.PeerPublicKey == "" {
			t.Errorf("%s: PeerPublicKey is empty", slot.ID)
		}
		if !strings.HasSuffix(slot.Endpoint, ":51820") {
			t.Errorf("%s: Endpoint = %q, want the NordLynx port", slot.ID, slot.Endpoint)
		}
	}
}

func TestSlotsRejectAnEmptyPrivateKey(t *testing.T) {
	t.Parallel()
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := list.Slots(""); err == nil {
		t.Fatal("Slots(\"\") returned no error, want one")
	}
}

// The private key is the account's whole VPN identity. It must not reach an
// error message, however malformed the input is.
func TestSlotErrorsNeverCarryThePrivateKey(t *testing.T) {
	t.Parallel()
	testPrivateKey := testKey(0x11)

	empty := &List{}
	_, err := empty.Slots(testPrivateKey)
	if err == nil {
		t.Fatal("Slots on an empty list returned no error")
	}
	if strings.Contains(err.Error(), testPrivateKey) {
		t.Errorf("error leaked the private key: %q", err)
	}

	broken := &List{Servers: []Server{{
		Hostname:  "kr100.nordvpn.com",
		Station:   "not an address",
		Status:    "online",
		PublicKey: "AAAA",
		Country:   "kr",
		CityName:  "seoul",
		groups:    []string{groupStandard},
	}}}
	if _, err := broken.Slots(testPrivateKey); err != nil && strings.Contains(err.Error(), testPrivateKey) {
		t.Errorf("error leaked the private key: %q", err)
	}
}

func TestSlotsProduceCatalogCompatibleGeography(t *testing.T) {
	t.Parallel()
	testPrivateKey := testKey(0x11)
	list, err := parse(fixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	slots, err := list.Slots(testPrivateKey)
	if err != nil {
		t.Fatalf("Slots: %v", err)
	}
	byID := map[string]catalog.Slot{}
	for _, slot := range slots {
		byID[slot.ID] = slot
	}
	slot, ok := byID["kr100"]
	if !ok {
		t.Fatalf("kr100 missing; got %v", byID)
	}
	if slot.Country != "kr" || slot.City != "kr-seoul" {
		t.Errorf("geography = %q/%q, want kr/kr-seoul", slot.Country, slot.City)
	}
}
