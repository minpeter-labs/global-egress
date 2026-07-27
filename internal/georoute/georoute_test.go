package georoute

import "testing"

func TestRegionOf(t *testing.T) {
	t.Parallel()
	cases := map[string]Region{
		"jp": EastAsia, "JP": EastAsia, " jp ": EastAsia,
		"sg": SouthAsia, "au": Oceania, "de": Europe,
		"us": NorthAmerica, "br": SouthAmerica, "za": Africa,
		"il": MiddleEast, "zz": Unknown, "": Unknown,
	}
	for country, want := range cases {
		if got := RegionOf(country); got != want {
			t.Errorf("RegionOf(%q) = %q, want %q", country, got, want)
		}
	}
}

func TestCostPrefersNearbyEntries(t *testing.T) {
	t.Parallel()
	// Reaching a Japanese exit should look cheapest from an Asian entry.
	fromJP := Cost("jp", "jp")
	fromSG := Cost("sg", "jp")
	fromDE := Cost("de", "jp")
	if fromJP >= fromSG || fromSG >= fromDE {
		t.Errorf("expected jp < sg < de for a jp exit, got %d, %d, %d", fromJP, fromSG, fromDE)
	}

	// And a German exit should look cheapest from Europe.
	if Cost("de", "de") >= Cost("us", "de") {
		t.Errorf("a European entry should beat an American one for a German exit")
	}
}

func TestCostIsSymmetricEnough(t *testing.T) {
	t.Parallel()
	// The matrix is hand written, so guard against gross asymmetry which would
	// make routing decisions depend on which side we look from.
	for _, pair := range [][2]string{{"jp", "de"}, {"us", "au"}, {"br", "se"}} {
		a, b := Cost(pair[0], pair[1]), Cost(pair[1], pair[0])
		if diff := a - b; diff > 1 || diff < -1 {
			t.Errorf("Cost(%s,%s)=%d but Cost(%s,%s)=%d", pair[0], pair[1], a, pair[1], pair[0], b)
		}
	}
}

func TestUnknownCountriesGetMiddlingCost(t *testing.T) {
	t.Parallel()
	unknown := Cost("zz", "jp")
	if unknown != unknownCost {
		t.Errorf("Cost with an unknown country = %d, want %d", unknown, unknownCost)
	}
	// It must not be the cheapest option, or unknown entries would win by default.
	if unknown <= Cost("jp", "jp") {
		t.Error("an unknown pairing should not beat a same-region pairing")
	}
}
